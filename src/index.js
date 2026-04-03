import { EventEmitter } from 'node:events';
import { ShieldLogger, createNullLogger } from './utils/logger.js';
import { PersistenceStore } from './persistence/store.js';
import { AbuseIPDBProvider } from './core/reputationProviders.js';

// Core
import { PortScanDetector } from './core/portScanner.js';
import { ConnectionTable } from './core/connectionTable.js';
import { BehavioralRateLimiter } from './core/rateLimiter.js';
import { ThreatIntel } from './core/threatIntel.js';
import { AlertPipeline } from './core/alertPipeline.js';

// Honeypot
import { HoneypotMesh } from './honeypot/mesh.js';

// Sentinel
import { ExfilDetector } from './sentinel/exfilDetector.js';
import { DNSMonitor } from './sentinel/dnsMonitor.js';

// Kill chain
import { KillChainTracker } from './core/killChain.js';

// Mesh
import { ThreatMesh } from './mesh/threatMesh.js';

// Integrations
import { PulseShield } from './integrations/pulseShield.js';

export class Shield extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._opts = opts;

    // core subsystems
    this.scanner     = new PortScanDetector(opts.scanner);
    this.connections = new ConnectionTable(opts.connections);
    this.rateLimiter = new BehavioralRateLimiter(opts.rateLimit);
    this.threatIntel = new ThreatIntel(opts.threatIntel);
    this.alerts      = new AlertPipeline(opts.alerts);

    // honeypot mesh
    this.honeypot = new HoneypotMesh(opts.honeypot);

    // outbound sentinel
    this.exfil = new ExfilDetector(opts.exfil);
    this.dns   = new DNSMonitor(opts.dns);

    // kill chain tracker (always on)
    this.killChain = new KillChainTracker(opts.killChain);

    // p2p threat mesh (optional — pass opts.mesh to enable)
    this.mesh = opts.mesh ? new ThreatMesh(opts.mesh) : null;

    // pulse integration (optional — pass opts.pulse to enable)
    this.pulse = opts.pulse ? new PulseShield({ shield: this, ...opts.pulse }) : null;

    // audit logger
    this.logger = opts.logging !== false 
      ? new ShieldLogger({ ...opts.logging, format: opts.logging?.format || 'json' }) 
      : createNullLogger();

    // SQL persistence
    this.persistence = opts.persistence ? new PersistenceStore(opts.persistence) : null;

    this._wired = false;
  }

  _wire() {
    if (this._wired) return;
    this._wired = true;

    // scan detection -> threat intel + kill chain + alerts
    this.scanner.on('scan-detected', (det) => {
      this.threatIntel.recordEvent(det.ip, 'scan-detected', det.severity);
      this.killChain.record(det.ip, det.type ?? 'port-scan', { severity: det.severity, portCount: det.portCount });
      this.alerts.fire({
        type:      'scan-detected',
        ip:        det.ip,
        severity:  det.severity,
        scanType:  det.type,
        portCount: det.portCount,
      });
      this.emit('scan', det);
    });

    // honeypot connections -> kill chain + threat intel
    this.honeypot.on('connection', (conn) => {
      this.threatIntel.recordEvent(conn.ip, 'honeypot-hit', 'high');
      this.killChain.record(conn.ip, 'honeypot', { port: conn.port, service: conn.service });
      this.scanner.ingest({ srcIp: conn.ip, dstPort: conn.port, flags: { syn: true } });
      this.alerts.fire({
        type:     'honeypot-hit',
        ip:       conn.ip,
        port:     conn.port,
        banner:   conn.banner,
        severity: 'high',
      });
      this.emit('honeypot', conn);
    });

    // exfil alerts -> kill chain + threat intel
    this.exfil.on('exfil-alert', (alert) => {
      if (alert.remoteAddr) {
        this.threatIntel.recordEvent(alert.remoteAddr, 'exfil-attempt', alert.severity);
        this.killChain.record(alert.remoteAddr, 'exfil', { bytes: alert.bytes, pid: alert.pid });
      }
      this.alerts.fire({
        type:        `exfil:${alert.type}`,
        severity:    alert.severity,
        pid:         alert.pid,
        processName: alert.processName,
      });
      this.emit('exfil', alert);
    });

    // DNS tunneling -> kill chain + alerts
    this.dns.on('tunnel-detected', (alert) => {
      this.killChain.record(alert.ip ?? alert.srcIp, 'dns-tunnel', { domain: alert.domain, entropy: alert.entropy });
      this.alerts.fire({
        type:     'dns-tunnel',
        severity: alert.score > 0.7 ? 'high' : 'medium',
        domain:   alert.domain,
        score:    alert.score,
      });
      this.emit('dns-tunnel', alert);
    });

    // kill chain -> campaign detected
    this.killChain.on('campaign-detected', (campaign) => {
      this.alerts.fire({
        type:      'campaign-detected',
        ip:        campaign.ip,
        severity:  campaign.severity,
        stages:    campaign.stageCount,
        score:     campaign.score,
        techniques:campaign.stages.map(s => s.technique),
      });
      this.emit('campaign-detected', campaign);
    });

    // connection table -> forward event
    this.connections.on('new-connection', (conn) => {
      this.emit('new-connection', conn);
    });

    // p2p mesh -> feed received threats into local threat intel
    if (this.mesh) {
      this.mesh.on('threat-received', (event) => {
        this.threatIntel.recordEvent(event.ip, event.eventType, event.severity);
        this.emit('threat-received', event);
      });
      this.mesh.on('peer-joined',    (peer)  => this.emit('peer-joined', peer));
      this.mesh.on('peer-left',      (peer)  => this.emit('peer-left', peer));
      this.mesh.on('threat-shared',  (event) => this.emit('threat-shared', event));
    }

    // pulse integration events
    if (this.pulse) {
      this.pulse.on('blocked', (result) => {
        this.emit('pulse-blocked', result);
      });
      this.pulse.on('population-analysis', (result) => {
        this.emit('coordination-detected', result);
      });
    }

    // audit logging & persistence
    this.on('scan', (det) => {
      this.logger.security('PortScanner', 'scan-detected', det.ip, det.severity, det);
      if (this.persistence) this.persistence.saveThreatEvent({ ...det, type: 'port-scan' });
    });

    this.on('honeypot', (conn) => {
      this.logger.security('Honeypot', 'honeypot-hit', conn.ip, 'high', conn);
      if (this.persistence) this.persistence.saveThreatEvent({ ...conn, type: 'honeypot-hit', severity: 'high' });
    });

    this.on('exfil', (alert) => {
      this.logger.security('ExfilDetector', 'exfil-suspected', alert.remoteAddr || 'local', alert.severity, alert);
      if (this.persistence) this.persistence.saveThreatEvent({ ...alert, type: 'exfil' });
    });

    this.on('dns-tunnel', (alert) => {
      this.logger.security('DNSMonitor', 'dns-tunnel-detected', alert.ip, 'high', alert);
      if (this.persistence) this.persistence.saveThreatEvent({ ...alert, type: 'dns-tunnel', severity: 'high' });
    });

    this.alerts.on('alert', (alert) => {
      if (this.persistence) this.persistence.saveAlert(alert);
    });

    this.threatIntel.on('reputation-changed', (rep) => {
      if (this.persistence) this.persistence.saveReputation(rep.ip, this.threatIntel.getProfile(rep.ip));
    });

    this.killChain.on('event-recorded', (e) => {
      if (this.persistence) this.persistence.saveKillChain(this.killChain.getChain(e.ip));
    });

    if (this.mesh) {
      this.mesh.on('threat-received', (e) => {
        if (this.persistence) this.persistence.saveMeshEvent(e);
      });
    }

    this.honeypot.on('forensics', (f) => {
      this.logger.info('Honeypot', 'forensic-record', f);
      if (this.persistence) this.persistence.saveForensicRecord(f);
      this.threatIntel.recordEvent(f.ip, 'honeypot-forensics', 'medium');
    });
  }

  async start() {
    this._wire();

    this.scanner.start();
    this.rateLimiter.start();
    this.threatIntel.start();

    await this.honeypot.start();

    // register reputation providers
    if (this._opts.threatIntel?.abuseIPDBKey) {
      this.threatIntel.addProvider(new AbuseIPDBProvider(this._opts.threatIntel.abuseIPDBKey));
    }

    this.connections.start();
    this.dns.start();

    if (this.mesh) await this.mesh.start();

    if (this.persistence) {
      await this.persistence.open();
      // TODO: hydration logic for threatIntel/killChain from DB
    }

    this.logger.info('Shield', 'started', {
      honeypots: this.honeypot.activePorts.length,
      mesh:      !!this.mesh,
    });

    return this;
  }

  stop() {
    if (this.mesh) this.mesh.stop();
    this.killChain.stop();
    this.honeypot.stop();
    this.connections.stop();
    this.scanner.stop();
    this.rateLimiter.stop();
    this.threatIntel.stop();
    this.dns.stop();
    this.emit('stopped');
  }

  investigate(ip) {
    return {
      reputation:        this.threatIntel.getProfile(ip),
      connections:       this.connections.byIP(ip),
      connectionHistory: this.connections.queryHistory({ ip }),
      scanActivity:      this.scanner.getProfile(ip),
      honeypotHits:      this.honeypot.getConnectionInfo(ip),
      alerts:            this.alerts.query({ ip }),
      rateLimit:         this.rateLimiter.getProfile(ip),
      killChain:         this.killChain.getChain(ip),
      forensics:         this.persistence?.getForensics(ip) || [],
    };
  }

  /**
   * Generates a comprehensive forensic report for an IP.
   */
  collectEvidence(ip) {
    const raw = this.investigate(ip);
    const summary = {
      ip,
      threatScore: raw.reputation?.score ?? 0.5,
      classification: raw.reputation?.classification ?? 'unknown',
      killChainStage: raw.killChain?.stageList.pop() || 'none',
      totalAlerts: raw.alerts.length,
      firstSeen: raw.reputation?.firstSeen,
      lastSeen: raw.reputation?.lastSeen,
    };

    return {
      metadata: {
        generatedAt: new Date().toISOString(),
        shieldVersion: '0.2.0',
        targetIP: ip,
      },
      summary,
      evidence: raw,
    };
  }

  get status() {
    return {
      scanner:     this.scanner.stats,
      connections: this.connections.summary(),
      rateLimiter: this.rateLimiter.stats,
      threatIntel: this.threatIntel.stats,
      alerts:      this.alerts.stats,
      honeypot:    this.honeypot.stats,
      exfil:       this.exfil.stats,
      dns:         this.dns.stats,
      killChain:   this.killChain.stats,
      mesh:        this.mesh?.stats  || null,
      pulse:       this.pulse?.stats || null,
    };
  }

  static create(opts) {
    return new Shield(opts).start();
  }
}

// Re-exports
export { PortScanDetector } from './core/portScanner.js';
export { ConnectionTable } from './core/connectionTable.js';
export { BehavioralRateLimiter } from './core/rateLimiter.js';
export { ThreatIntel } from './core/threatIntel.js';
export { AlertPipeline } from './core/alertPipeline.js';
export { HoneypotMesh } from './honeypot/mesh.js';
export { getBanner, listBanners, BANNERS } from './honeypot/banners.js';
export { ExfilDetector } from './sentinel/exfilDetector.js';
export { DNSMonitor } from './sentinel/dnsMonitor.js';
export { ThreatMesh } from './mesh/threatMesh.js';
export { PulseShield } from './integrations/pulseShield.js';
export { KillChainTracker, TECHNIQUES } from './core/killChain.js';
