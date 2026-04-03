import { EventEmitter } from 'node:events';

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

    // p2p threat mesh (optional — pass opts.mesh to enable)
    this.mesh = opts.mesh ? new ThreatMesh(opts.mesh) : null;

    // pulse integration (optional — pass opts.pulse to enable)
    this.pulse = opts.pulse ? new PulseShield({ shield: this, ...opts.pulse }) : null;

    this._wired = false;
  }

  _wire() {
    if (this._wired) return;
    this._wired = true;

    // scan detection -> threat intel + alerts
    this.scanner.on('scan-detected', (det) => {
      this.threatIntel.recordEvent(det.ip, 'scan-detected', det.severity);
      this.alerts.fire({
        type:      'scan-detected',
        ip:        det.ip,
        severity:  det.severity,
        scanType:  det.type,
        portCount: det.portCount,
      });
      this.emit('scan', det);
    });

    // honeypot connections -> zero false positive threat intel
    this.honeypot.on('connection', (conn) => {
      this.threatIntel.recordEvent(conn.ip, 'honeypot-hit', 'high');
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

    // exfil alerts -> threat intel + alerts
    this.exfil.on('exfil-alert', (alert) => {
      if (alert.remoteAddr) {
        this.threatIntel.recordEvent(alert.remoteAddr, 'exfil-attempt', alert.severity);
      }
      this.alerts.fire({
        type:        `exfil:${alert.type}`,
        severity:    alert.severity,
        pid:         alert.pid,
        processName: alert.processName,
      });
      this.emit('exfil', alert);
    });

    // DNS tunneling -> alerts
    this.dns.on('tunnel-detected', (alert) => {
      this.alerts.fire({
        type:     'dns-tunnel',
        severity: alert.score > 0.7 ? 'high' : 'medium',
        domain:   alert.domain,
        score:    alert.score,
      });
      this.emit('dns-tunnel', alert);
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
  }

  async start() {
    this._wire();

    this.scanner.start();
    this.rateLimiter.start();
    this.threatIntel.start();

    await this.honeypot.start();

    this.connections.start();
    this.dns.start();

    if (this.mesh) await this.mesh.start();

    this.emit('started', {
      honeypots: this.honeypot.activePorts.length,
      mesh:      !!this.mesh,
    });

    return this;
  }

  stop() {
    if (this.mesh) this.mesh.stop();
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
