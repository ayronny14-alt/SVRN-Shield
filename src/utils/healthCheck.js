/**
 * Health check and Prometheus-compatible metrics export for Shield.
 *
 * shield.health()   → structured health report
 * shield.metrics()  → Prometheus text format
 *
 * Optional: Start a lightweight HTTP server for /healthz and /metrics
 *   shield.startHealthServer(9100)
 */

import http from 'node:http';
import { EventEmitter } from 'node:events';

export class HealthCheck extends EventEmitter {
  constructor(shield) {
    super();
    this._shield = shield;
    this._startedAt = Date.now();
    this._httpServer = null;
    this._customChecks = [];
  }

  /**
   * Add a custom health check function.
   * @param {string} name
   * @param {function} fn — returns { ok: bool, detail?: string }
   */
  addCheck(name, fn) {
    this._customChecks.push({ name, fn });
    return this;
  }

  /**
   * Full health report.
   */
  health() {
    const s = this._shield;
    const now = Date.now();
    const uptimeMs = now - this._startedAt;

    const modules = {};
    const moduleNames = [
      'scanner', 'connections', 'rateLimiter', 'threatIntel',
      'alerts', 'honeypot', 'exfil', 'dns', 'killChain',
    ];

    for (const name of moduleNames) {
      const mod = s[name];
      if (mod) {
        modules[name] = {
          ok: true,
          stats: mod.stats || {},
        };
      }
    }

    if (s.mesh) {
      const meshStats = s.mesh.stats;
      modules.mesh = {
        ok: meshStats.peers > 0 || true, // mesh is ok even with 0 peers on a single node
        peers: meshStats.peers,
        stats: meshStats,
      };
    }

    if (s.persistence) {
      try {
        const pStats = s.persistence.stats;
        modules.persistence = { ok: pStats.ready, stats: pStats };
      } catch {
        modules.persistence = { ok: false, error: 'unreachable' };
      }
    }

    // Custom checks
    const customResults = {};
    for (const { name, fn } of this._customChecks) {
      try {
        customResults[name] = fn();
      } catch (err) {
        customResults[name] = { ok: false, error: err.message };
      }
    }

    const allOk = Object.values(modules).every(m => m.ok !== false);

    return {
      status: allOk ? 'healthy' : 'degraded',
      uptime: uptimeMs,
      uptimeHuman: this._formatUptime(uptimeMs),
      startedAt: new Date(this._startedAt).toISOString(),
      checkedAt: new Date(now).toISOString(),
      memory: {
        rss: process.memoryUsage().rss,
        heapUsed: process.memoryUsage().heapUsed,
        heapTotal: process.memoryUsage().heapTotal,
        external: process.memoryUsage().external,
      },
      modules,
      custom: customResults,
    };
  }

  /**
   * Prometheus-compatible metrics in text exposition format.
   */
  metrics() {
    const s = this._shield;
    const lines = [];
    const now = Date.now();

    const gauge = (name, help, value, labels = {}) => {
      const lStr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',');
      lines.push(`# HELP ${name} ${help}`);
      lines.push(`# TYPE ${name} gauge`);
      lines.push(lStr ? `${name}{${lStr}} ${value}` : `${name} ${value}`);
    };

    const counter = (name, help, value, labels = {}) => {
      const lStr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',');
      lines.push(`# HELP ${name} ${help}`);
      lines.push(`# TYPE ${name} counter`);
      lines.push(lStr ? `${name}{${lStr}} ${value}` : `${name} ${value}`);
    };

    // Uptime
    gauge('shield_uptime_seconds', 'Shield uptime in seconds', Math.floor((now - this._startedAt) / 1000));

    // Memory
    const mem = process.memoryUsage();
    gauge('shield_memory_rss_bytes', 'Resident set size', mem.rss);
    gauge('shield_memory_heap_used_bytes', 'Heap used', mem.heapUsed);

    // Scanner
    if (s.scanner) {
      gauge('shield_scanner_tracked_ips', 'IPs currently tracked by scan detector', s.scanner.stats.trackedIPs);
      gauge('shield_scanner_blocked_ips', 'IPs blocked by scan detector', s.scanner.stats.blockedIPs);
    }

    // Threat Intel
    if (s.threatIntel) {
      const ti = s.threatIntel.stats;
      gauge('shield_threat_intel_tracked', 'Total IPs tracked', ti.tracked);
      gauge('shield_threat_intel_malicious', 'IPs classified malicious', ti.malicious);
      gauge('shield_threat_intel_suspicious', 'IPs classified suspicious', ti.suspicious);
      gauge('shield_threat_intel_blocklist_entries', 'Total blocklist entries', ti.blocklistEntries);
    }

    // Alert Pipeline
    if (s.alerts) {
      const al = s.alerts.stats;
      counter('shield_alerts_total', 'Total alerts fired', al.total);
      for (const [sev, count] of Object.entries(al.bySeverity || {})) {
        counter('shield_alerts_by_severity', 'Alerts by severity', count, { severity: sev });
      }
    }

    // Honeypot
    if (s.honeypot) {
      const hp = s.honeypot.stats;
      counter('shield_honeypot_connections_total', 'Total honeypot connections', hp.totalConnections);
      gauge('shield_honeypot_unique_ips', 'Unique IPs seen by honeypot', hp.uniqueIPs);
      gauge('shield_honeypot_active_ports', 'Active honeypot ports', hp.activePorts);
    }

    // Rate Limiter
    if (s.rateLimiter) {
      const rl = s.rateLimiter.stats;
      gauge('shield_rate_limiter_tracked', 'Identities tracked', rl.tracked);
      gauge('shield_rate_limiter_blocked', 'Identities currently blocked', rl.blocked);
    }

    // Kill Chain
    if (s.killChain) {
      const kc = s.killChain.stats;
      gauge('shield_kill_chain_tracked', 'Active kill chains', kc.tracked);
      gauge('shield_kill_chain_campaigns', 'Campaigns detected', kc.campaigns);
    }

    // Mesh
    if (s.mesh) {
      const ms = s.mesh.stats;
      gauge('shield_mesh_peers', 'Connected mesh peers', ms.peers);
      counter('shield_mesh_events_shared', 'Events shared to mesh', ms.eventsShared);
      counter('shield_mesh_events_received', 'Events received from mesh', ms.eventsReceived);
      counter('shield_mesh_events_rejected', 'Events rejected (bad sig)', ms.eventsRejected);
    }

    // DNS
    if (s.dns) {
      const dn = s.dns.stats;
      gauge('shield_dns_tracked_domains', 'Domains tracked', dn.trackedDomains);
      counter('shield_dns_alerts', 'DNS tunnel alerts', dn.alerts);
    }

    // ExfilDetector
    if (s.exfil) {
      const ex = s.exfil.stats;
      gauge('shield_exfil_tracked_processes', 'Processes tracked', ex.trackedProcesses);
      counter('shield_exfil_alerts_total', 'Exfil alerts total', ex.totalAlerts);
    }

    return lines.join('\n') + '\n';
  }

  /**
   * Start a minimal HTTP server for health checks.
   * @param {number} port
   */
  startServer(port = 9100) {
    this._httpServer = http.createServer((req, res) => {
      if (req.url === '/healthz' || req.url === '/health') {
        const h = this.health();
        res.writeHead(h.status === 'healthy' ? 200 : 503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(h, null, 2));
      } else if (req.url === '/metrics') {
        res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
        res.end(this.metrics());
      } else if (req.url === '/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this._shield.status, null, 2));
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    this._httpServer.listen(port, () => {
      this.emit('listening', { port });
    });

    this._httpServer.on('error', (err) => {
      this.emit('error', err);
    });

    return this;
  }

  stopServer() {
    if (this._httpServer) {
      this._httpServer.close();
      this._httpServer = null;
    }
  }

  _formatUptime(ms) {
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${sec}s`;
    return `${m}m ${sec}s`;
  }
}
