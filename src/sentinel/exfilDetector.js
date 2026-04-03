import { EventEmitter } from 'node:events';
import { RingBuffer } from '../utils/ringBuffer.js';
import { isPrivateIP } from '../utils/geoip.js';
import { BehavioralBaseline } from '../utils/stats.js';

export class ExfilDetector extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._thresholds = {
      uploadBytesPerMin: opts.uploadBytesPerMin || 10 * 1024 * 1024,  // 10MB/min
      unusualPortRange: opts.unusualPorts || [1, 79, 81, 442, 444, 1023],
      newDestinationBurst: opts.newDestBurst || 5,                     // 5 new dests in window
      burstWindowMs: opts.burstWindow || 60_000,
      dnsEntropyThreshold: opts.dnsEntropy || 3.5,
      connectionRateThreshold: opts.connRate || 30,                    // new conns/min
      ...opts.thresholds,
    };
    this._processProfiles = new Map();
    this._alerts = [];
    this._maxAlerts = opts.maxAlerts || 5000;
  }

  ingest(event) {
    const {
      pid, processName, remoteAddr, remotePort,
      bytesSent = 0, bytesReceived = 0, direction = 'outbound',
    } = event;

    if (!remoteAddr || isPrivateIP(remoteAddr)) return null;

    const profile = this._getProfile(pid, processName);
    const now = Date.now();

    profile.events.push({
      remoteAddr, remotePort, bytesSent, bytesReceived,
      direction, ts: now,
    });

    const isNewDest = !profile.knownDestinations.has(remoteAddr);
    if (isNewDest) {
      profile.knownDestinations.add(remoteAddr);
      profile.recentNewDests.push({ addr: remoteAddr, ts: now });
    }

    profile.totalBytesSent += bytesSent;
    profile.totalBytesReceived += bytesReceived;
    profile.connectionCount++;

    const alerts = [];

    // 1. Volume-based exfil: large uploads
    const recentSent = this._recentBytesSent(profile, 60_000);
    this._updateBaseline(profile, recentSent);

    if (profile.baseline?.isAnomalous(recentSent, 4)) {
      alerts.push(this._alert(profile, 'anomalous-upload-volume', 'critical', {
        bytesPerMin: recentSent,
        baseline: profile.baseline.toJSON(),
      }));
    } else if (recentSent > this._thresholds.uploadBytesPerMin) {
      alerts.push(this._alert(profile, 'high-upload-volume', 'high', {
        bytesPerMin: recentSent,
        threshold: this._thresholds.uploadBytesPerMin,
        remoteAddr,
      }));
    }

    // 2. Unusual port usage
    if (this._isUnusualPort(remotePort)) {
      alerts.push(this._alert(profile, 'unusual-port', 'medium', {
        port: remotePort,
        remoteAddr,
      }));
    }

    // 3. Destination burst: many new destinations in short window
    const recentNewDests = profile.recentNewDests.filter(
      d => d.ts >= now - this._thresholds.burstWindowMs
    );
    if (recentNewDests.length >= this._thresholds.newDestinationBurst) {
      alerts.push(this._alert(profile, 'destination-burst', 'high', {
        newDestinations: recentNewDests.length,
        window: this._thresholds.burstWindowMs,
        destinations: recentNewDests.map(d => d.addr),
      }));
    }

    // 4. Asymmetric traffic: sending much more than receiving
    if (profile.totalBytesSent > 1024 * 1024) {
      const ratio = profile.totalBytesSent / Math.max(1, profile.totalBytesReceived);
      if (ratio > 10) {
        alerts.push(this._alert(profile, 'asymmetric-traffic', 'medium', {
          sentTotal: profile.totalBytesSent,
          receivedTotal: profile.totalBytesReceived,
          ratio: Math.round(ratio * 10) / 10,
        }));
      }
    }

    // 5. Connection rate spike
    const recentConns = profile.events.filter(e => e.ts >= now - 60_000).length;
    if (recentConns >= this._thresholds.connectionRateThreshold) {
      alerts.push(this._alert(profile, 'connection-rate-spike', 'medium', {
        connectionsPerMin: recentConns,
        threshold: this._thresholds.connectionRateThreshold,
      }));
    }

    // 6. Beaconing detection: regular interval connections
    const beacon = this._detectBeaconing(profile);
    if (beacon) {
      alerts.push(this._alert(profile, 'beaconing', 'critical', beacon));
    }

    // trim old events
    if (profile.events.size > 1500) {
      // ring buffer auto-handles this
    }
    if (profile.recentNewDests.length > 200) {
      profile.recentNewDests = profile.recentNewDests.slice(-160);
    }

    return alerts.length > 0 ? alerts : null;
  }

  _getProfile(pid, processName) {
    const key = `${pid}:${processName}`;
    if (!this._processProfiles.has(key)) {
      this._processProfiles.set(key, {
        pid,
        processName,
        events: new RingBuffer(2048),
        knownDestinations: new Set(),
        recentNewDests: [],
        totalBytesSent: 0,
        totalBytesReceived: 0,
        connectionCount: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        alertCount: 0,
      });
    }
    const p = this._processProfiles.get(key);
    p.lastSeen = Date.now();
    return p;
  }

  _recentBytesSent(profile, windowMs) {
    const cutoff = Date.now() - windowMs;
    let total = 0;
    for (const e of profile.events) {
      if (e.ts >= cutoff) total += (e.bytesSent || 0);
    }
    return total;
  }

  _updateBaseline(profile, bytesSent) {
    if (!profile.baseline) {
      profile.baseline = new BehavioralBaseline();
    }
    // only update if not currently anomalous (don't train on attack)
    if (!profile.baseline.isAnomalous(bytesSent, 5)) {
      profile.baseline.update(bytesSent);
    }
  }

  _isUnusualPort(port) {
    // common outbound ports
    const normalPorts = new Set([80, 443, 8080, 8443, 53, 22, 993, 587, 465, 143, 110, 995]);
    return !normalPorts.has(port);
  }

  _detectBeaconing(profile) {
    const events = profile.events.toArray();
    if (events.length < 10) return null;

    // compute inter-event intervals
    const intervals = [];
    for (let i = 1; i < events.length; i++) {
      intervals.push(events[i].ts - events[i - 1].ts);
    }

    if (intervals.length < 5) return null;

    // check for regularity: low coefficient of variation
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean < 1000) return null; // sub-second intervals aren't beaconing

    const variance = intervals.reduce((a, v) => a + (v - mean) ** 2, 0) / intervals.length;
    const stddev = Math.sqrt(variance);
    const cv = stddev / mean;

    // CV < 0.3 = very regular intervals = likely beaconing
    if (cv < 0.3 && intervals.length >= 8) {
      return {
        intervalMs: Math.round(mean),
        stddev: Math.round(stddev),
        cv: Math.round(cv * 1000) / 1000,
        samples: intervals.length,
        destinations: [...new Set(events.map(e => e.remoteAddr))],
      };
    }

    return null;
  }

  _alert(profile, type, severity, meta) {
    profile.alertCount++;
    const alert = {
      type,
      severity,
      pid: profile.pid,
      processName: profile.processName,
      ts: Date.now(),
      ...meta,
    };
    this._alerts.push(alert);
    if (this._alerts.length > this._maxAlerts) {
      this._alerts = this._alerts.slice(-Math.floor(this._maxAlerts * 0.8));
    }
    this.emit('exfil-alert', alert);
    return alert;
  }

  getProfile(pid, processName) {
    const key = `${pid}:${processName}`;
    const p = this._processProfiles.get(key);
    if (!p) return null;
    return {
      pid: p.pid,
      processName: p.processName,
      knownDestinations: [...p.knownDestinations],
      totalBytesSent: p.totalBytesSent,
      totalBytesReceived: p.totalBytesReceived,
      connectionCount: p.connectionCount,
      alertCount: p.alertCount,
      age: Date.now() - p.firstSeen,
    };
  }

  getSuspiciousProcesses() {
    const results = [];
    for (const p of this._processProfiles.values()) {
      if (p.alertCount > 0) {
        results.push({
          pid: p.pid,
          processName: p.processName,
          alertCount: p.alertCount,
          totalBytesSent: p.totalBytesSent,
          destinations: p.knownDestinations.size,
        });
      }
    }
    return results.sort((a, b) => b.alertCount - a.alertCount);
  }

  getAlerts(filter = {}) {
    let results = this._alerts;
    if (filter.type) results = results.filter(a => a.type === filter.type);
    if (filter.severity) results = results.filter(a => a.severity === filter.severity);
    if (filter.pid) results = results.filter(a => a.pid === filter.pid);
    if (filter.since) results = results.filter(a => a.ts >= filter.since);
    return results;
  }

  get stats() {
    return {
      module: 'ExfilDetector',
      trackedProcesses: this._processProfiles.size,
      totalAlerts: this._alerts.length,
      suspiciousProcesses: this.getSuspiciousProcesses().length,
    };
  }
}
