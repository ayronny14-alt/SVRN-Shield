import { EventEmitter } from 'node:events';
import { RingBuffer } from '../utils/ringBuffer.js';
import { PortBitfield } from '../utils/bitfield.js';

const SCAN_TYPES = {
  SYN:     'syn_scan',
  FIN:     'fin_scan',
  NULL:    'null_scan',
  XMAS:    'xmas_scan',
  UDP:     'udp_scan',
  CONNECT: 'connect_scan',
  SLOW:    'slow_scan',
  SWEEP:   'port_sweep',
};

export class PortScanDetector extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._windowMs = opts.window || 10_000;
    this._thresholds = {
      portsPerWindow: opts.portsPerWindow || 15,
      connectsPerSecond: opts.connectsPerSecond || 20,
      synWithoutAck: opts.synWithoutAck || 10,
      slowScanPorts: opts.slowScanPorts || 25,
      slowScanWindowMs: opts.slowScanWindow || 300_000,
      ...opts.thresholds,
    };
    this._trackers = new Map();    // ip -> tracker
    this._slowTrackers = new Map();// ip -> slow scan tracker
    this._sweepWindow = new RingBuffer(4096);
    this._gcInterval = null;
    this._blocked = new Set();
  }

  start() {
    this._gcInterval = setInterval(() => this._gc(), 30_000);
    this._gcInterval.unref?.();
    return this;
  }

  stop() {
    if (this._gcInterval) clearInterval(this._gcInterval);
    this._gcInterval = null;
  }

  _getTracker(ip) {
    if (!this._trackers.has(ip)) {
      this._trackers.set(ip, {
        ip,
        ports: new PortBitfield(),
        events: new RingBuffer(512),
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalProbes: 0,
        halfOpen: 0,
        detections: [],
      });
    }
    const t = this._trackers.get(ip);
    t.lastSeen = Date.now();
    return t;
  }

  _getSlowTracker(ip) {
    if (!this._slowTrackers.has(ip)) {
      this._slowTrackers.set(ip, {
        ip,
        ports: new PortBitfield(),
        firstSeen: Date.now(),
        lastSeen: Date.now(),
      });
    }
    const t = this._slowTrackers.get(ip);
    t.lastSeen = Date.now();
    return t;
  }

  ingest(event) {
    const { srcIp, dstPort, flags = {}, proto = 'tcp' } = event;
    if (!srcIp || dstPort == null) return null;

    const tracker = this._getTracker(srcIp);
    const now = Date.now();

    tracker.totalProbes++;
    tracker.ports.set(dstPort);
    tracker.events.push({ port: dstPort, ts: now, flags, proto });

    // slow scan tracking (wider window)
    const slow = this._getSlowTracker(srcIp);
    slow.ports.set(dstPort);

    // sweep tracking (all IPs)
    this._sweepWindow.push({ ip: srcIp, port: dstPort, ts: now });

    const detections = [];

    // 1. Fast port scan: many unique ports in short window
    const recentPorts = new Set();
    const cutoff = now - this._windowMs;
    for (const e of tracker.events) {
      if (e.ts >= cutoff) recentPorts.add(e.port);
    }
    if (recentPorts.size >= this._thresholds.portsPerWindow) {
      detections.push(this._detect(tracker, SCAN_TYPES.CONNECT, recentPorts.size));
    }

    // 2. SYN scan: SYN flags without completing handshake
    if (flags.syn && !flags.ack) {
      tracker.halfOpen++;
      if (tracker.halfOpen >= this._thresholds.synWithoutAck) {
        detections.push(this._detect(tracker, SCAN_TYPES.SYN, tracker.halfOpen));
      }
    }
    if (flags.syn && flags.ack) {
      tracker.halfOpen = Math.max(0, tracker.halfOpen - 1);
    }

    // 3. FIN scan
    if (flags.fin && !flags.ack && !flags.syn) {
      detections.push(this._detect(tracker, SCAN_TYPES.FIN, 1));
    }

    // 4. NULL scan (no flags)
    if (proto === 'tcp' && !flags.syn && !flags.ack && !flags.fin && !flags.rst && !flags.psh) {
      detections.push(this._detect(tracker, SCAN_TYPES.NULL, 1));
    }

    // 5. XMAS scan (FIN + PSH + URG)
    if (flags.fin && flags.psh && flags.urg) {
      detections.push(this._detect(tracker, SCAN_TYPES.XMAS, 1));
    }

    // 6. UDP scan
    if (proto === 'udp') {
      const udpPorts = tracker.events.filter(e => e.proto === 'udp' && e.ts >= cutoff);
      const udpUnique = new Set(udpPorts.map(e => e.port));
      if (udpUnique.size >= this._thresholds.portsPerWindow) {
        detections.push(this._detect(tracker, SCAN_TYPES.UDP, udpUnique.size));
      }
    }

    // 7. Slow scan: many ports over long window
    if (slow.ports.count >= this._thresholds.slowScanPorts) {
      const age = now - slow.firstSeen;
      if (age >= this._thresholds.slowScanWindowMs) {
        detections.push(this._detect(tracker, SCAN_TYPES.SLOW, slow.ports.count));
        this._slowTrackers.delete(srcIp); // reset after detection
      }
    }

    return detections.length > 0 ? detections : null;
  }

  _detect(tracker, type, portCount) {
    const detection = {
      type,
      ip: tracker.ip,
      portCount,
      totalProbes: tracker.totalProbes,
      uniquePorts: tracker.ports.count,
      duration: Date.now() - tracker.firstSeen,
      ts: Date.now(),
      severity: this._severity(type, portCount),
    };
    tracker.detections.push(detection);
    this.emit('scan-detected', detection);
    return detection;
  }

  _severity(type, portCount) {
    if (type === SCAN_TYPES.XMAS || type === SCAN_TYPES.NULL) return 'critical';
    if (type === SCAN_TYPES.SYN && portCount > 50) return 'critical';
    if (portCount > 100) return 'high';
    if (type === SCAN_TYPES.SLOW) return 'medium';
    if (portCount > 30) return 'high';
    return 'medium';
  }

  detectSweep() {
    const now = Date.now();
    const cutoff = now - this._windowMs;
    const portMap = new Map();
    for (const e of this._sweepWindow) {
      if (e.ts < cutoff) continue;
      if (!portMap.has(e.port)) portMap.set(e.port, new Set());
      portMap.get(e.port).add(e.ip);
    }
    const sweeps = [];
    for (const [port, ips] of portMap) {
      if (ips.size >= 5) {
        sweeps.push({ port, sourceCount: ips.size, type: SCAN_TYPES.SWEEP });
      }
    }
    return sweeps;
  }

  getProfile(ip) {
    const t = this._trackers.get(ip);
    if (!t) return { ip, ports: [], events: [], totalProbes: 0, detections: [], firstSeen: null, lastSeen: null };
    return {
      ...t,
      ports: t.ports.listSet(),
      events: t.events.toArray(),
    };
  }

  isBlocked(ip) { return this._blocked.has(ip); }
  block(ip) { this._blocked.add(ip); }
  unblock(ip) { this._blocked.delete(ip); }

  _gc() {
    const now = Date.now();
    const expiry = this._windowMs * 6;
    for (const [ip, t] of this._trackers) {
      if (now - t.lastSeen > expiry) this._trackers.delete(ip);
    }
    for (const [ip, t] of this._slowTrackers) {
      if (now - t.lastSeen > this._thresholds.slowScanWindowMs * 2) {
        this._slowTrackers.delete(ip);
      }
    }
  }

  get stats() {
    return {
      module: 'PortScanDetector',
      trackedIPs: this._trackers.size,
      slowTrackedIPs: this._slowTrackers.size,
      blockedIPs: this._blocked.size,
    };
  }
}
