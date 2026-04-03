import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:os';
import { readFile } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { classifyIP, isPrivateIP } from '../utils/geoip.js';

const exec = promisify(execFile);

const STATES = {
  '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
  '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
  '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
  '0A': 'LISTEN', '0B': 'CLOSING',
};

export class ConnectionTable extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._pollInterval = opts.pollInterval || 3000;
    this._connections = new Map();
    this._history = [];
    this._maxHistory = opts.maxHistory || 10000;
    this._timer = null;
    this._os = platform();
    this._enrichGeo = opts.geoip !== false;
    this._ipProfiles = new Map();
    this._snapCount = 0;
  }

  async snapshot() {
    const raw = this._os === 'win32' ? await this._parseWindows() : await this._parseLinux();
    const now = Date.now();
    const prev = new Map(this._connections);
    this._connections.clear();
    this._snapCount++;

    for (const conn of raw) {
      const key = `${conn.proto}:${conn.localAddr}:${conn.localPort}-${conn.remoteAddr}:${conn.remotePort}`;
      conn.key = key;
      this._connections.set(key, conn);

      if (!prev.has(key)) {
        conn.firstSeen = now;
        this._trackIP(conn.remoteAddr, conn);
        this.emit('new-connection', conn);
      } else {
        conn.firstSeen = prev.get(key).firstSeen;
      }
    }

    for (const [key, conn] of prev) {
      if (!this._connections.has(key)) {
        conn.closedAt = now;
        conn.duration = now - (conn.firstSeen || now);
        this._pushHistory(conn);
        this.emit('closed-connection', conn);
      }
    }

    this.emit('snapshot', this.summary());
    return this.list();
  }

  _trackIP(ip, conn) {
    if (!ip || isPrivateIP(ip)) return;
    if (!this._ipProfiles.has(ip)) {
      this._ipProfiles.set(ip, {
        ip,
        firstSeen: Date.now(),
        connectionCount: 0,
        ports: new Set(),
        states: new Map(),
      });
    }
    const profile = this._ipProfiles.get(ip);
    profile.connectionCount++;
    profile.ports.add(conn.localPort);
    profile.lastSeen = Date.now();
    const sc = profile.states.get(conn.state) || 0;
    profile.states.set(conn.state, sc + 1);
  }

  _pushHistory(conn) {
    this._history.push(conn);
    if (this._history.length > this._maxHistory) {
      this._history = this._history.slice(-Math.floor(this._maxHistory * 0.8));
    }
  }

  async _parseWindows() {
    const results = [];
    try {
      const { stdout } = await exec('netstat', ['-ano']);
      for (const line of stdout.split('\n').slice(4)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) continue;
        const proto = parts[0].toLowerCase();
        if (proto !== 'tcp' && proto !== 'udp') continue;

        const local = parts[1];
        const remote = parts[2];
        const lColon = local.lastIndexOf(':');
        const rColon = remote.lastIndexOf(':');

        results.push({
          proto,
          localAddr: local.slice(0, lColon),
          localPort: parseInt(local.slice(lColon + 1), 10),
          remoteAddr: remote.slice(0, rColon),
          remotePort: parseInt(remote.slice(rColon + 1), 10),
          state: proto === 'tcp' ? (parts[3] || 'UNKNOWN') : 'STATELESS',
          pid: parseInt(parts[proto === 'tcp' ? 4 : 3], 10) || null,
        });
      }
    } catch { /* fallback gracefully */ }
    return results;
  }

  async _parseLinux() {
    const results = [];
    try {
      const data = await readFile('/proc/net/tcp', 'utf8');
      for (const line of data.split('\n').slice(1)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) continue;
        const [lHex, lPortHex] = parts[1].split(':');
        const [rHex, rPortHex] = parts[2].split(':');

        const parseAddr = hex => {
          const n = parseInt(hex, 16);
          return `${n & 0xFF}.${(n >> 8) & 0xFF}.${(n >> 16) & 0xFF}.${(n >> 24) & 0xFF}`;
        };

        results.push({
          proto: 'tcp',
          localAddr: parseAddr(lHex),
          localPort: parseInt(lPortHex, 16),
          remoteAddr: parseAddr(rHex),
          remotePort: parseInt(rPortHex, 16),
          state: STATES[parts[3]] || 'UNKNOWN',
          pid: null,
        });
      }
    } catch {
      try {
        const { stdout } = await exec('ss', ['-tnp']);
        for (const line of stdout.split('\n').slice(1)) {
          const parts = line.trim().split(/\s+/);
          if (parts.length < 5) continue;
          const local = parts[3];
          const remote = parts[4];
          const lColon = local.lastIndexOf(':');
          const rColon = remote.lastIndexOf(':');
          results.push({
            proto: 'tcp',
            localAddr: local.slice(0, lColon),
            localPort: parseInt(local.slice(lColon + 1), 10),
            remoteAddr: remote.slice(0, rColon),
            remotePort: parseInt(remote.slice(rColon + 1), 10),
            state: parts[0],
            pid: null,
          });
        }
      } catch { /* no access */ }
    }
    return results;
  }

  start() {
    this.snapshot();
    this._timer = setInterval(() => this.snapshot(), this._pollInterval);
    this._timer.unref?.();
    return this;
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  list() { return [...this._connections.values()]; }

  established() {
    return this.list().filter(c => c.state === 'ESTABLISHED');
  }

  halfOpen() {
    return this.list().filter(c => c.state === 'SYN_SENT' || c.state === 'SYN_RECV');
  }

  timeWait() {
    return this.list().filter(c => c.state === 'TIME_WAIT');
  }

  byIP(ip) {
    return this.list().filter(c => c.remoteAddr === ip);
  }

  byPort(port) {
    return this.list().filter(c => c.localPort === port);
  }

  async enrichIP(ip) {
    return classifyIP(ip);
  }

  getIPProfile(ip) {
    const p = this._ipProfiles.get(ip);
    if (!p) return null;
    return { ...p, ports: [...p.ports], states: Object.fromEntries(p.states) };
  }

  queryHistory(filter = {}) {
    let results = this._history;
    if (filter.ip) results = results.filter(c => c.remoteAddr === filter.ip);
    if (filter.port) results = results.filter(c => c.localPort === filter.port);
    if (filter.since) results = results.filter(c => (c.closedAt || 0) >= filter.since);
    if (filter.state) results = results.filter(c => c.state === filter.state);
    return results;
  }

  summary() {
    const conns = this.list();
    const byState = {};
    for (const c of conns) {
      byState[c.state] = (byState[c.state] || 0) + 1;
    }
    const uniqueRemotes = new Set(conns.map(c => c.remoteAddr));
    return {
      total: conns.length,
      byState,
      uniqueRemoteIPs: uniqueRemotes.size,
      halfOpen: this.halfOpen().length,
      snapshots: this._snapCount,
      trackedIPs: this._ipProfiles.size,
    };
  }
}
