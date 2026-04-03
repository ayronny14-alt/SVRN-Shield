import { EventEmitter } from 'node:events';
import { isPrivateIP, classifyIP } from '../utils/geoip.js';

export class ThreatIntel extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._reputations = new Map();
    this._blocklists = new Map();
    this._decayRate = opts.decayRate || 0.999;
    this._boostRate = opts.boostRate || 0.01;
    this._penaltyRate = opts.penaltyRate || 0.1;
    this._minScore = opts.minScore || 0;
    this._maxScore = opts.maxScore || 1;
    this._defaultScore = opts.defaultScore || 0.5;
    this._blockThreshold = opts.blockThreshold || 0.15;
    this._warnThreshold = opts.warnThreshold || 0.3;
    this._providers = [];
    this._gcInterval = null;
  }

  start() {
    this._gcInterval = setInterval(() => this._decay(), 60_000);
    this._gcInterval.unref?.();
    return this;
  }

  stop() {
    if (this._gcInterval) clearInterval(this._gcInterval);
  }

  _getReputation(ip) {
    if (!this._reputations.has(ip)) {
      this._reputations.set(ip, {
        ip,
        score: this._defaultScore,
        events: [],
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalEvents: 0,
      });
    }
    const r = this._reputations.get(ip);
    r.lastSeen = Date.now();
    return r;
  }

  score(ip) {
    if (isPrivateIP(ip)) return 1.0;

    // check blocklists first (even for unknown IPs)
    for (const list of this._blocklists.values()) {
      if (list.has(ip)) return 0;
    }

    const r = this._reputations.get(ip);
    if (!r) return this._defaultScore;
    return r.score;
  }

  classify(ip) {
    const s = this.score(ip);
    if (s <= this._blockThreshold) return 'malicious';
    if (s <= this._warnThreshold) return 'suspicious';
    if (s >= 0.8) return 'trusted';
    return 'neutral';
  }

  recordEvent(ip, type, severity = 'medium') {
    const r = this._getReputation(ip);
    r.totalEvents++;

    const penalties = {
      'port-scan': 0.2,
      'honeypot-hit': 0.35,
      'brute-force': 0.25,
      'protocol-mismatch': 0.15,
      'exfil-attempt': 0.3,
      'rate-limit': 0.1,
      'scan-detected': 0.2,
    };

    const severityMult = { low: 0.5, medium: 1, high: 1.5, critical: 2.5 };
    const penalty = (penalties[type] || this._penaltyRate) * (severityMult[severity] || 1);

    r.score = Math.max(this._minScore, r.score - penalty);
    r.events.push({ type, severity, ts: Date.now(), scoreDelta: -penalty });

    if (r.events.length > 100) r.events = r.events.slice(-80);

    const classification = this.classify(ip);
    this.emit('reputation-changed', { ip, score: r.score, classification, event: type });

    if (classification === 'malicious') {
      this.emit('malicious-ip', { ip, score: r.score, events: r.totalEvents });
    }

    return r.score;
  }

  reward(ip, amount = null) {
    const r = this._getReputation(ip);
    const boost = amount || this._boostRate;
    r.score = Math.min(this._maxScore, r.score + boost);
    r.events.push({ type: 'reward', ts: Date.now(), scoreDelta: boost });
    return r.score;
  }

  addBlocklist(name, ips) {
    const set = new Set(ips);
    this._blocklists.set(name, set);
    this.emit('blocklist-loaded', { name, count: set.size });
    return this;
  }

  removeBlocklist(name) {
    this._blocklists.delete(name);
    return this;
  }

  addProvider(provider) {
    this._providers.push(provider);
    return this;
  }

  async fetchExternalReputation(ip) {
    const results = [];
    for (const provider of this._providers) {
      try {
        const data = await provider.check(ip);
        if (data) {
          results.push({ provider: provider.name, ...data });
          if (data.scoreDelta) {
            this.recordEvent(ip, `external:${provider.name}`, data.severity || 'medium');
          }
        }
      } catch (err) {
        this.emit('provider-error', { name: provider.name, error: err.message });
      }
    }
    return results;
  }

  isBlocked(ip) {
    return this.score(ip) <= this._blockThreshold;
  }

  isOnBlocklist(ip) {
    for (const list of this._blocklists.values()) {
      if (list.has(ip)) return true;
    }
    return false;
  }

  getProfile(ip) {
    const r = this._reputations.get(ip);
    if (!r) return { ip, score: this._defaultScore, classification: 'unknown', events: [] };
    return {
      ip: r.ip,
      score: r.score,
      classification: this.classify(ip),
      events: r.events.slice(-20),
      totalEvents: r.totalEvents,
      firstSeen: r.firstSeen,
      lastSeen: r.lastSeen,
      age: Date.now() - r.firstSeen,
      onBlocklist: this.isOnBlocklist(ip),
    };
  }

  async enrichProfile(ip) {
    const profile = this.getProfile(ip);
    const geo = await classifyIP(ip);
    return { ...profile, ...geo };
  }

  _decay() {
    for (const r of this._reputations.values()) {
      if (r.score < this._defaultScore) {
        r.score = Math.min(this._defaultScore, r.score + (this._defaultScore - r.score) * 0.01);
      }
    }
  }

  get stats() {
    let malicious = 0, suspicious = 0, trusted = 0;
    for (const r of this._reputations.values()) {
      const c = this.classify(r.ip);
      if (c === 'malicious') malicious++;
      else if (c === 'suspicious') suspicious++;
      else if (c === 'trusted') trusted++;
    }
    return {
      module: 'ThreatIntel',
      tracked: this._reputations.size,
      malicious, suspicious, trusted,
      blocklists: this._blocklists.size,
      blocklistEntries: [...this._blocklists.values()].reduce((a, s) => a + s.size, 0),
    };
  }
}
