import { EventEmitter } from 'node:events';
import { RingBuffer } from '../utils/ringBuffer.js';

export class BehavioralRateLimiter extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._defaultRate = opts.defaultRate || 60;       // requests per window
    this._windowMs = opts.window || 60_000;            // 1 minute
    this._burstMultiplier = opts.burstMultiplier || 3;
    this._trustDecay = opts.trustDecay || 0.995;       // per-check decay
    this._trustGrowth = opts.trustGrowth || 0.001;
    this._banDuration = opts.banDuration || 300_000;   // 5 min default
    this._escalationSteps = opts.escalation || [
      { action: 'throttle', multiplier: 0.5 },
      { action: 'throttle', multiplier: 0.25 },
      { action: 'block',    duration: 60_000 },
      { action: 'block',    duration: 300_000 },
      { action: 'ban',      duration: 3600_000 },
    ];
    this._identities = new Map();
    this._gcInterval = null;
  }

  start() {
    this._gcInterval = setInterval(() => this._gc(), 30_000);
    this._gcInterval.unref?.();
    return this;
  }

  stop() {
    if (this._gcInterval) clearInterval(this._gcInterval);
  }

  _getIdentity(id) {
    if (!this._identities.has(id)) {
      this._identities.set(id, {
        id,
        trust: 0.5,
        requests: new RingBuffer(2048),
        violations: 0,
        escalationLevel: 0,
        blockedUntil: 0,
        baseline: null,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalRequests: 0,
      });
    }
    const ident = this._identities.get(id);
    ident.lastSeen = Date.now();
    return ident;
  }

  check(id, meta = {}) {
    const ident = this._getIdentity(id);
    const now = Date.now();
    ident.totalRequests++;

    // blocked?
    if (ident.blockedUntil > now) {
      return { allowed: false, reason: 'blocked', retryAfter: ident.blockedUntil - now, trust: ident.trust };
    }

    ident.requests.push({ ts: now, ...meta });

    // compute current rate
    const windowStart = now - this._windowMs;
    let count = 0;
    for (const r of ident.requests) {
      if (r.ts >= windowStart) count++;
    }

    // adaptive limit based on trust
    const effectiveLimit = this._effectiveLimit(ident);

    // update baseline
    this._updateBaseline(ident, count);

    if (count <= effectiveLimit) {
      // good behavior — grow trust
      ident.trust = Math.min(1, ident.trust + this._trustGrowth);
      return { allowed: true, remaining: effectiveLimit - count, trust: ident.trust, limit: effectiveLimit };
    }

    // violation
    ident.violations++;
    ident.trust = Math.max(0, ident.trust * this._trustDecay * 0.9);
    const step = this._escalate(ident);

    const result = {
      allowed: false,
      reason: step.action,
      trust: ident.trust,
      violations: ident.violations,
      escalationLevel: ident.escalationLevel,
    };

    if (step.action === 'throttle') {
      result.retryAfter = Math.ceil(this._windowMs / (effectiveLimit * step.multiplier));
      result.allowed = count <= effectiveLimit * (1 + this._burstMultiplier);
    } else {
      const duration = step.duration || this._banDuration;
      ident.blockedUntil = now + duration;
      result.retryAfter = duration;
    }

    this.emit('limit-exceeded', { id, ...result });
    return result;
  }

  _effectiveLimit(ident) {
    const trustBonus = ident.trust * this._defaultRate * 0.5;
    const base = this._defaultRate + trustBonus;

    // if we have a behavioral baseline, use it
    if (ident.baseline) {
      const baselineLimit = ident.baseline.mean + ident.baseline.stddev * 2;
      return Math.max(base, baselineLimit);
    }
    return base;
  }

  _updateBaseline(ident, currentRate) {
    if (!ident.baseline) {
      ident.baseline = { samples: 0, mean: currentRate, m2: 0, stddev: 0 };
    }
    const b = ident.baseline;
    b.samples++;
    const delta = currentRate - b.mean;
    b.mean += delta / b.samples;
    const delta2 = currentRate - b.mean;
    b.m2 += delta * delta2;
    b.stddev = b.samples > 1 ? Math.sqrt(b.m2 / (b.samples - 1)) : 0;
  }

  _escalate(ident) {
    const level = Math.min(ident.escalationLevel, this._escalationSteps.length - 1);
    const step = this._escalationSteps[level];
    ident.escalationLevel = Math.min(ident.escalationLevel + 1, this._escalationSteps.length - 1);
    this.emit('escalation', { id: ident.id, level: ident.escalationLevel, action: step.action });
    return step;
  }

  resetTrust(id) {
    const ident = this._identities.get(id);
    if (ident) {
      ident.trust = 0.5;
      ident.violations = 0;
      ident.escalationLevel = 0;
      ident.blockedUntil = 0;
    }
  }

  ban(id, duration) {
    const ident = this._getIdentity(id);
    ident.blockedUntil = Date.now() + (duration || this._banDuration);
    ident.trust = 0;
    this.emit('ban', { id, until: ident.blockedUntil });
  }

  unban(id) {
    const ident = this._identities.get(id);
    if (ident) ident.blockedUntil = 0;
  }

  getProfile(id) {
    const ident = this._identities.get(id);
    if (!ident) return null;
    return {
      id: ident.id,
      trust: ident.trust,
      violations: ident.violations,
      escalationLevel: ident.escalationLevel,
      blocked: ident.blockedUntil > Date.now(),
      blockedUntil: ident.blockedUntil,
      baseline: ident.baseline,
      totalRequests: ident.totalRequests,
      age: Date.now() - ident.firstSeen,
    };
  }

  _gc() {
    const now = Date.now();
    for (const [id, ident] of this._identities) {
      if (now - ident.lastSeen > this._windowMs * 10) {
        this._identities.delete(id);
      }
    }
  }

  get stats() {
    let blocked = 0;
    const now = Date.now();
    for (const ident of this._identities.values()) {
      if (ident.blockedUntil > now) blocked++;
    }
    return { module: 'BehavioralRateLimiter', tracked: this._identities.size, blocked };
  }
}
