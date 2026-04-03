/**
 * Shield x Pulse Cross-Integration
 *
 * Bridges network-layer defense (Shield) with physics-layer identity (Pulse).
 * When a request arrives, Shield knows what the network looks like.
 * Pulse knows whether the client is a real device or a VM farm.
 * Together: full-stack attestation from silicon to socket.
 */

import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';

export class PulseShield extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._shield = opts.shield;
    this._pulseVerify = opts.pulseVerify;     // validateProof function from @svrnsec/pulse
    this._trustScore = opts.trustScore;        // computeTrustScore from @svrnsec/pulse
    this._coordination = opts.coordination;    // analyseCoordination from @svrnsec/pulse
    this._identities = new Map();
    this._cohort = [];
    this._maxCohort = opts.maxCohort || 5000;
    this._fusionWeights = {
      networkReputation: 0.25,
      physicsScore: 0.35,
      behavioralRate: 0.15,
      honeypotHistory: 0.15,
      coordinationSignal: 0.10,
      ...opts.weights,
    };
  }

  /**
   * Unified trust gate. Fuses Shield network intel with Pulse physics proof.
   * Returns a single verdict with full evidence chain.
   */
  async evaluate(request) {
    const { ip, pulsePayload, pulseHash, headers = {}, meta = {} } = request;

    // 1. Shield: network-layer intelligence
    const networkScore = this._shield ? this._getNetworkScore(ip) : 0.5;

    // 2. Pulse: physics-layer verification
    let physicsResult = null;
    let physicsScore = 0;
    let trustBreakdown = null;

    if (pulsePayload && this._pulseVerify) {
      try {
        physicsResult = await this._pulseVerify(pulsePayload, pulseHash);
        if (this._trustScore) {
          trustBreakdown = this._trustScore(pulsePayload, meta.extended);
          physicsScore = (trustBreakdown.score || 0) / 100;
        } else {
          physicsScore = physicsResult.valid ? physicsResult.score : 0;
        }
      } catch (err) {
        physicsResult = { valid: false, reasons: [err.message], riskFlags: [] };
      }
    }

    // 3. Rate limiter trust
    const rateProfile = this._shield?.rateLimiter?.getProfile(ip);
    const rateTrust = rateProfile ? rateProfile.trust : 0.5;

    // 4. Honeypot history — has this IP ever hit a decoy?
    const honeypotHit = this._shield?.honeypot?.stats?.byPort?.[ip] ? 0 : 1;

    // 5. Coordination signal (if we have cohort data)
    let coordinationScore = 1; // 1 = no coordination detected
    if (pulsePayload) {
      this._addToCohort(ip, pulsePayload);
      if (this._coordination && this._cohort.length >= 10) {
        try {
          const coordResult = this._coordination(this._cohort);
          coordinationScore = 1 - (coordResult.coordinationScore / 100);
        } catch { /* coordination analysis optional */ }
      }
    }

    // 6. Fuse all signals
    const w = this._fusionWeights;
    const fusedScore = (
      networkScore * w.networkReputation +
      physicsScore * w.physicsScore +
      rateTrust * w.behavioralRate +
      honeypotHit * w.honeypotHistory +
      coordinationScore * w.coordinationSignal
    );

    // 7. Hard overrides — physics can't be faked
    let hardOverride = null;
    if (physicsResult && !physicsResult.valid) {
      if (physicsResult.reasons?.some(r => r.includes('ejr') || r.includes('forgery'))) {
        hardOverride = { reason: 'physics-forgery', cap: 0.1 };
      }
    }
    if (networkScore === 0) {
      hardOverride = hardOverride || { reason: 'blocklisted-ip', cap: 0.05 };
    }

    const finalScore = hardOverride
      ? Math.min(fusedScore, hardOverride.cap)
      : fusedScore;

    // 8. Classify
    const verdict = finalScore >= 0.7 ? 'trusted'
      : finalScore >= 0.4 ? 'suspicious'
      : 'blocked';

    const identity = this._updateIdentity(ip, {
      fusedScore: finalScore,
      networkScore,
      physicsScore,
      rateTrust,
      honeypotHit: honeypotHit === 0,
      coordinationScore,
      verdict,
      hardOverride,
      physicsResult,
      trustBreakdown,
    });

    const result = {
      verdict,
      score: Math.round(finalScore * 1000) / 1000,
      identity: identity.id,
      evidence: {
        network: {
          score: networkScore,
          reputation: this._shield?.threatIntel?.classify(ip) || 'unknown',
          scanHistory: !!this._shield?.scanner?.getProfile(ip),
          honeypotHit: honeypotHit === 0,
        },
        physics: physicsResult ? {
          valid: physicsResult.valid,
          score: physicsScore,
          confidence: physicsResult.confidence,
          reasons: physicsResult.reasons,
          riskFlags: physicsResult.riskFlags,
          grade: trustBreakdown?.grade,
          breakdown: trustBreakdown?.breakdown,
          vmIndicators: pulsePayload?.classification?.vmIndicators,
        } : null,
        behavioral: {
          rateTrust,
          violations: rateProfile?.violations || 0,
          escalationLevel: rateProfile?.escalationLevel || 0,
        },
        coordination: {
          score: coordinationScore,
          cohortSize: this._cohort.length,
        },
      },
      hardOverride,
      ts: Date.now(),
    };

    this.emit('evaluation-complete', result);

    if (verdict === 'blocked') {
      this.emit('blocked', result);
      this._shield?.audit?.record({
        cat: 'pulse-shield',
        action: 'block',
        ip,
        fusedScore: finalScore,
        reason: hardOverride?.reason || 'low-trust',
      });
    }

    return result;
  }

  _getNetworkScore(ip) {
    if (!this._shield?.threatIntel) return 0.5;
    return this._shield.threatIntel.score(ip);
  }

  _addToCohort(ip, payload) {
    const entry = {
      ip,
      ts: Date.now(),
      signals: payload.signals || {},
      classification: payload.classification || {},
    };
    this._cohort.push(entry);
    if (this._cohort.length > this._maxCohort) {
      this._cohort = this._cohort.slice(-Math.floor(this._maxCohort * 0.8));
    }
  }

  _updateIdentity(ip, evaluation) {
    if (!this._identities.has(ip)) {
      const id = createHash('sha256').update(ip + Date.now().toString()).digest('hex').slice(0, 12);
      this._identities.set(ip, {
        id,
        ip,
        evaluations: [],
        firstSeen: Date.now(),
        lastSeen: Date.now(),
      });
    }
    const ident = this._identities.get(ip);
    ident.lastSeen = Date.now();
    ident.latest = evaluation;
    ident.evaluations.push({
      ts: Date.now(),
      score: evaluation.fusedScore,
      verdict: evaluation.verdict,
    });
    if (ident.evaluations.length > 100) {
      ident.evaluations = ident.evaluations.slice(-80);
    }
    return ident;
  }

  /**
   * Detect VM-behind-proxy: Pulse says VM, Shield sees residential IP.
   * Most bot farms route through residential proxies to look clean.
   * Physics can't be proxied.
   */
  detectProxiedVM(ip, pulsePayload) {
    if (!pulsePayload?.classification?.vmIndicators) return null;
    const vmIndicators = pulsePayload.classification.vmIndicators;
    if (vmIndicators.length === 0) return null;

    const networkClassification = this._shield?.threatIntel?.classify(ip);
    const rdns = null; // would come from async geoip

    // VM indicators present but IP looks clean = proxy
    if (networkClassification === 'trusted' || networkClassification === 'neutral') {
      return {
        detected: true,
        type: 'proxied-vm',
        severity: 'critical',
        ip,
        vmIndicators,
        networkReputation: networkClassification,
        reason: 'Physics layer detects VM but network appears residential — traffic is being proxied',
      };
    }

    return { detected: false };
  }

  /**
   * Cross-reference: honeypot connection timing vs Pulse engagement tokens.
   * If a client submits a valid Pulse proof but was also seen on honeypot ports,
   * the Pulse proof is likely automated (headless browser with physics spoofing).
   */
  crossReferenceHoneypot(ip, pulseValid) {
    const honeypotConnections = this._shield?.honeypot?.getConnectionInfo(ip) || [];
    if (honeypotConnections.length === 0) return null;

    if (pulseValid) {
      return {
        anomaly: true,
        type: 'valid-proof-honeypot-hit',
        severity: 'critical',
        ip,
        honeypotHits: honeypotConnections.length,
        reason: 'Client passed physics verification but also probed honeypot ports — sophisticated automated attack',
      };
    }

    return {
      anomaly: false,
      type: 'invalid-proof-honeypot-hit',
      severity: 'high',
      ip,
      honeypotHits: honeypotConnections.length,
    };
  }

  /**
   * Cross-reference: malicious payload hits vs Pulse attestation.
   * Detecting an exploit payload from a 'verified' device is a critical signal
   * of an advanced persistent threat (APT) or a zero-day bypass.
   */
  crossReferencePayload(ip, pulsePayload) {
    const alerts = this._shield?.honeypot?.getPayloadAlerts?.(ip) || [];
    if (alerts.length === 0) return null;

    return {
      anomaly: true,
      type: 'verified-device-exploit',
      severity: 'critical',
      ip,
      payloadAlerts: alerts.length,
      rules: alerts.map(a => a.rule),
      reason: 'Verified device attempting to send malicious exploit payloads — potential APT bypass detected',
    };
  }

  /**
   * Population-level analysis: feed all recent Pulse proofs to coordination detector.
   * Returns whether the current traffic cohort shows signs of a bot farm.
   */
  async analyzePopulation() {
    if (!this._coordination || this._cohort.length < 10) {
      return { available: false, reason: 'insufficient cohort data' };
    }

    try {
      const result = this._coordination(this._cohort);
      this.emit('population-analysis', result);

      if (result.verdict === 'coordinated_inauthentic' || result.verdict === 'suspicious_coordination') {
        this._shield?.audit?.record({
          cat: 'pulse-shield',
          action: 'coordination-detected',
          verdict: result.verdict,
          score: result.coordinationScore,
          flags: result.flags,
          cohortSize: this._cohort.length,
        });
      }

      return result;
    } catch (err) {
      return { available: false, error: err.message };
    }
  }

  /**
   * Express middleware factory.
   * Drops in as: app.use(pulseShield.middleware())
   */
  middleware(opts = {}) {
    const threshold = opts.threshold || 0.4;
    const proofHeader = opts.proofHeader || 'x-pulse-proof';
    const hashHeader = opts.hashHeader || 'x-pulse-hash';

    return async (req, res, next) => {
      const ip = req.ip || req.connection?.remoteAddress;
      let pulsePayload = null;
      if (req.headers[proofHeader]) {
        try {
          const raw = JSON.parse(Buffer.from(req.headers[proofHeader], 'base64').toString());
          // Guard against prototype pollution from untrusted header data
          if (raw && typeof raw === 'object' && !Array.isArray(raw) &&
              !Object.prototype.hasOwnProperty.call(raw, '__proto__') &&
              !Object.prototype.hasOwnProperty.call(raw, 'constructor') &&
              !Object.prototype.hasOwnProperty.call(raw, 'prototype')) {
            pulsePayload = Object.assign(Object.create(null), raw);
          }
        } catch { /* malformed base64/JSON — treat as no payload */ }
      }
      const pulseHash = req.headers[hashHeader] || null;

      const result = await this.evaluate({
        ip,
        pulsePayload,
        pulseHash,
        headers: req.headers,
      });

      req.shieldResult = result;

      if (result.score < threshold) {
        res.status(403).json({
          error: 'Request blocked by Shield',
          verdict: result.verdict,
          score: result.score,
        });
        return;
      }

      next();
    };
  }

  getIdentity(ip) {
    return this._identities.get(ip) || null;
  }

  get stats() {
    return {
      module: 'PulseShield',
      identities: this._identities.size,
      cohortSize: this._cohort.length,
      weights: this._fusionWeights,
    };
  }
}
