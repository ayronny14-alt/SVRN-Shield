import { EventEmitter } from 'node:events';

/**
 * KillChainTracker — MITRE ATT&CK kill chain correlation per IP.
 *
 * Maps Shield events to ATT&CK techniques in real time.
 * When an IP completes all four kill-chain stages it emits
 * 'campaign-detected' with the full chain and technique IDs.
 *
 * Stages: Reconnaissance → Discovery → C&C → Exfiltration
 */

export const TECHNIQUES = {
  'port-scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'port_scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'syn-scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'syn_scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'connect-scan':   { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'connect_scan':   { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'xmas-scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1595.001',sub: null,        name: 'Active Scanning: Wordlist Scan' },
  'xmas_scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1595.001',sub: null,        name: 'Active Scanning: Wordlist Scan' },
  'null-scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: null,        name: 'Network Service Scanning' },
  'null_scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: null,        name: 'Network Service Scanning' },
  'fin-scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: null,        name: 'Network Service Scanning' },
  'fin_scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: null,        name: 'Network Service Scanning' },
  'udp-scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'udp_scan':       { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'slow-scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1592',     name: 'Network Service Scanning' },
  'slow_scan':      { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1592',     name: 'Network Service Scanning' },
  'port-sweep':     { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'port_sweep':     { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
  'honeypot':       { stage: 'discovery', tactic: 'Discovery',            id: 'T1018',    sub: 'T1590',     name: 'Remote System Discovery' },
  'honeypot-hit':   { stage: 'discovery', tactic: 'Discovery',            id: 'T1018',    sub: 'T1590',     name: 'Remote System Discovery' },
  'exfil':          { stage: 'exfil',     tactic: 'Exfiltration',         id: 'T1048',    sub: 'T1041',     name: 'Exfiltration Over Alternative Protocol' },
  'dns-tunnel':     { stage: 'c2',        tactic: 'Command and Control',  id: 'T1071.004',sub: 'T1568',     name: 'Application Layer Protocol: DNS' },
  'c2':             { stage: 'c2',        tactic: 'Command and Control',  id: 'T1071',    sub: null,        name: 'Application Layer Protocol' },
  'rate-flood':     { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1498',    sub: null,        name: 'Network Denial of Service' },
  'scan-detected':  { stage: 'recon',     tactic: 'Reconnaissance',       id: 'T1046',    sub: 'T1595.001', name: 'Network Service Scanning' },
};

const STAGE_ORDER = ['recon', 'discovery', 'c2', 'exfil'];

export class KillChainTracker extends EventEmitter {
  #chains = new Map();   // ip → ChainState
  #opts;

  constructor(opts = {}) {
    super();
    this.#opts = {
      maxChains:    opts.maxChains    ?? 2000,
      ttlMs:        opts.ttlMs        ?? 3_600_000,   // 1h inactivity
      alertOnStages:opts.alertOnStages ?? 4,           // stages before campaign alert
    };

    // Periodic cleanup of stale chains
    this._cleanupInterval = setInterval(() => this._cleanup(), 300_000);
  }

  /**
   * Record an event for an IP.
   * @param {string} ip
   * @param {string} eventType  — must match a key in TECHNIQUES
   * @param {object} [detail]   — optional extra context
   * @returns {{ chain: ChainState, technique: object|null, newStage: boolean }}
   */
  record(ip, eventType, detail = {}) {
    const technique = TECHNIQUES[eventType] ?? null;
    if (!ip || typeof ip !== 'string') return { chain: null, technique, newStage: false };

    let chain = this.#chains.get(ip);
    if (!chain) {
      if (this.#chains.size >= this.#opts.maxChains) this._evictOldest();
      chain = {
        ip,
        stages:   new Map(),   // stage → first-seen timestamp
        events:   [],
        score:    0,
        firstSeen:Date.now(),
        lastSeen: Date.now(),
        alerted:  false,
      };
      this.#chains.set(ip, chain);
    }

    chain.lastSeen = Date.now();
    chain.events.push({ ts: Date.now(), type: eventType, technique, detail });
    if (chain.events.length > 200) chain.events.shift();

    let newStage = false;
    if (technique) {
      if (!chain.stages.has(technique.stage)) {
        chain.stages.set(technique.stage, Date.now());
        newStage = true;
      }
    }
    chain.score = Math.min(100, chain.score + this._scoreFor(eventType));

    this.emit('event-recorded', { ip, chain: this._serialise(chain), technique, newStage });

    // Campaign detection
    if (!chain.alerted && chain.stages.size >= this.#opts.alertOnStages) {
      chain.alerted = true;
      const campaign = this._buildCampaignReport(chain);
      this.emit('campaign-detected', campaign);
    }

    return { chain: this._serialise(chain), technique, newStage };
  }

  /**
   * Get the current chain state for an IP.
   * @returns {object|null}
   */
  getChain(ip) {
    const chain = this.#chains.get(ip);
    return chain ? this._serialise(chain) : null;
  }

  /**
   * All active chains, sorted by score descending.
   */
  get chains() {
    return [...this.#chains.values()]
      .map(c => this._serialise(c))
      .sort((a, b) => b.score - a.score);
  }

  get stats() {
    return {
      module:    'KillChainTracker',
      tracked:   this.#chains.size,
      campaigns: [...this.#chains.values()].filter(c => c.alerted).length,
      avgScore:  this._avgScore(),
    };
  }

  stop() {
    clearInterval(this._cleanupInterval);
  }

  // ── Internals ─────────────────────────────────────────────

  _scoreFor(type) {
    const weights = {
      'port-scan': 15, 'syn-scan': 15, 'xmas-scan': 20, 'null-scan': 15,
      'honeypot': 15, 'exfil': 30, 'dns-tunnel': 25, 'rate-flood': 10, 'c2': 20,
    };
    return weights[type] ?? 5;
  }

  _buildCampaignReport(chain) {
    const orderedStages = STAGE_ORDER
      .filter(s => chain.stages.has(s))
      .map(s => {
        const ev = chain.events.find(e => e.technique?.stage === s);
        return {
          stage:     s,
          tactic:    ev?.technique?.tactic ?? s,
          technique: ev?.technique?.id ?? '—',
          sub:       ev?.technique?.sub ?? null,
          name:      ev?.technique?.name ?? s,
          firstSeen: chain.stages.get(s),
          eventType: ev?.type ?? null,
        };
      });

    return {
      ip:          chain.ip,
      score:       chain.score,
      stages:      orderedStages,
      stageCount:  chain.stages.size,
      duration:    chain.lastSeen - chain.firstSeen,
      firstSeen:   chain.firstSeen,
      detectedAt:  Date.now(),
      severity:    chain.score >= 80 ? 'critical' : 'high',
    };
  }

  _serialise(chain) {
    return {
      ip:        chain.ip,
      score:     chain.score,
      stages:    Object.fromEntries(chain.stages),
      stageList: [...chain.stages.keys()],
      complete:  chain.stages.size >= 4,
      alerted:   chain.alerted,
      firstSeen: chain.firstSeen,
      lastSeen:  chain.lastSeen,
      eventCount:chain.events.length,
      techniques:[...new Set(chain.events.map(e => e.technique?.id).filter(Boolean))],
    };
  }

  _cleanup() {
    const cutoff = Date.now() - this.#opts.ttlMs;
    for (const [ip, chain] of this.#chains) {
      if (chain.lastSeen < cutoff) this.#chains.delete(ip);
    }
  }

  _evictOldest() {
    let oldest = null, oldestTs = Infinity;
    for (const [ip, chain] of this.#chains) {
      if (chain.lastSeen < oldestTs) { oldest = ip; oldestTs = chain.lastSeen; }
    }
    if (oldest) this.#chains.delete(oldest);
  }

  _avgScore() {
    if (!this.#chains.size) return 0;
    let total = 0;
    this.#chains.forEach(c => total += c.score);
    return Math.round(total / this.#chains.size);
  }
}
