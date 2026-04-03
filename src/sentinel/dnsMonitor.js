import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:os';
import { stringEntropy } from '../utils/entropy.js';
import { RingBuffer } from '../utils/ringBuffer.js';
import { BehavioralBaseline } from '../utils/stats.js';

const exec = promisify(execFile);

const DNS_TUNNEL_INDICATORS = {
  entropyThreshold: 3.5,      // high entropy in subdomain = data encoding
  maxLabelLength: 50,          // normal labels rarely exceed 30 chars
  maxSubdomains: 6,            // deep nesting is suspicious
  queryRateThreshold: 30,      // queries per minute per domain
  txtQueryRatio: 0.3,          // high TXT query ratio = tunneling
  unusualRecordTypes: new Set(['TXT', 'NULL', 'CNAME', 'MX']),
};

export class DNSMonitor extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._pollInterval = opts.pollInterval || 5000;
    this._thresholds = { ...DNS_TUNNEL_INDICATORS, ...opts.thresholds };
    this._queries = new RingBuffer(8192);
    this._domainProfiles = new Map();
    this._alerts = [];
    this._timer = null;
    this._os = platform();
    this._whitelistedDomains = new Set(opts.whitelist || []);
  }

  ingest(query) {
    const { domain, type = 'A', pid = null, processName = null } = query;
    if (!domain) return null;

    const entry = {
      domain,
      type,
      pid,
      processName,
      ts: Date.now(),
      analysis: this._analyzeQuery(domain, type),
    };

    this._queries.push(entry);
    this._updateProfile(domain, entry);

    if (entry.analysis.suspicious) {
      const alert = {
        type: 'dns-tunnel-suspect',
        domain,
        queryType: type,
        pid,
        processName,
        reasons: entry.analysis.reasons,
        score: entry.analysis.score,
        ts: Date.now(),
      };
      this._alerts.push(alert);
      this.emit('tunnel-detected', alert);
      return alert;
    }

    return null;
  }

  _analyzeQuery(domain, type) {
    const reasons = [];
    let score = 0;

    // skip whitelisted
    const baseDomain = domain.split('.').slice(-2).join('.');
    if (this._whitelistedDomains.has(baseDomain)) {
      return { suspicious: false, reasons: [], score: 0 };
    }

    const labels = domain.split('.');

    // 1. entropy of longest subdomain
    if (labels.length > 2) {
      const subdomain = labels.slice(0, -2).join('.');
      const entropy = stringEntropy(subdomain);
      if (entropy > this._thresholds.entropyThreshold) {
        reasons.push(`high subdomain entropy: ${entropy.toFixed(2)}`);
        score += 0.3;
      }
    }

    // 2. label length
    for (const label of labels) {
      if (label.length > this._thresholds.maxLabelLength) {
        reasons.push(`long label: ${label.length} chars`);
        score += 0.2;
        break;
      }
    }

    // 3. subdomain depth
    if (labels.length > this._thresholds.maxSubdomains) {
      reasons.push(`deep nesting: ${labels.length} levels`);
      score += 0.15;
    }

    // 4. unusual record type
    if (this._thresholds.unusualRecordTypes.has(type)) {
      reasons.push(`unusual record type: ${type}`);
      score += 0.15;
    }

    // 5. hex/base32/base64 patterns in subdomain
    if (labels.length > 2) {
      const sub = labels.slice(0, -2).join('');
      if (/^[0-9a-f]+$/i.test(sub) && sub.length > 16) {
        reasons.push('hex-encoded subdomain');
        score += 0.25;
      }
      if (/^[A-Z2-7]+=*$/i.test(sub) && sub.length > 16) {
        reasons.push('base32-encoded subdomain');
        score += 0.25;
      }
    }

    // 6. numeric-heavy subdomain
    if (labels.length > 2) {
      const sub = labels.slice(0, -2).join('');
      const numRatio = (sub.match(/\d/g) || []).length / sub.length;
      if (numRatio > 0.5 && sub.length > 10) {
        reasons.push(`numeric-heavy subdomain: ${(numRatio * 100).toFixed(0)}%`);
        score += 0.15;
      }
    }

    return {
      suspicious: score >= 0.4,
      reasons,
      score: Math.min(1, score),
    };
  }

  _updateProfile(domain, entry) {
    const baseDomain = domain.split('.').slice(-2).join('.');
    if (!this._domainProfiles.has(baseDomain)) {
      this._domainProfiles.set(baseDomain, {
        domain: baseDomain,
        queryCount: 0,
        types: new Map(),
        subdomains: new Set(),
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        suspiciousCount: 0,
        pids: new Set(),
      });
    }
    const p = this._domainProfiles.get(baseDomain);
    p.queryCount++;
    p.lastSeen = Date.now();
    p.types.set(entry.type, (p.types.get(entry.type) || 0) + 1);
    if (domain !== baseDomain) {
      p.subdomains.add(domain.split('.').slice(0, -2).join('.'));
    }
    if (entry.analysis.suspicious) p.suspiciousCount++;
    if (entry.pid) p.pids.add(entry.pid);

    // check query rate
    const age = (Date.now() - p.firstSeen) / 60_000;
    const currentRate = p.queryCount / (age || 1);
    
    if (!p.baseline) p.baseline = new BehavioralBaseline();
    if (!p.baseline.isAnomalous(currentRate, 5)) {
      p.baseline.update(currentRate);
    }

    if (p.baseline.isAnomalous(currentRate, 4)) {
      this.emit('anomalous-query-rate', {
        domain: baseDomain,
        rate: currentRate,
        baseline: p.baseline.toJSON(),
      });
    } else if (age > 0.5 && currentRate > this._thresholds.queryRateThreshold) {
      this.emit('high-query-rate', {
        domain: baseDomain,
        rate: currentRate,
        queryCount: p.queryCount,
      });
    }

    // check TXT ratio
    const txtCount = p.types.get('TXT') || 0;
    if (p.queryCount > 10 && txtCount / p.queryCount > this._thresholds.txtQueryRatio) {
      this.emit('high-txt-ratio', {
        domain: baseDomain,
        ratio: txtCount / p.queryCount,
        txtCount,
        totalQueries: p.queryCount,
      });
    }
  }

  async pollSystemDNS() {
    try {
      if (this._os === 'win32') {
        const { stdout } = await exec('powershell', [
          '-Command', 'Get-DnsClientCache | Select-Object Entry,RecordType,Data | ConvertTo-Csv -NoTypeInformation'
        ], { timeout: 10000 });
        const lines = stdout.split('\n').slice(1);
        for (const line of lines) {
          const match = line.match(/"([^"]+)","([^"]+)"/);
          if (match) {
            this.ingest({ domain: match[1], type: match[2] });
          }
        }
      } else {
        // on linux, read from /etc/resolv.conf or systemd-resolve --statistics
        // passive monitoring would require pcap access
      }
    } catch { /* ignore poll failures */ }
  }

  start() {
    this.pollSystemDNS();
    this._timer = setInterval(() => this.pollSystemDNS(), this._pollInterval);
    this._timer.unref?.();
    return this;
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  getDomainProfile(domain) {
    const baseDomain = domain.split('.').slice(-2).join('.');
    const p = this._domainProfiles.get(baseDomain);
    if (!p) return null;
    return {
      ...p,
      subdomains: [...p.subdomains],
      types: Object.fromEntries(p.types),
      pids: [...p.pids],
    };
  }

  getSuspiciousDomains() {
    const results = [];
    for (const [domain, p] of this._domainProfiles) {
      if (p.suspiciousCount > 0) {
        results.push({
          domain,
          suspiciousCount: p.suspiciousCount,
          totalQueries: p.queryCount,
          ratio: p.suspiciousCount / p.queryCount,
        });
      }
    }
    return results.sort((a, b) => b.ratio - a.ratio);
  }

  whitelist(domain) {
    this._whitelistedDomains.add(domain);
    return this;
  }

  get stats() {
    return {
      module: 'DNSMonitor',
      totalQueries: this._queries.size,
      trackedDomains: this._domainProfiles.size,
      alerts: this._alerts.length,
      suspiciousDomains: this.getSuspiciousDomains().length,
    };
  }
}
