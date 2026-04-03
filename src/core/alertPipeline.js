import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:os';
import crypto from 'node:crypto';

const exec = promisify(execFile);

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

// Strict allowlist: IPv4, IPv6, CIDR — nothing else reaches a shell
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:3[0-2]|[12]?\d))?$/;
const IPV6_RE = /^[0-9a-fA-F:]+(?:\/(?:12[0-8]|1[01]\d|\d{1,2}))?$/;

function validateIP(ip) {
  if (typeof ip !== 'string') return false;
  const clean = ip.trim();
  return IPV4_RE.test(clean) || IPV6_RE.test(clean);
}

// Safe rule name: hash of IP so no user data reaches the shell argument
function ruleId(ip) {
  return 'shield-' + crypto.createHash('sha256').update(ip).digest('hex').slice(0, 12);
}

export class AlertPipeline extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._handlers = [];
    this._minSeverity = opts.minSeverity || 'medium';
    this._cooldowns = new Map();
    this._cooldownMs = opts.cooldownMs || 10_000;
    this._history = [];
    this._maxHistory = opts.maxHistory || 5000;
    this._autoBlock = opts.autoBlock !== false;
    this._os = platform();
  }

  onAlert(handler) {
    this._handlers.push(handler);
    return this;
  }

  onWebhook(url, opts = {}) {
    this._handlers.push(async (alert) => {
      try {
        const body = JSON.stringify(alert);
        await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...opts.headers },
          body,
          signal: AbortSignal.timeout(opts.timeout || 5000),
        });
      } catch (err) {
        this.emit('webhook-error', { url, error: err.message });
      }
    });
    return this;
  }

  async fire(alert) {
    const sev = SEVERITY_ORDER[alert.severity] ?? 1;
    if (sev < (SEVERITY_ORDER[this._minSeverity] ?? 0)) return false;

    // cooldown check
    const key = `${alert.type}:${alert.ip || 'global'}`;
    const now = Date.now();
    if (this._cooldowns.has(key) && now - this._cooldowns.get(key) < this._cooldownMs) {
      return false;
    }
    this._cooldowns.set(key, now);

    const entry = { id: this._history.length, ts: now, ...alert };
    this._history.push(entry);
    if (this._history.length > this._maxHistory) {
      this._history = this._history.slice(-Math.floor(this._maxHistory * 0.8));
    }

    this.emit('alert', entry);

    // fire all handlers
    const results = await Promise.allSettled(
      this._handlers.map(h => h(entry))
    );

    // auto-block on critical
    if (this._autoBlock && alert.severity === 'critical' && alert.ip) {
      await this.blockIP(alert.ip, alert.duration || 3600);
    }

    return true;
  }

  async blockIP(ip, durationSec = 3600) {
    if (!validateIP(ip)) {
      this.emit('block-error', { ip, error: 'Invalid IP address — blocked before shell execution' });
      return false;
    }
    const rule = ruleId(ip);
    try {
      if (this._os === 'win32') {
        await exec('netsh', [
          'advfirewall', 'firewall', 'add', 'rule',
          `name=${rule}`,
          'dir=in', 'action=block',
          `remoteip=${ip}`,
          'enable=yes',
        ]);
        if (durationSec > 0) {
          setTimeout(async () => {
            try {
              await exec('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${rule}`]);
              this.emit('unblock', { ip, auto: true });
            } catch { /* ignore */ }
          }, durationSec * 1000).unref?.();
        }
      } else {
        await exec('iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
        if (durationSec > 0) {
          setTimeout(async () => {
            try {
              await exec('iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
              this.emit('unblock', { ip, auto: true });
            } catch { /* ignore */ }
          }, durationSec * 1000).unref?.();
        }
      }
      this.emit('block', { ip, duration: durationSec });
      return true;
    } catch (err) {
      this.emit('block-error', { ip, error: err.message });
      return false;
    }
  }

  async unblockIP(ip) {
    if (!validateIP(ip)) {
      this.emit('unblock-error', { ip, error: 'Invalid IP address' });
      return false;
    }
    const rule = ruleId(ip);
    try {
      if (this._os === 'win32') {
        await exec('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${rule}`]);
      } else {
        await exec('iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
      }
      this.emit('unblock', { ip, manual: true });
      return true;
    } catch (err) {
      this.emit('unblock-error', { ip, error: err.message });
      return false;
    }
  }

  query(filter = {}) {
    let results = this._history;
    if (filter.severity) {
      const min = SEVERITY_ORDER[filter.severity] ?? 0;
      results = results.filter(a => (SEVERITY_ORDER[a.severity] ?? 0) >= min);
    }
    if (filter.type) results = results.filter(a => a.type === filter.type);
    if (filter.ip) results = results.filter(a => a.ip === filter.ip);
    if (filter.since) results = results.filter(a => a.ts >= filter.since);
    if (filter.limit) results = results.slice(-filter.limit);
    return results;
  }

  get stats() {
    const bySeverity = {};
    for (const a of this._history) {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
    }
    return { module: 'AlertPipeline', total: this._history.length, bySeverity, handlers: this._handlers.length };
  }
}
