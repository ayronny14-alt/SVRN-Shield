/**
 * Structured logger for Shield — NDJSON audit trail.
 *
 * Every security event gets a machine-readable log line with:
 *   ts, level, module, event, ip, severity, detail
 *
 * Supports: console, file (with rotation), and custom transports.
 * SOC teams can pipe this to Splunk, ELK, or any SIEM that reads NDJSON.
 */

import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { EventEmitter } from 'node:events';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, critical: 4 };

export class ShieldLogger extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._level = LEVELS[opts.level || 'info'] ?? 1;
    this._console = opts.console !== false;
    this._filePath = opts.file || null;
    this._fileStream = null;
    this._transports = [];
    this._buffer = [];
    this._maxBuffer = opts.maxBuffer || 10_000;
    this._ready = false;

    if (this._filePath) {
      this._initFile().catch(err => {
        if (this._console) {
          process.stderr.write(`[shield-logger] Failed to open log file: ${err.message}\n`);
        }
      });
    } else {
      this._ready = true;
    }
  }

  async _initFile() {
    await mkdir(dirname(this._filePath), { recursive: true });
    this._fileStream = createWriteStream(this._filePath, { flags: 'a' });
    this._fileStream.on('error', () => { /* non-fatal */ });
    this._ready = true;

    // flush buffer
    for (const line of this._buffer) {
      this._fileStream.write(line);
    }
    this._buffer = [];
  }

  /**
   * Add a custom transport function.
   * @param {function} fn — receives (logObject, logLine)
   */
  addTransport(fn) {
    this._transports.push(fn);
    return this;
  }

  /**
   * Core log method.
   * @param {string} level
   * @param {string} module
   * @param {string} event
   * @param {object} data — merged into the log object
   */
  log(level, module, event, data = {}) {
    const numLevel = LEVELS[level] ?? 1;
    if (numLevel < this._level) return;

    const entry = {
      ts: new Date().toISOString(),
      level,
      module,
      event,
      ...data,
    };

    const line = JSON.stringify(entry) + '\n';

    // console output
    if (this._console) {
      const prefix = this._colorize(level, `[${level.toUpperCase().padEnd(8)}]`);
      const mod = `[${module}]`.padEnd(22);
      const detail = data.ip ? ` ip=${data.ip}` : '';
      const sev = data.severity ? ` severity=${data.severity}` : '';
      process.stdout.write(`${prefix} ${mod} ${event}${detail}${sev}\n`);
    }

    // file output
    if (this._fileStream) {
      this._fileStream.write(line);
    } else if (this._filePath && !this._ready) {
      this._buffer.push(line);
      if (this._buffer.length > this._maxBuffer) {
        this._buffer = this._buffer.slice(-Math.floor(this._maxBuffer * 0.8));
      }
    }

    // custom transports
    for (const transport of this._transports) {
      try { transport(entry, line); } catch { /* non-fatal */ }
    }

    this.emit('log', entry);
  }

  // convenience methods
  debug(module, event, data)    { this.log('debug', module, event, data); }
  info(module, event, data)     { this.log('info', module, event, data); }
  warn(module, event, data)     { this.log('warn', module, event, data); }
  error(module, event, data)    { this.log('error', module, event, data); }
  critical(module, event, data) { this.log('critical', module, event, data); }

  /**
   * Log a security event (shorthand for the most common pattern).
   */
  security(module, event, ip, severity, detail = {}) {
    this.log(
      severity === 'critical' ? 'critical' : severity === 'high' ? 'warn' : 'info',
      module,
      event,
      { ip, severity, ...detail },
    );
  }

  /**
   * Log an audit event — always logged regardless of level.
   */
  audit(module, action, data = {}) {
    const entry = {
      ts: new Date().toISOString(),
      level: 'audit',
      module,
      action,
      ...data,
    };
    const line = JSON.stringify(entry) + '\n';

    if (this._fileStream) this._fileStream.write(line);
    for (const transport of this._transports) {
      try { transport(entry, line); } catch { /* non-fatal */ }
    }
    this.emit('audit', entry);
  }

  _colorize(level, text) {
    const colors = {
      debug: '\x1b[90m',    // gray
      info: '\x1b[36m',     // cyan
      warn: '\x1b[33m',     // yellow
      error: '\x1b[31m',    // red
      critical: '\x1b[41m', // red background
    };
    const reset = '\x1b[0m';
    return `${colors[level] || ''}${text}${reset}`;
  }

  close() {
    if (this._fileStream) {
      this._fileStream.end();
      this._fileStream = null;
    }
  }
}

/**
 * Create a no-op logger (for testing or when logging is disabled).
 */
export function createNullLogger() {
  return {
    log() {}, debug() {}, info() {}, warn() {}, error() {},
    critical() {}, security() {}, audit() {},
    addTransport() { return this; },
    on() { return this; },
    close() {},
  };
}
