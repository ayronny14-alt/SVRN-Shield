/**
 * Configuration validation utilities for Shield modules.
 *
 * Every module constructor should call validateConfig() to catch
 * invalid options early instead of silently producing NaN comparisons
 * or undefined-is-not-a-function errors deep in runtime.
 */

export class ConfigError extends Error {
  constructor(module, field, expected, got) {
    const msg = `[${module}] Invalid config: "${field}" expected ${expected}, got ${typeof got} (${JSON.stringify(got)})`;
    super(msg);
    this.name = 'ShieldConfigError';
    this.module = module;
    this.field = field;
  }
}

const VALIDATORS = {
  number:   (v) => typeof v === 'number' && !Number.isNaN(v),
  posInt:   (v) => Number.isInteger(v) && v > 0,
  nonNegInt:(v) => Number.isInteger(v) && v >= 0,
  string:   (v) => typeof v === 'string' && v.length > 0,
  bool:     (v) => typeof v === 'boolean',
  array:    (v) => Array.isArray(v),
  object:   (v) => v !== null && typeof v === 'object' && !Array.isArray(v),
  port:     (v) => Number.isInteger(v) && v > 0 && v < 65536,
  severity: (v) => ['low', 'medium', 'high', 'critical'].includes(v),
  func:     (v) => typeof v === 'function',
};

/**
 * Validate a configuration object against a schema.
 *
 * @param {string} moduleName  — for error messages
 * @param {object} opts        — the user-provided config
 * @param {object} schema      — { fieldName: { type, default?, required?, validate? } }
 * @returns {object} — validated config with defaults applied
 */
export function validateConfig(moduleName, opts, schema) {
  if (opts !== undefined && opts !== null && typeof opts !== 'object') {
    throw new ConfigError(moduleName, 'opts', 'object or undefined', opts);
  }

  const config = {};
  const src = opts || {};

  for (const [key, spec] of Object.entries(schema)) {
    const value = src[key];

    // required check
    if (value === undefined || value === null) {
      if (spec.required) {
        throw new ConfigError(moduleName, key, spec.type + ' (required)', value);
      }
      config[key] = spec.default;
      continue;
    }

    // type check
    if (spec.type && VALIDATORS[spec.type]) {
      if (!VALIDATORS[spec.type](value)) {
        throw new ConfigError(moduleName, key, spec.type, value);
      }
    }

    // custom validator
    if (spec.validate && !spec.validate(value)) {
      throw new ConfigError(moduleName, key, spec.expected || spec.type, value);
    }

    config[key] = value;
  }

  // pass through unknown keys (backwards compatible)
  for (const [key, value] of Object.entries(src)) {
    if (!(key in schema)) {
      config[key] = value;
    }
  }

  return config;
}

/**
 * Schema definitions for each Shield module.
 */
export const SCHEMAS = {
  portScanDetector: {
    window:           { type: 'posInt',   default: 10_000 },
    portsPerWindow:   { type: 'posInt',   default: 15 },
    connectsPerSecond:{ type: 'posInt',   default: 20 },
    synWithoutAck:    { type: 'posInt',   default: 10 },
    slowScanPorts:    { type: 'posInt',   default: 25 },
    slowScanWindow:   { type: 'posInt',   default: 300_000 },
  },

  rateLimiter: {
    defaultRate:      { type: 'posInt',   default: 60 },
    window:           { type: 'posInt',   default: 60_000 },
    burstMultiplier:  { type: 'number',   default: 3 },
    trustDecay:       { type: 'number',   default: 0.995 },
    trustGrowth:      { type: 'number',   default: 0.001 },
    banDuration:      { type: 'posInt',   default: 300_000 },
  },

  threatIntel: {
    decayRate:        { type: 'number',   default: 0.999 },
    boostRate:        { type: 'number',   default: 0.01 },
    penaltyRate:      { type: 'number',   default: 0.1 },
    minScore:         { type: 'number',   default: 0 },
    maxScore:         { type: 'number',   default: 1 },
    defaultScore:     { type: 'number',   default: 0.5 },
    blockThreshold:   { type: 'number',   default: 0.15 },
    warnThreshold:    { type: 'number',   default: 0.3 },
  },

  alertPipeline: {
    minSeverity:      { type: 'severity', default: 'medium' },
    cooldownMs:       { type: 'nonNegInt',default: 10_000 },
    maxHistory:       { type: 'posInt',   default: 5000 },
    autoBlock:        { type: 'bool',     default: true },
  },

  dnsMonitor: {
    pollInterval:     { type: 'posInt',   default: 5000 },
    entropyThreshold: { type: 'number',   default: 3.5 },
  },

  exfilDetector: {
    uploadBytesPerMin:{ type: 'posInt',   default: 10 * 1024 * 1024 },
    newDestBurst:     { type: 'posInt',   default: 5 },
    connRate:         { type: 'posInt',   default: 30 },
    maxAlerts:        { type: 'posInt',   default: 5000 },
  },

  honeypotMesh: {
    maxConnectionTime:{ type: 'posInt',   default: 30_000 },
  },

  killChainTracker: {
    maxChains:        { type: 'posInt',   default: 2000 },
    ttlMs:            { type: 'posInt',   default: 3_600_000 },
    alertOnStages:    { type: 'posInt',   default: 4 },
  },

  threatMesh: {
    port:             { type: 'nonNegInt',default: 0 },
    maxPeers:         { type: 'posInt',   default: 50 },
    syncHistory:      { type: 'posInt',   default: 500 },
  },

  connectionTable: {
    pollInterval:     { type: 'posInt',   default: 3000 },
    maxHistory:       { type: 'posInt',   default: 10000 },
  },
};
