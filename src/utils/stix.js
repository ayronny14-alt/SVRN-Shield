/**
 * STIX 2.1 Threat Intelligence export.
 *
 * Provides utilities for generating STIX 2.1 JSON bundles from Shield events.
 * Useful for sharing findings with other security researchers or teams.
 */
export class STIXGenerator {
  constructor(opts = {}) {
    this._nodeId = opts.nodeId || 'svrn-shield-node';
    this._defaultIdentityId = `identity--${this._uuid('identity')}`;
  }

  _uuid(type) {
    // deterministic-ish for fixed types
    const seed = `${type}:${this._nodeId}:${Math.random().toString(36).slice(2, 9)}`;
    return '01234567-89ab-4000-8000-' + Math.floor((Math.random() * 0xFFFFFFFFFFFF)).toString(16).padStart(12, '0');
  }

  generateBundle(payloads) {
    const objects = payloads.map(p => this.toIndicator(p));
    return {
      type: 'bundle',
      id: `bundle--${this._uuid('bundle')}`,
      objects: [
        this.getIdentity(),
        ...objects
      ]
    };
  }

  getIdentity() {
    return {
      type: 'identity',
      id: this._defaultIdentityId,
      name: 'Shield Security Agent',
      description: 'Host-based network defense agent',
      identity_class: 'system'
    };
  }

  toIndicator(e) {
    const id = `indicator--${this._uuid('indicator')}`;
    const now = new Date().toISOString();
    
    let pattern;
    if (e.ip) {
      pattern = `[ipv4-addr:value = '${e.ip}']`;
    } else if (e.domain) {
      pattern = `[domain-name:value = '${e.domain}']`;
    }

    return {
      type: 'indicator',
      id,
      created: now,
      modified: now,
      name: `Shield Detection: ${e.event || e.type || 'Unknown'}`,
      description: `Observed ${e.module || 'Shield'} alert: ${e.event || e.type}. Severity: ${e.severity || 'unknown'}`,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: now,
      created_by_ref: this._defaultIdentityId,
      external_references: [
        {
          source_name: 'MITRE ATT&CK',
          external_id: e.technique?.id || 'T1595',
          url: `https://attack.mitre.org/techniques/${e.technique?.id || 'T1595'}`
        }
      ]
    };
  }
}
