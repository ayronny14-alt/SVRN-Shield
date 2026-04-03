/**
 * PayloadAnalyst — YARA-lite pattern matching for malicious payloads.
 *
 * Scans honeypot captures and packet payloads for:
 *  - Reverse shell commands
 *  - Known exploit strings (Log4j, etc.)
 *  - Web shell markers
 *  - Obfuscated PowerShell/Bash
 */
export class PayloadAnalyst {
  constructor(opts = {}) {
    this._rules = [
      { name: 'Reverse Shell',        regex: /bash\s+-i\s+>(?:&|&amp;)\s+\/dev\/tcp\//i, severity: 'critical' },
      { name: 'Log4Shell Attempt',    regex: /\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|lds|http):/i, severity: 'critical' },
      { name: 'PHP WebShell',         regex: /<\?php\s+(?:system|shell_exec|passthru|exec|eval|base64_decode|gzinflate)\s*\(/i, severity: 'high' },
      { name: 'PowerShell Encoded',   regex: /powershell(?:\.exe)?\s+(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i, severity: 'high' },
      { name: 'RCE Download',         regex: /(?:curl|wget)\s+http.*?\s*\|\s*(?:bash|sh|php|python)/i, severity: 'critical' },
      { name: 'CryptoMiner Signature',regex: /(?:stratum\+tcp|pool\.mine|nicehash|xmrig|nanopool)/i, severity: 'high' },
      { name: 'SQL Injection',        regex: /(?:UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|INFORMATION_SCHEMA)/i, severity: 'low' },
      ...(opts.customRules || [])
    ];
  }

  /**
   * Scan data for known malicious patterns.
   * @param {string|Buffer} data
   * @returns {Array<{rule: string, severity: string, match: string}>}
   */
  analyze(data) {
    if (!data) return [];
    
    // Safely convert to string, capped at 10kb to avoid ReDoS on huge blobs
    const content = Buffer.isBuffer(data) 
      ? data.toString('utf8', 0, 10240) 
      : data.slice(0, 10240);
      
    const matches = [];

    for (const rule of this._rules) {
      if (rule.regex.test(content)) {
        const matchText = content.match(rule.regex)[0];
        matches.push({
          rule: rule.name,
          severity: rule.severity,
          match: matchText.length > 100 ? matchText.slice(0, 97) + '...' : matchText
        });
      }
    }

    return matches;
  }
}
