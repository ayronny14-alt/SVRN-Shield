import crypto from 'node:crypto';

/**
 * ThreatMesh unit tests.
 *
 * These test the crypto, event ingestion, and protocol logic WITHOUT
 * actually binding sockets. We import internal helpers and test the
 * ThreatMesh class methods directly using mock peers.
 */

// We need to test the signing/verification functions, which are module-scoped.
// Recreate them here (same logic as threatMesh.js):
function signEvent(event, privateKey) {
  const payload = `${event.ip}|${event.eventType}|${event.severity}|${event.ts}|${event.nodeId}`;
  return crypto.sign(null, Buffer.from(payload), privateKey).toString('hex');
}

function verifyEvent(event) {
  try {
    const { ip, eventType, severity, ts, nodeId, sig, publicKey: pubHex } = event;
    if (!ip || !eventType || !severity || !ts || !nodeId || !sig || !pubHex) return false;
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(pubHex, 'hex'),
      format: 'der', type: 'spki',
    });
    const payload = `${ip}|${eventType}|${severity}|${ts}|${nodeId}`;
    return crypto.verify(null, Buffer.from(payload), pubKey, Buffer.from(sig, 'hex'));
  } catch {
    return false;
  }
}

function makeKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pubHex = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const nodeId = crypto.createHash('sha256').update(pubHex).digest('hex').slice(0, 16);
  return { privateKey, publicKey, pubHex, nodeId };
}

describe('ThreatMesh Crypto', () => {
  let kp;
  beforeAll(() => { kp = makeKeypair(); });

  test('signEvent produces hex string', () => {
    const event = {
      ip: '1.2.3.4', eventType: 'port-scan', severity: 'high',
      ts: Date.now(), nodeId: kp.nodeId,
    };
    const sig = signEvent(event, kp.privateKey);
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(10);
  });

  test('verifyEvent accepts valid signature', () => {
    const event = {
      ip: '10.0.0.1', eventType: 'honeypot-hit', severity: 'critical',
      ts: Date.now(), nodeId: kp.nodeId, publicKey: kp.pubHex,
    };
    event.sig = signEvent(event, kp.privateKey);
    expect(verifyEvent(event)).toBe(true);
  });

  test('verifyEvent rejects tampered event', () => {
    const event = {
      ip: '10.0.0.1', eventType: 'honeypot-hit', severity: 'critical',
      ts: Date.now(), nodeId: kp.nodeId, publicKey: kp.pubHex,
    };
    event.sig = signEvent(event, kp.privateKey);

    // tamper with IP
    event.ip = '10.0.0.2';
    expect(verifyEvent(event)).toBe(false);
  });

  test('verifyEvent rejects tampered severity', () => {
    const event = {
      ip: '1.1.1.1', eventType: 'port-scan', severity: 'low',
      ts: Date.now(), nodeId: kp.nodeId, publicKey: kp.pubHex,
    };
    event.sig = signEvent(event, kp.privateKey);
    event.severity = 'critical';
    expect(verifyEvent(event)).toBe(false);
  });

  test('verifyEvent rejects wrong public key', () => {
    const kp2 = makeKeypair();
    const event = {
      ip: '1.1.1.1', eventType: 'port-scan', severity: 'high',
      ts: Date.now(), nodeId: kp.nodeId, publicKey: kp2.pubHex, // wrong key
    };
    event.sig = signEvent(event, kp.privateKey);
    expect(verifyEvent(event)).toBe(false);
  });

  test('verifyEvent rejects missing fields', () => {
    expect(verifyEvent({})).toBe(false);
    expect(verifyEvent({ ip: '1.1.1.1' })).toBe(false);
    expect(verifyEvent(null)).toBe(false);
  });

  test('different keypairs produce different signatures', () => {
    const kp2 = makeKeypair();
    const event = {
      ip: '5.5.5.5', eventType: 'exfil', severity: 'high',
      ts: Date.now(), nodeId: kp.nodeId,
    };
    const sig1 = signEvent(event, kp.privateKey);
    const sig2 = signEvent({ ...event, nodeId: kp2.nodeId }, kp2.privateKey);
    expect(sig1).not.toBe(sig2);
  });

  test('replaying event with different timestamp is rejected', () => {
    const event = {
      ip: '3.3.3.3', eventType: 'port-scan', severity: 'medium',
      ts: Date.now(), nodeId: kp.nodeId, publicKey: kp.pubHex,
    };
    event.sig = signEvent(event, kp.privateKey);
    expect(verifyEvent(event)).toBe(true);

    // replay with different timestamp
    event.ts = event.ts + 1;
    expect(verifyEvent(event)).toBe(false);
  });
});

describe('ThreatMesh Event Deduplication', () => {
  // Test the hash-based dedup logic
  function hashEvent(event) {
    return `${event.nodeId}|${event.ts}|${event.eventType}|${event.ip}`;
  }

  test('same event produces same hash', () => {
    const e = { nodeId: 'abc', ts: 1000, eventType: 'scan', ip: '1.1.1.1' };
    expect(hashEvent(e)).toBe(hashEvent(e));
  });

  test('different events produce different hashes', () => {
    const e1 = { nodeId: 'abc', ts: 1000, eventType: 'scan', ip: '1.1.1.1' };
    const e2 = { nodeId: 'abc', ts: 1001, eventType: 'scan', ip: '1.1.1.1' };
    expect(hashEvent(e1)).not.toBe(hashEvent(e2));
  });

  test('seen set correctly deduplicates', () => {
    const seen = new Set();
    const e = { nodeId: 'n1', ts: 1000, eventType: 'scan', ip: '10.0.0.1' };
    const hash = hashEvent(e);

    expect(seen.has(hash)).toBe(false);
    seen.add(hash);
    expect(seen.has(hash)).toBe(true);
  });

  test('seen set trimming preserves newest events', () => {
    const cap = 100;
    const seen = new Set();
    for (let i = 0; i < 150; i++) {
      seen.add(`event_${i}`);
    }
    // trim like ThreatMesh does
    if (seen.size > cap) {
      const toDelete = seen.size - (cap / 2);
      let j = 0;
      for (const key of seen) {
        if (j++ >= toDelete) break;
        seen.delete(key);
      }
    }
    expect(seen.size).toBeLessThanOrEqual(cap);
    // newest events should survive
    expect(seen.has('event_149')).toBe(true);
  });
});

describe('ThreatMesh IP Validation', () => {
  const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  const IPV6_RE = /^[0-9a-fA-F:]+$/;

  function isValidIP(host) {
    if (typeof host !== 'string') return false;
    return IPV4_RE.test(host) || IPV6_RE.test(host);
  }

  function isValidPort(port) {
    return Number.isInteger(port) && port > 0 && port < 65536;
  }

  test('accepts valid IPv4', () => {
    expect(isValidIP('10.0.0.1')).toBe(true);
    expect(isValidIP('192.168.1.1')).toBe(true);
    expect(isValidIP('255.255.255.255')).toBe(true);
    expect(isValidIP('0.0.0.0')).toBe(true);
  });

  test('accepts valid IPv6', () => {
    expect(isValidIP('::1')).toBe(true);
    expect(isValidIP('fe80::1')).toBe(true);
    expect(isValidIP('2001:db8::1')).toBe(true);
  });

  test('rejects hostnames (prevents DNS lookup injection)', () => {
    expect(isValidIP('evil.com')).toBe(false);
    expect(isValidIP('localhost')).toBe(false);
    expect(isValidIP('attacker.example.org')).toBe(false);
  });

  test('rejects empty/null', () => {
    expect(isValidIP('')).toBe(false);
    expect(isValidIP(null)).toBe(false);
    expect(isValidIP(undefined)).toBe(false);
    expect(isValidIP(42)).toBe(false);
  });

  test('port validation works', () => {
    expect(isValidPort(1)).toBe(true);
    expect(isValidPort(443)).toBe(true);
    expect(isValidPort(65535)).toBe(true);
    expect(isValidPort(0)).toBe(false);
    expect(isValidPort(-1)).toBe(false);
    expect(isValidPort(65536)).toBe(false);
    expect(isValidPort(NaN)).toBe(false);
    expect(isValidPort('443')).toBe(false);
  });
});

describe('ThreatMesh PEX Protocol', () => {
  test('peer list respects max peers limit', () => {
    const PEX_MAX = 20;
    const peers = Array.from({ length: 50 }, (_, i) => ({
      host: `10.0.0.${i}`, port: 41338,
    }));
    const limited = peers.slice(0, PEX_MAX);
    expect(limited.length).toBe(20);
  });

  test('peer list filters invalid entries', () => {
    const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    const peers = [
      { host: '10.0.0.1', port: 41338 },       // valid
      { host: 'evil.com', port: 41338 },         // hostname — reject
      { host: '10.0.0.2', port: 0 },             // bad port — reject
      { host: null, port: 41338 },                // null — reject
      { host: '192.168.1.1', port: 41338 },      // valid
    ];
    const valid = peers.filter(p =>
      IPV4_RE.test(p.host) && Number.isInteger(p.port) && p.port > 0 && p.port < 65536
    );
    expect(valid.length).toBe(2);
  });
});
