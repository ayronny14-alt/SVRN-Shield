import { PortScanDetector } from '../src/core/portScanner.js';
import { BehavioralRateLimiter } from '../src/core/rateLimiter.js';
import { ThreatIntel } from '../src/core/threatIntel.js';
import { AlertPipeline } from '../src/core/alertPipeline.js';

describe('PortScanDetector', () => {
  let detector;
  beforeEach(() => {
    detector = new PortScanDetector({ portsPerWindow: 5, window: 5000 });
  });

  test('detects fast port scan', () => {
    let detected = null;
    detector.on('scan-detected', (d) => { detected = d; });

    for (let port = 1; port <= 10; port++) {
      detector.ingest({ srcIp: '1.2.3.4', dstPort: port, flags: { syn: true, ack: true } });
    }

    expect(detected).not.toBeNull();
    expect(detected.ip).toBe('1.2.3.4');
    expect(detected.type).toBe('connect_scan');
  });

  test('detects SYN scan (half-open)', () => {
    detector = new PortScanDetector({ synWithoutAck: 3 });
    let detected = null;
    detector.on('scan-detected', (d) => {
      if (d.type === 'syn_scan') detected = d;
    });

    for (let port = 1; port <= 5; port++) {
      detector.ingest({ srcIp: '5.6.7.8', dstPort: port, flags: { syn: true } });
    }

    expect(detected).not.toBeNull();
    expect(detected.type).toBe('syn_scan');
  });

  test('detects XMAS scan', () => {
    let detected = null;
    detector.on('scan-detected', (d) => {
      if (d.type === 'xmas_scan') detected = d;
    });

    detector.ingest({ srcIp: '9.9.9.9', dstPort: 80, flags: { fin: true, psh: true, urg: true } });
    expect(detected).not.toBeNull();
    expect(detected.severity).toBe('critical');
  });

  test('detects NULL scan', () => {
    let detected = null;
    detector.on('scan-detected', (d) => {
      if (d.type === 'null_scan') detected = d;
    });

    detector.ingest({ srcIp: '10.10.10.10', dstPort: 443, proto: 'tcp', flags: {} });
    expect(detected).not.toBeNull();
  });

  test('tracks per-IP state', () => {
    for (let i = 0; i < 20; i++) {
      detector.ingest({ srcIp: '1.1.1.1', dstPort: i, flags: { syn: true, ack: true } });
    }
    const tracker = detector.getProfile('1.1.1.1');
    expect(tracker).not.toBeNull();
    expect(tracker.totalProbes).toBe(20);
    expect(tracker.ports.length).toBe(20);
  });

  test('block/unblock', () => {
    expect(detector.isBlocked('1.2.3.4')).toBe(false);
    detector.block('1.2.3.4');
    expect(detector.isBlocked('1.2.3.4')).toBe(true);
    detector.unblock('1.2.3.4');
    expect(detector.isBlocked('1.2.3.4')).toBe(false);
  });
});

describe('BehavioralRateLimiter', () => {
  let limiter;
  beforeEach(() => {
    limiter = new BehavioralRateLimiter({ defaultRate: 10, window: 1000 });
  });

  test('allows requests under limit', () => {
    const result = limiter.check('user1');
    expect(result.allowed).toBe(true);
    expect(result.trust).toBeGreaterThan(0);
  });

  test('blocks after being banned', () => {
    limiter.ban('user2', 60000);
    const result = limiter.check('user2');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('blocked');
  });

  test('trust grows with good behavior', () => {
    const r1 = limiter.check('user3');
    const r2 = limiter.check('user3');
    expect(r2.trust).toBeGreaterThanOrEqual(r1.trust);
  });

  test('ban and unban', () => {
    limiter.ban('user4', 60000);
    const result = limiter.check('user4');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('blocked');

    limiter.unban('user4');
    const result2 = limiter.check('user4');
    expect(result2.reason).not.toBe('blocked');
  });

  test('getProfile returns identity info', () => {
    limiter.check('user5');
    const profile = limiter.getProfile('user5');
    expect(profile).not.toBeNull();
    expect(profile.id).toBe('user5');
    expect(profile.totalRequests).toBe(1);
  });
});

describe('ThreatIntel', () => {
  let intel;
  beforeEach(() => {
    intel = new ThreatIntel();
  });

  test('default score for unknown IP', () => {
    expect(intel.score('1.2.3.4')).toBe(0.5);
  });

  test('private IPs always trusted', () => {
    expect(intel.score('192.168.1.1')).toBe(1.0);
  });

  test('score decreases on bad events', () => {
    intel.recordEvent('5.5.5.5', 'port-scan', 'high');
    expect(intel.score('5.5.5.5')).toBeLessThan(0.5);
  });

  test('classify changes with score', () => {
    expect(intel.classify('5.5.5.5')).toBe('neutral');
    intel.recordEvent('5.5.5.5', 'honeypot-hit', 'critical');
    intel.recordEvent('5.5.5.5', 'port-scan', 'high');
    const c = intel.classify('5.5.5.5');
    expect(c === 'malicious' || c === 'suspicious').toBe(true);
  });

  test('blocklist overrides score', () => {
    intel.addBlocklist('test', ['9.9.9.9']);
    expect(intel.score('9.9.9.9')).toBe(0);
    expect(intel.isBlocked('9.9.9.9')).toBe(true);
  });

  test('reward increases score', () => {
    intel.recordEvent('2.2.2.2', 'port-scan');
    const before = intel.score('2.2.2.2');
    intel.reward('2.2.2.2', 0.1);
    expect(intel.score('2.2.2.2')).toBeGreaterThan(before);
  });

  test('getProfile returns events', () => {
    intel.recordEvent('3.3.3.3', 'scan-detected');
    const profile = intel.getProfile('3.3.3.3');
    expect(profile.events.length).toBe(1);
    expect(profile.totalEvents).toBe(1);
  });
});

describe('AlertPipeline', () => {
  test('fires alert above severity threshold', async () => {
    const pipeline = new AlertPipeline({ minSeverity: 'medium' });
    let received = null;
    pipeline.on('alert', (a) => { received = a; });

    await pipeline.fire({ type: 'test', severity: 'high', ip: '1.1.1.1' });
    expect(received).not.toBeNull();
    expect(received.type).toBe('test');
  });

  test('suppresses below threshold', async () => {
    const pipeline = new AlertPipeline({ minSeverity: 'high' });
    const result = await pipeline.fire({ type: 'test', severity: 'low' });
    expect(result).toBe(false);
  });

  test('cooldown prevents duplicate alerts', async () => {
    const pipeline = new AlertPipeline({ cooldownMs: 5000 });
    const r1 = await pipeline.fire({ type: 'scan', severity: 'high', ip: '2.2.2.2' });
    const r2 = await pipeline.fire({ type: 'scan', severity: 'high', ip: '2.2.2.2' });
    expect(r1).toBe(true);
    expect(r2).toBe(false);
  });

  test('custom handlers receive alerts', async () => {
    const pipeline = new AlertPipeline();
    let handlerCalled = false;
    pipeline.onAlert(() => { handlerCalled = true; });
    await pipeline.fire({ type: 'test', severity: 'high' });
    expect(handlerCalled).toBe(true);
  });

  test('query filters by type', async () => {
    const pipeline = new AlertPipeline({ cooldownMs: 0 });
    await pipeline.fire({ type: 'scan', severity: 'high' });
    await pipeline.fire({ type: 'honeypot', severity: 'high' });
    expect(pipeline.query({ type: 'scan' })).toHaveLength(1);
    expect(pipeline.query({ type: 'honeypot' })).toHaveLength(1);
  });
});
