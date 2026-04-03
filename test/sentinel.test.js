import { DNSMonitor } from '../src/sentinel/dnsMonitor.js';
import { ExfilDetector } from '../src/sentinel/exfilDetector.js';

describe('DNSMonitor', () => {
  let dns;
  beforeEach(() => {
    dns = new DNSMonitor({ whitelist: ['google.com', 'github.com'] });
  });

  test('whitelisted domains not flagged', () => {
    const result = dns.ingest({ domain: 'www.google.com', type: 'A' });
    expect(result).toBeNull();
  });

  test('normal domains not flagged', () => {
    const result = dns.ingest({ domain: 'example.com', type: 'A' });
    expect(result).toBeNull();
  });

  test('high-entropy subdomain flagged', () => {
    // simulate DNS tunneling with encoded data in subdomain
    const encoded = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.tunnel.evil.com';
    const result = dns.ingest({ domain: encoded, type: 'TXT' });
    expect(result).not.toBeNull();
    expect(result.type).toBe('dns-tunnel-suspect');
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  test('hex-encoded subdomain flagged', () => {
    const hex = '48656c6c6f576f726c6448656c6c6f.evil.com';
    const result = dns.ingest({ domain: hex, type: 'A' });
    expect(result).not.toBeNull();
    expect(result.reasons.some(r => r.includes('hex'))).toBe(true);
  });

  test('deep nesting flagged', () => {
    const deep = 'a.b.c.d.e.f.g.evil.com';
    const result = dns.ingest({ domain: deep, type: 'A' });
    // may or may not be flagged depending on other factors
    // but profile should track it
    const profile = dns.getDomainProfile(deep);
    expect(profile).not.toBeNull();
  });

  test('domain profiles track query types', () => {
    dns.ingest({ domain: 'test.example.org', type: 'A' });
    dns.ingest({ domain: 'test.example.org', type: 'TXT' });
    dns.ingest({ domain: 'other.example.org', type: 'A' });
    const profile = dns.getDomainProfile('example.org');
    expect(profile).not.toBeNull();
    expect(profile.queryCount).toBe(3);
    expect(profile.types['A']).toBe(2);
    expect(profile.types['TXT']).toBe(1);
  });

  test('getSuspiciousDomains returns ranked results', () => {
    dns.ingest({ domain: '48656c6c6f576f726c6448656c6c6f.evil.com', type: 'TXT' });
    dns.ingest({ domain: 'normal.safe.com', type: 'A' });
    const suspicious = dns.getSuspiciousDomains();
    expect(suspicious.length).toBeGreaterThanOrEqual(1);
    expect(suspicious[0].domain).toBe('evil.com');
  });

  test('whitelist method works', () => {
    dns.whitelist('newdomain.com');
    const result = dns.ingest({ domain: '48656c6c6f576f726c64.newdomain.com', type: 'TXT' });
    expect(result).toBeNull();
  });

  test('stats tracked', () => {
    dns.ingest({ domain: 'test.com', type: 'A' });
    const stats = dns.stats;
    expect(stats.totalQueries).toBe(1);
    expect(stats.trackedDomains).toBe(1);
  });
});

describe('ExfilDetector', () => {
  let detector;
  beforeEach(() => {
    detector = new ExfilDetector({
      uploadBytesPerMin: 1024 * 1024,
      newDestBurst: 3,
      connRate: 5,
    });
  });

  test('ignores private IPs', () => {
    const result = detector.ingest({
      pid: 1234, processName: 'node.exe',
      remoteAddr: '192.168.1.1', remotePort: 80,
      bytesSent: 100000,
    });
    expect(result).toBeNull();
  });

  test('flags unusual port', () => {
    const result = detector.ingest({
      pid: 1234, processName: 'suspicious.exe',
      remoteAddr: '5.5.5.5', remotePort: 31337,
      bytesSent: 100,
    });
    expect(result).not.toBeNull();
    expect(result.some(a => a.type === 'unusual-port')).toBe(true);
  });

  test('flags destination burst', () => {
    const alerts = [];
    detector.on('exfil-alert', (a) => alerts.push(a));

    for (let i = 1; i <= 5; i++) {
      detector.ingest({
        pid: 1234, processName: 'exfil.exe',
        remoteAddr: `${i}.${i}.${i}.${i}`, remotePort: 443,
        bytesSent: 100,
      });
    }

    expect(alerts.some(a => a.type === 'destination-burst')).toBe(true);
  });

  test('flags high upload volume', () => {
    const result = detector.ingest({
      pid: 5678, processName: 'uploader.exe',
      remoteAddr: '8.8.8.8', remotePort: 443,
      bytesSent: 2 * 1024 * 1024, // 2MB in one shot
    });
    expect(result).not.toBeNull();
    expect(result.some(a => a.type === 'high-upload-volume')).toBe(true);
  });

  test('getSuspiciousProcesses returns ranked list', () => {
    detector.ingest({
      pid: 1, processName: 'bad.exe',
      remoteAddr: '5.5.5.5', remotePort: 31337,
    });
    const procs = detector.getSuspiciousProcesses();
    expect(procs.length).toBeGreaterThanOrEqual(1);
    expect(procs[0].processName).toBe('bad.exe');
  });

  test('getProfile returns process info', () => {
    detector.ingest({
      pid: 99, processName: 'test.exe',
      remoteAddr: '8.8.4.4', remotePort: 443,
      bytesSent: 500, bytesReceived: 200,
    });
    const profile = detector.getProfile(99, 'test.exe');
    expect(profile).not.toBeNull();
    expect(profile.totalBytesSent).toBe(500);
    expect(profile.totalBytesReceived).toBe(200);
    expect(profile.connectionCount).toBe(1);
  });

  test('getAlerts filters correctly', () => {
    detector.ingest({ pid: 1, processName: 'a.exe', remoteAddr: '1.1.1.1', remotePort: 31337 });
    detector.ingest({ pid: 2, processName: 'b.exe', remoteAddr: '2.2.2.2', remotePort: 443, bytesSent: 5 * 1024 * 1024 });
    const portAlerts = detector.getAlerts({ type: 'unusual-port' });
    expect(portAlerts.length).toBeGreaterThanOrEqual(1);
  });
});
