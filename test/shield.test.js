/**
 * Shield orchestrator integration tests.
 *
 * Tests the wiring between modules — when scanner detects a scan,
 * does threatIntel get updated? Does killChain record it? Does the
 * alert pipeline fire?
 */

import { Shield } from '../src/index.js';

describe('Shield Orchestrator', () => {
  let shield;

  beforeEach(() => {
    // Create without starting (no network sockets)
    shield = new Shield({
      honeypot: { ports: [], auto: false },
      scanner: { portsPerWindow: 5, window: 5_000 },
    });
    shield._wire();
  });

  afterEach(() => {
    shield.stop();
  });

  test('constructor initializes all modules', () => {
    expect(shield.scanner).toBeDefined();
    expect(shield.connections).toBeDefined();
    expect(shield.rateLimiter).toBeDefined();
    expect(shield.threatIntel).toBeDefined();
    expect(shield.alerts).toBeDefined();
    expect(shield.honeypot).toBeDefined();
    expect(shield.exfil).toBeDefined();
    expect(shield.dns).toBeDefined();
    expect(shield.killChain).toBeDefined();
  });

  test('mesh is null when not configured', () => {
    expect(shield.mesh).toBeNull();
  });

  test('pulse is null when not configured', () => {
    expect(shield.pulse).toBeNull();
  });

  test('scan detection flows to threat intel', () => {
    // Simulate port scan by ingesting enough events
    for (let port = 1; port <= 10; port++) {
      shield.scanner.ingest({
        srcIp: '203.0.113.50',
        dstPort: port,
        flags: { syn: true, ack: true },
      });
    }

    // Threat intel should have recorded events for this IP
    const profile = shield.threatIntel.getProfile('203.0.113.50');
    expect(profile.totalEvents).toBeGreaterThan(0);
    expect(profile.score).toBeLessThan(0.5);
  });

  test('scan detection feeds kill chain', () => {
    for (let port = 1; port <= 10; port++) {
      shield.scanner.ingest({
        srcIp: '198.51.100.1',
        dstPort: port,
        flags: { syn: true, ack: true },
      });
    }

    const chain = shield.killChain.getChain('198.51.100.1');
    expect(chain).not.toBeNull();
    expect(chain.stageList).toContain('recon');
  });

  test('scan detection fires alert', async () => {
    let alertFired = false;
    shield.alerts.on('alert', () => { alertFired = true; });

    for (let port = 1; port <= 10; port++) {
      shield.scanner.ingest({
        srcIp: '203.0.113.99',
        dstPort: port,
        flags: { syn: true, ack: true },
      });
    }

    // Give alert pipeline time to process
    await new Promise(r => setTimeout(r, 50));
    expect(alertFired).toBe(true);
  });

  test('honeypot connection flows to threat intel and kill chain', () => {
    // Simulate honeypot connection event
    shield.honeypot.emit('connection', {
      ip: '198.51.100.10',
      port: 2222,
      service: 'ssh',
      banner: 'ssh',
      ts: Date.now(),
    });

    const profile = shield.threatIntel.getProfile('198.51.100.10');
    expect(profile.totalEvents).toBe(1);

    const chain = shield.killChain.getChain('198.51.100.10');
    expect(chain).not.toBeNull();
    expect(chain.stageList).toContain('discovery');
  });

  test('exfil alert flows to kill chain', () => {
    shield.exfil.emit('exfil-alert', {
      type: 'high-upload-volume',
      severity: 'high',
      remoteAddr: '198.51.100.20',
      bytes: 10_000_000,
      pid: 1234,
      processName: 'exfil.exe',
    });

    const chain = shield.killChain.getChain('198.51.100.20');
    expect(chain).not.toBeNull();
    expect(chain.stageList).toContain('exfil');
  });

  test('DNS tunnel flows to kill chain and alerts', async () => {
    let alertFired = false;
    shield.alerts.on('alert', (a) => {
      if (a.type === 'dns-tunnel') alertFired = true;
    });

    shield.dns.emit('tunnel-detected', {
      ip: '198.51.100.30',
      domain: 'encoded-data.evil.com',
      entropy: 4.5,
      score: 0.8,
    });

    const chain = shield.killChain.getChain('198.51.100.30');
    expect(chain).not.toBeNull();
    expect(chain.stageList).toContain('c2');

    await new Promise(r => setTimeout(r, 50));
    expect(alertFired).toBe(true);
  });

  test('full kill chain triggers campaign-detected event', () => {
    let campaign = null;
    shield.on('campaign-detected', (c) => { campaign = c; });

    // Simulate a full attack lifecycle through Shield's wiring
    shield.scanner.emit('scan-detected', {
      ip: '192.0.2.1', type: 'port-scan', severity: 'high', portCount: 100,
    });
    shield.honeypot.emit('connection', {
      ip: '192.0.2.1', port: 2222, service: 'ssh', banner: 'ssh',
    });
    shield.dns.emit('tunnel-detected', {
      ip: '192.0.2.1', domain: 'c2.evil.com', entropy: 4.2, score: 0.75,
    });
    shield.exfil.emit('exfil-alert', {
      type: 'high-upload-volume', severity: 'critical',
      remoteAddr: '192.0.2.1', bytes: 50_000_000, pid: 999,
    });

    expect(campaign).not.toBeNull();
    expect(campaign.ip).toBe('192.0.2.1');
    expect(campaign.stageCount).toBe(4);
  });

  test('investigate returns cross-module data', () => {
    // Generate some events
    for (let port = 1; port <= 10; port++) {
      shield.scanner.ingest({
        srcIp: '203.0.113.77',
        dstPort: port,
        flags: { syn: true, ack: true },
      });
    }

    const report = shield.investigate('203.0.113.77');
    expect(report).toHaveProperty('reputation');
    expect(report).toHaveProperty('connections');
    expect(report).toHaveProperty('scanActivity');
    expect(report).toHaveProperty('honeypotHits');
    expect(report).toHaveProperty('alerts');
    expect(report).toHaveProperty('rateLimit');
  });

  test('status returns all module stats', () => {
    const status = shield.status;
    expect(status).toHaveProperty('scanner');
    expect(status).toHaveProperty('connections');
    expect(status).toHaveProperty('rateLimiter');
    expect(status).toHaveProperty('threatIntel');
    expect(status).toHaveProperty('alerts');
    expect(status).toHaveProperty('honeypot');
    expect(status).toHaveProperty('exfil');
    expect(status).toHaveProperty('dns');
    expect(status).toHaveProperty('killChain');
    expect(status.mesh).toBeNull();
    expect(status.pulse).toBeNull();
  });

  test('scan event emitted on shield instance', () => {
    let emitted = null;
    shield.on('scan', (det) => { emitted = det; });

    for (let port = 1; port <= 10; port++) {
      shield.scanner.ingest({
        srcIp: '203.0.113.88',
        dstPort: port,
        flags: { syn: true, ack: true },
      });
    }

    expect(emitted).not.toBeNull();
    expect(emitted.ip).toBe('203.0.113.88');
  });
});

describe('Shield Configuration', () => {
  test('accepts empty config', () => {
    const s = new Shield();
    expect(s.scanner).toBeDefined();
    s.stop();
  });

  test('passes config to submodules', () => {
    const s = new Shield({
      scanner: { portsPerWindow: 50 },
    });
    // portsPerWindow should be set to 50
    expect(s.scanner._thresholds.portsPerWindow).toBe(50);
    s.stop();
  });
});
