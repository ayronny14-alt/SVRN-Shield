import { Shield } from '../src/index.js';

describe('Shield Lifecycle Integration', () => {
  let shield;
  const attackerIP = '203.0.113.100';

  beforeAll(async () => {
    shield = await Shield.create({
      honeypot: { ports: [2222, 8080] },
      persistence: false, 
      logging: { console: false },
    });
  });

  afterAll(async () => {
    await shield.stop();
  });

  test('full kill-chain lifecycle: recon -> discovery -> c2 -> exfil', async () => {
    let campaignDetected = false;
    shield.on('campaign-detected', (c) => { 
      if (c.ip === attackerIP) campaignDetected = true; 
    });

    // 1. RECON: SYN Scan
    for (let i = 0; i < 20; i++) {
        shield.scanner.ingest({ 
          srcIp: attackerIP, 
          dstPort: 1000 + i, 
          flags: { syn: true, ack: false },
          now: Date.now() + (i * 200)
        });
    }
    const chain1 = shield.killChain.getChain(attackerIP);
    expect(chain1.stages).toHaveProperty('recon');
    
    // 2. DISCOVERY: Honeypot Hit
    shield.honeypot.emit('connection', { ip: attackerIP, port: 2222, service: 'ssh' });
    expect(shield.killChain.getChain(attackerIP).stages).toHaveProperty('discovery');

    // 3. C2: DNS Tunnel
    shield.dns.emit('tunnel-detected', { 
      ip: attackerIP, 
      domain: 'v3ry-long-encoded-data.attacker.com', 
      entropy: 4.5,
      score: 0.8
    });
    expect(shield.killChain.getChain(attackerIP).stages).toHaveProperty('c2');

    // 4. EXFIL: Data Bursts
    shield.sentinel.emit('exfil-alert', { 
      remoteAddr: attackerIP, 
      bytes: 50000000, 
      window: 60000,
      severity: 'high',
      type: 'volume'
    });
    expect(shield.killChain.getChain(attackerIP).stages).toHaveProperty('exfil');

    // Verify campaign
    expect(campaignDetected).toBe(true);

    // Verify reputation
    const rep = shield.threatIntel.getProfile(attackerIP);
    expect(rep.score).toBeLessThan(0.4); 
    expect(rep.classification).toBe('malicious');
  });

  test('P2P ThreatMesh integration', async () => {
    const peerIP = '10.0.0.5';
    shield.killChain.record(peerIP, 'port-scan', { severity: 'high' });
    const rep = shield.threatIntel.getProfile(peerIP);
    expect(rep.totalEvents).toBeGreaterThan(0);
  });
});
