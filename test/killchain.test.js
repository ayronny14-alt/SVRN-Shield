import { KillChainTracker, TECHNIQUES } from '../src/core/killChain.js';

describe('KillChainTracker', () => {
  let tracker;
  afterEach(() => { tracker?.stop(); });

  beforeEach(() => {
    tracker = new KillChainTracker({ ttlMs: 60_000 });
  });

  test('records an event and associates technique', () => {
    const result = tracker.record('1.2.3.4', 'port-scan', { severity: 'high' });
    expect(result.technique).not.toBeNull();
    expect(result.technique.id).toBe('T1046');
    expect(result.technique.stage).toBe('recon');
    expect(result.chain).not.toBeNull();
    expect(result.chain.score).toBeGreaterThan(0);
  });

  test('records new stage flag correctly', () => {
    const r1 = tracker.record('5.5.5.5', 'port-scan');
    expect(r1.newStage).toBe(true);

    // same stage again — not new
    const r2 = tracker.record('5.5.5.5', 'syn-scan');
    expect(r2.newStage).toBe(false); // same stage: recon
  });

  test('tracks multiple stages for same IP', () => {
    tracker.record('10.0.0.1', 'port-scan');   // recon
    tracker.record('10.0.0.1', 'honeypot');    // discovery
    tracker.record('10.0.0.1', 'dns-tunnel');  // c2

    const chain = tracker.getChain('10.0.0.1');
    expect(chain.stageList).toContain('recon');
    expect(chain.stageList).toContain('discovery');
    expect(chain.stageList).toContain('c2');
    expect(chain.stages).toHaveProperty('recon');
    expect(chain.stages).toHaveProperty('discovery');
    expect(chain.stages).toHaveProperty('c2');
  });

  test('emits campaign-detected when all 4 stages complete', () => {
    let campaign = null;
    tracker.on('campaign-detected', (c) => { campaign = c; });

    tracker.record('9.9.9.9', 'port-scan');    // recon
    tracker.record('9.9.9.9', 'honeypot');     // discovery
    tracker.record('9.9.9.9', 'dns-tunnel');   // c2
    expect(campaign).toBeNull(); // only 3 stages

    tracker.record('9.9.9.9', 'exfil');        // exfil — completes chain
    expect(campaign).not.toBeNull();
    expect(campaign.ip).toBe('9.9.9.9');
    expect(campaign.stageCount).toBe(4);
    expect(campaign.stages).toHaveLength(4);
    expect(campaign.severity).toBe('critical');
  });

  test('campaign only alerts once per IP', () => {
    let count = 0;
    tracker.on('campaign-detected', () => { count++; });

    tracker.record('8.8.8.8', 'port-scan');
    tracker.record('8.8.8.8', 'honeypot');
    tracker.record('8.8.8.8', 'dns-tunnel');
    tracker.record('8.8.8.8', 'exfil');
    tracker.record('8.8.8.8', 'exfil'); // repeat — should NOT re-alert

    expect(count).toBe(1);
  });

  test('score accumulates across events', () => {
    tracker.record('7.7.7.7', 'port-scan');
    const s1 = tracker.getChain('7.7.7.7').score;

    tracker.record('7.7.7.7', 'xmas-scan');
    const s2 = tracker.getChain('7.7.7.7').score;

    expect(s2).toBeGreaterThan(s1);
  });

  test('score capped at 100', () => {
    for (let i = 0; i < 20; i++) {
      tracker.record('6.6.6.6', 'exfil');
    }
    expect(tracker.getChain('6.6.6.6').score).toBeLessThanOrEqual(100);
  });

  test('getChain returns null for unknown IP', () => {
    expect(tracker.getChain('unknown')).toBeNull();
  });

  test('chains getter returns sorted by score', () => {
    tracker.record('1.1.1.1', 'port-scan');
    tracker.record('2.2.2.2', 'exfil'); // higher score
    tracker.record('2.2.2.2', 'port-scan');

    const chains = tracker.chains;
    expect(chains.length).toBe(2);
    expect(chains[0].score).toBeGreaterThanOrEqual(chains[1].score);
  });

  test('emits event-recorded for every event', () => {
    let emitted = null;
    tracker.on('event-recorded', (e) => { emitted = e; });

    tracker.record('3.3.3.3', 'port-scan');
    expect(emitted).not.toBeNull();
    expect(emitted.ip).toBe('3.3.3.3');
    expect(emitted.newStage).toBe(true);
  });

  test('unknown event type still records but technique is null', () => {
    const result = tracker.record('4.4.4.4', 'unknown-event');
    expect(result.technique).toBeNull();
    expect(result.chain).not.toBeNull();
    expect(result.chain.score).toBe(5); // default score
  });

  test('handles invalid IP gracefully', () => {
    const result = tracker.record(null, 'port-scan');
    expect(result.chain).toBeNull();
  });

  test('evicts oldest when at maxChains capacity', () => {
    const small = new KillChainTracker({ maxChains: 3 });
    small.record('1.1.1.1', 'port-scan');
    small.record('2.2.2.2', 'port-scan');
    small.record('3.3.3.3', 'port-scan');
    small.record('4.4.4.4', 'port-scan'); // should evict oldest

    expect(small.stats.tracked).toBeLessThanOrEqual(3);
    small.stop();
  });

  test('stats reports correct counts', () => {
    tracker.record('1.1.1.1', 'port-scan');
    tracker.record('1.1.1.1', 'honeypot');
    tracker.record('1.1.1.1', 'dns-tunnel');
    tracker.record('1.1.1.1', 'exfil');

    const stats = tracker.stats;
    expect(stats.module).toBe('KillChainTracker');
    expect(stats.tracked).toBe(1);
    expect(stats.campaigns).toBe(1);
  });

  test('TECHNIQUES map has expected entries', () => {
    expect(TECHNIQUES['port-scan']).toBeDefined();
    expect(TECHNIQUES['honeypot']).toBeDefined();
    expect(TECHNIQUES['exfil']).toBeDefined();
    expect(TECHNIQUES['dns-tunnel']).toBeDefined();
    expect(TECHNIQUES['c2']).toBeDefined();
  });

  test('campaign report includes MITRE technique IDs', () => {
    let campaign = null;
    tracker.on('campaign-detected', (c) => { campaign = c; });

    tracker.record('10.10.10.10', 'port-scan');
    tracker.record('10.10.10.10', 'honeypot');
    tracker.record('10.10.10.10', 'dns-tunnel');
    tracker.record('10.10.10.10', 'exfil');

    expect(campaign.stages.some(s => s.technique.startsWith('T'))).toBe(true);
  });

  test('events trimmed at 200', () => {
    for (let i = 0; i < 250; i++) {
      tracker.record('99.99.99.99', 'port-scan');
    }
    const chain = tracker.getChain('99.99.99.99');
    expect(chain.eventCount).toBeLessThanOrEqual(200);
  });
});
