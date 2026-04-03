import { KillChainTracker } from '../src/core/killChain.js';

describe('KillChainTracker Unit', () => {
    test('records stage correctly', () => {
        const tracker = new KillChainTracker();
        const res = tracker.record('1.1.1.1', 'port-scan');
        expect(res.chain.stages).toHaveProperty('recon');
        expect(tracker.getChain('1.1.1.1').stages).toHaveProperty('recon');
    });
});
