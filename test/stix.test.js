import { STIXGenerator } from '../src/utils/stix.js';

describe('STIXGenerator', () => {
    const generator = new STIXGenerator({ nodeId: 'test-node' });

    test('generates valid indicator from IP', () => {
        const alert = { ip: '1.2.3.4', module: 'Honeypot', event: 'honeypot-hit', severity: 'high', technique: { id: 'T1018' } };
        const obj = generator.toIndicator(alert);
        expect(obj.type).toBe('indicator');
        expect(obj.pattern).toContain("ipv4-addr:value = '1.2.3.4'");
        expect(obj.indicator_types).toContain('malicious-activity');
    });

    test('generates indicator from domain', () => {
        const alert = { domain: 'evil.com', type: 'dns-tunnel' };
        const obj = generator.toIndicator(alert);
        expect(obj.pattern).toContain("domain-name:value = 'evil.com'");
    });

    test('creates full bundle', () => {
        const bundle = generator.generateBundle([
            { ip: '1.1.1.1', event: 'port-scan' },
            { domain: 'bad.xyz', event: 'dns-tunnel' }
        ]);
        expect(bundle.type).toBe('bundle');
        expect(bundle.objects.length).toBe(3); // 1 identity + 2 indicators
        expect(bundle.objects[0].type).toBe('identity');
    });
});
