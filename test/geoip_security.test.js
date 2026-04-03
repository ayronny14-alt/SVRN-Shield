import { isPrivateIP, parseIPv4 } from '../src/utils/geoip.js';

describe('IP Security & Classification', () => {
  test('Standard Private IPs', () => {
    expect(isPrivateIP('127.0.0.1')).toBe(true);
    expect(isPrivateIP('10.0.0.5')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
    expect(isPrivateIP('172.16.0.10')).toBe(true);
    expect(isPrivateIP('169.254.1.1')).toBe(true);
    expect(isPrivateIP('0.0.0.0')).toBe(true);
  });

  test('Public IPs', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('1.1.1.1')).toBe(false);
    expect(isPrivateIP('203.0.113.1')).toBe(false);
  });

  test('CVE-2024-29415 Bypasses (Short Formats)', () => {
    expect(isPrivateIP('127.1')).toBe(true);
    expect(isPrivateIP('127.0.1')).toBe(true);
    expect(isPrivateIP('10.1')).toBe(true);
    expect(isPrivateIP('10.0.1')).toBe(true);
  });

  test('Octal Bypasses', () => {
    expect(isPrivateIP('0177.0.0.01')).toBe(true); // 127.0.0.1
    expect(isPrivateIP('012.0.0.1')).toBe(true);   // 10.0.0.1
  });

  test('Hex Bypasses', () => {
    expect(isPrivateIP('0x7f000001')).toBe(true); // 127.0.0.1
    expect(isPrivateIP('127.0x1')).toBe(true);
  });

  test('IPv4-mapped IPv6 obfuscation', () => {
    expect(isPrivateIP('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIP('::ffff:127.1')).toBe(true);
    expect(isPrivateIP('::fFFf:127.0.0.1')).toBe(true);
  });

  test('IPv6 Loopback', () => {
    expect(isPrivateIP('::1')).toBe(true);
    expect(isPrivateIP('0:0:0:0:0:0:0:1')).toBe(true);
  });

  test('Invalid Input', () => {
    expect(isPrivateIP('not an ip')).toBe(false);
    expect(isPrivateIP('')).toBe(false);
    expect(isPrivateIP(null)).toBe(false);
    expect(isPrivateIP('127.0.0.1.1')).toBe(false);
  });
});
