import { shannonEntropy, stringEntropy, entropyGradient, isHighEntropy } from '../src/utils/entropy.js';
import { RingBuffer } from '../src/utils/ringBuffer.js';
import { PortBitfield } from '../src/utils/bitfield.js';
import { isPrivateIP, ipToInt } from '../src/utils/geoip.js';

describe('Entropy', () => {
  test('zero entropy for uniform buffer', () => {
    const buf = Buffer.alloc(100, 0x41);
    expect(shannonEntropy(buf)).toBe(0);
  });

  test('max entropy for random-like buffer', () => {
    const buf = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) buf[i] = i;
    expect(shannonEntropy(buf)).toBe(8);
  });

  test('string entropy works', () => {
    expect(stringEntropy('aaaa')).toBe(0);
    expect(stringEntropy('abcd')).toBe(2);
  });

  test('entropy gradient computes deltas', () => {
    const c1 = Buffer.alloc(100, 0x41);
    const c2 = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) c2[i] = i;
    const grad = entropyGradient([c1, c2]);
    expect(grad).toHaveLength(1);
    expect(grad[0]).toBe(8);
  });

  test('isHighEntropy detects encrypted data', () => {
    const buf = Buffer.alloc(1024);
    for (let i = 0; i < 1024; i++) buf[i] = Math.floor(Math.random() * 256);
    expect(isHighEntropy(buf, 6)).toBe(true);
  });

  test('empty buffer returns 0', () => {
    expect(shannonEntropy(Buffer.alloc(0))).toBe(0);
    expect(stringEntropy('')).toBe(0);
  });
});

describe('RingBuffer', () => {
  test('push and iterate', () => {
    const rb = new RingBuffer(3);
    rb.push(1).push(2).push(3);
    expect(rb.toArray()).toEqual([1, 2, 3]);
    expect(rb.size).toBe(3);
  });

  test('overflow wraps correctly', () => {
    const rb = new RingBuffer(3);
    rb.push(1).push(2).push(3).push(4);
    expect(rb.toArray()).toEqual([2, 3, 4]);
    expect(rb.size).toBe(3);
    expect(rb.full).toBe(true);
  });

  test('peek returns latest', () => {
    const rb = new RingBuffer(5);
    rb.push('a').push('b');
    expect(rb.peek()).toBe('b');
  });

  test('oldest returns first element', () => {
    const rb = new RingBuffer(3);
    rb.push(10).push(20).push(30).push(40);
    expect(rb.oldest()).toBe(20);
  });

  test('filter and countWhere', () => {
    const rb = new RingBuffer(10);
    for (let i = 0; i < 10; i++) rb.push(i);
    expect(rb.filter(x => x > 5)).toEqual([6, 7, 8, 9]);
    expect(rb.countWhere(x => x % 2 === 0)).toBe(5);
  });

  test('clear resets', () => {
    const rb = new RingBuffer(5);
    rb.push(1).push(2);
    rb.clear();
    expect(rb.size).toBe(0);
    expect(rb.toArray()).toEqual([]);
  });

  test('Symbol.iterator works', () => {
    const rb = new RingBuffer(3);
    rb.push('x').push('y');
    expect([...rb]).toEqual(['x', 'y']);
  });
});

describe('PortBitfield', () => {
  test('set and has', () => {
    const bf = new PortBitfield();
    expect(bf.set(80)).toBe(true);
    expect(bf.has(80)).toBe(true);
    expect(bf.has(81)).toBe(false);
    expect(bf.count).toBe(1);
  });

  test('duplicate set returns false', () => {
    const bf = new PortBitfield();
    bf.set(443);
    expect(bf.set(443)).toBe(false);
    expect(bf.count).toBe(1);
  });

  test('listSet returns sorted ports', () => {
    const bf = new PortBitfield();
    bf.set(8080);
    bf.set(22);
    bf.set(443);
    expect(bf.listSet()).toEqual([22, 443, 8080]);
  });

  test('handles full range', () => {
    const bf = new PortBitfield();
    bf.set(0);
    bf.set(65535);
    expect(bf.has(0)).toBe(true);
    expect(bf.has(65535)).toBe(true);
    expect(bf.count).toBe(2);
  });

  test('union and intersection', () => {
    const a = new PortBitfield();
    const b = new PortBitfield();
    a.set(22); a.set(80);
    b.set(80); b.set(443);
    const u = a.union(b);
    expect(u.listSet()).toEqual([22, 80, 443]);
    const i = a.intersection(b);
    expect(i.listSet()).toEqual([80]);
  });

  test('clear resets', () => {
    const bf = new PortBitfield();
    bf.set(22); bf.set(80);
    bf.clear();
    expect(bf.count).toBe(0);
    expect(bf.has(22)).toBe(false);
  });
});

describe('IP Utilities', () => {
  test('isPrivateIP identifies private ranges', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
    expect(isPrivateIP('172.16.0.1')).toBe(true);
    expect(isPrivateIP('127.0.0.1')).toBe(true);
    expect(isPrivateIP('::1')).toBe(true);
    expect(isPrivateIP('0.0.0.0')).toBe(true);
  });

  test('isPrivateIP rejects public IPs', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('1.1.1.1')).toBe(false);
    expect(isPrivateIP('93.184.216.34')).toBe(false);
  });

  test('isPrivateIP handles IPv4-mapped IPv6', () => {
    expect(isPrivateIP('::ffff:192.168.1.1')).toBe(true);
    expect(isPrivateIP('::ffff:8.8.8.8')).toBe(false);
  });

  test('ipToInt converts correctly', () => {
    expect(ipToInt('0.0.0.0')).toBe(0);
    expect(ipToInt('0.0.0.1')).toBe(1);
    expect(ipToInt('10.0.0.1')).toBe(0x0A000001);
  });
});
