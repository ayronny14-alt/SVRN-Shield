import { getBanner, listBanners, BANNERS } from '../src/honeypot/banners.js';

describe('Banners', () => {
  test('listBanners returns all services', () => {
    const list = listBanners();
    expect(list).toContain('ssh');
    expect(list).toContain('http');
    expect(list).toContain('ftp');
    expect(list).toContain('smtp');
    expect(list).toContain('redis');
    expect(list).toContain('mysql');
    expect(list).toContain('dns');
    expect(list).toContain('telnet');
    expect(list).toContain('https');
  });

  test('SSH banner sends greeting', () => {
    const b = getBanner('ssh');
    expect(b.greeting).toContain('SSH-2.0');
    expect(b.proto).toBe('tcp');
  });

  test('HTTP banner responds to GET', () => {
    const b = getBanner('http');
    const resp = b.respond(Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'));
    expect(resp).not.toBeNull();
    expect(resp.toString()).toContain('200 OK');
    expect(resp.toString()).toContain('nginx');
  });

  test('FTP banner responds to USER/PASS', () => {
    const b = getBanner('ftp');
    expect(b.greeting).toContain('220');
    const userResp = b.respond(Buffer.from('USER admin\r\n'));
    expect(userResp.toString()).toContain('331');
    const passResp = b.respond(Buffer.from('PASS password\r\n'));
    expect(passResp.toString()).toContain('530');
  });

  test('Redis banner responds to PING', () => {
    const b = getBanner('redis');
    const resp = b.respond(Buffer.from('PING'));
    expect(resp.toString()).toContain('+PONG');
  });

  test('Redis rejects AUTH', () => {
    const b = getBanner('redis');
    const resp = b.respond(Buffer.from('AUTH mysecret'));
    expect(resp.toString()).toContain('invalid password');
  });

  test('SMTP banner responds to EHLO', () => {
    const b = getBanner('smtp');
    expect(b.greeting).toContain('220');
    const resp = b.respond(Buffer.from('EHLO client.example.com\r\n'));
    expect(resp.toString()).toContain('250');
  });

  test('HTTPS banner sends TLS alert for ClientHello', () => {
    const b = getBanner('https');
    const clientHello = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);
    const resp = b.respond(clientHello);
    expect(resp).not.toBeNull();
    expect(resp[0]).toBe(0x15); // Alert record
  });

  test('DNS banner responds with NXDOMAIN', () => {
    const b = getBanner('dns');
    const query = Buffer.alloc(20);
    query.writeUInt16BE(1, 0); // transaction ID
    query.writeUInt16BE(0x0100, 2); // standard query
    query.writeUInt16BE(1, 4); // 1 question
    const resp = b.respond(query);
    expect(resp).not.toBeNull();
    expect(resp[3] & 0x0F).toBe(3); // NXDOMAIN
  });

  test('unknown banner returns null', () => {
    expect(getBanner('nonexistent')).toBeNull();
  });
});

