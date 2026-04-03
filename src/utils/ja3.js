import crypto from 'node:crypto';

/**
 * Lightweight JA3 TLS Fingerprinting.
 * JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 */
export function calculateJA3(clientHello) {
  if (!clientHello || clientHello.length < 5) return null;

  try {
    // Basic TLS Record Layer check
    if (clientHello[0] !== 0x16) return null; // Not a Handshake record

    let pos = 5; // Skip TLS Record Header
    if (clientHello[pos] !== 0x01) return null; // Not ClientHello

    const handshakeLen = clientHello.readUInt24BE ? clientHello.readUInt24BE(pos + 1) : (clientHello[pos+1] << 16 | clientHello[pos+2] << 8 | clientHello[pos+3]);
    pos += 4;

    const version = clientHello.readUInt16BE(pos);
    pos += 2;

    pos += 32; // Random

    const sessionIDLen = clientHello[pos];
    pos += 1 + sessionIDLen;

    const cipherSuiteLen = clientHello.readUInt16BE(pos);
    pos += 2;
    const ciphers = [];
    for (let i = 0; i < cipherSuiteLen; i += 2) {
      const c = clientHello.readUInt16BE(pos + i);
      if (!isGrease(c)) ciphers.push(c);
    }
    pos += cipherSuiteLen;

    const compressionLen = clientHello[pos];
    pos += 1 + compressionLen;

    if (pos >= clientHello.length) return buildJA3(version, ciphers, [], [], []);

    const extensionsLen = clientHello.readUInt16BE(pos);
    pos += 2;
    
    const extensions = [];
    const curves = [];
    const points = [];

    const end = pos + extensionsLen;
    while (pos + 4 <= end && pos + 4 <= clientHello.length) {
      const type = clientHello.readUInt16BE(pos);
      const len = clientHello.readUInt16BE(pos + 2);
      pos += 4;

      if (!isGrease(type)) {
        extensions.push(type);
        if (type === 0x000a) { // supported_groups (curves)
          const listLen = clientHello.readUInt16BE(pos);
          for (let i = 2; i < listLen + 2; i += 2) {
            const c = clientHello.readUInt16BE(pos + i);
            if (!isGrease(c)) curves.push(c);
          }
        } else if (type === 0x000b) { // ec_point_formats
          const listLen = clientHello[pos];
          for (let i = 1; i < listLen + 1; i++) {
            points.push(clientHello[pos + i]);
          }
        }
      }
      pos += len;
    }

    return buildJA3(version, ciphers, extensions, curves, points);
  } catch (err) {
    return null;
  }
}

function isGrease(n) {
  if ((n & 0x0f0f) === 0x0a0a && n >> 8 === (n & 0xff)) return true;
  return false;
}

function buildJA3(ver, ciphers, exts, curves, points) {
  const str = [
    ver,
    ciphers.join('-'),
    exts.join('-'),
    curves.join('-'),
    points.join('-')
  ].join(',');
  
  return {
    ja3_str: str,
    ja3_hash: crypto.createHash('md5').update(str).digest('hex')
  };
}
