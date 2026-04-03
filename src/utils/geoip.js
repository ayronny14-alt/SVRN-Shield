/**
 * Minimal IP classification utilities.
 * Only private-IP detection and basic classification — no reverse DNS,
 * ASN lookups, or cloud-provider guessing (use dedicated tools for that).
 */

export function ipToInt(ip) {
  const parts = ip.split('.');
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function isPrivateIP(ip) {
  if (ip === '::1' || ip === '0.0.0.0' || ip === '127.0.0.1') return true;
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip.includes(':')) return ip === '::1';
  const n = ipToInt(ip);
  return (
    (n >= 0x0A000000 && n <= 0x0AFFFFFF) || // 10.0.0.0/8
    (n >= 0xAC100000 && n <= 0xAC1FFFFF) || // 172.16.0.0/12
    (n >= 0xC0A80000 && n <= 0xC0A8FFFF) || // 192.168.0.0/16
    (n >= 0x7F000000 && n <= 0x7FFFFFFF) || // 127.0.0.0/8
    n === 0                                  // 0.0.0.0
  );
}

export async function classifyIP(ip) {
  return { ip, private: isPrivateIP(ip) };
}
