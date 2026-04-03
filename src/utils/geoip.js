/**
 * IP classification and GeoIP enrichment.
 *
 * Provides:
 *   - Private IP detection (always available, zero deps)
 *   - GeoIP enrichment via MaxMind GeoLite2 (optional, requires maxmind + .mmdb files)
 *
 * GeoIP is lazy-loaded: if maxmind isn't installed or .mmdb files aren't
 * present, classifyIP() falls back to basic private/public classification.
 *
 * Setup for full GeoIP:
 *   npm install maxmind
 *   Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind
 *   Pass paths via:
 *     Shield.create({ geoip: { cityDb: './GeoLite2-City.mmdb', asnDb: './GeoLite2-ASN.mmdb' } })
 */

let cityReader = null;
let asnReader = null;
let geoipReady = false;
let geoipAttempted = false;

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

/**
 * Initialize GeoIP readers.
 * @param {{ cityDb?: string, asnDb?: string }} opts
 * @returns {Promise<boolean>} true if GeoIP is available
 */
export async function initGeoIP(opts = {}) {
  if (geoipReady) return true;
  if (geoipAttempted) return false;
  geoipAttempted = true;

  try {
    const maxmind = await import('maxmind');
    const open = maxmind.default?.open || maxmind.open;

    if (opts.cityDb) {
      try {
        cityReader = await open(opts.cityDb);
      } catch { /* city db not available */ }
    }
    if (opts.asnDb) {
      try {
        asnReader = await open(opts.asnDb);
      } catch { /* asn db not available */ }
    }

    geoipReady = !!(cityReader || asnReader);
    return geoipReady;
  } catch {
    // maxmind package not installed — GeoIP not available
    return false;
  }
}

/**
 * Classify and enrich an IP address.
 *
 * Returns basic classification (always) + GeoIP enrichment (when available).
 *
 * @param {string} ip
 * @returns {Promise<object>}
 */
export async function classifyIP(ip) {
  const result = {
    ip,
    private: isPrivateIP(ip),
    geo: null,
    asn: null,
  };

  if (result.private || !geoipReady) return result;

  // City/Country lookup
  if (cityReader) {
    try {
      const city = cityReader.get(ip);
      if (city) {
        result.geo = {
          country: city.country?.iso_code || null,
          countryName: city.country?.names?.en || null,
          city: city.city?.names?.en || null,
          region: city.subdivisions?.[0]?.names?.en || null,
          continent: city.continent?.code || null,
          latitude: city.location?.latitude || null,
          longitude: city.location?.longitude || null,
          timezone: city.location?.time_zone || null,
          accuracy: city.location?.accuracy_radius || null,
        };
      }
    } catch { /* lookup failed */ }
  }

  // ASN lookup
  if (asnReader) {
    try {
      const asn = asnReader.get(ip);
      if (asn) {
        result.asn = {
          number: asn.autonomous_system_number || null,
          org: asn.autonomous_system_organization || null,
        };
      }
    } catch { /* lookup failed */ }
  }

  return result;
}

/**
 * Synchronous classification — returns only what's available without async.
 * Useful for hot-path inline enrichment (city/ASN readers are sync once loaded).
 */
export function classifyIPSync(ip) {
  const result = { ip, private: isPrivateIP(ip), geo: null, asn: null };
  if (result.private || !geoipReady) return result;

  if (cityReader) {
    try {
      const city = cityReader.get(ip);
      if (city) {
        result.geo = {
          country: city.country?.iso_code || null,
          countryName: city.country?.names?.en || null,
          city: city.city?.names?.en || null,
          org: null,
        };
      }
    } catch { /* ok */ }
  }

  if (asnReader) {
    try {
      const asn = asnReader.get(ip);
      if (asn) {
        result.asn = {
          number: asn.autonomous_system_number || null,
          org: asn.autonomous_system_organization || null,
        };
      }
    } catch { /* ok */ }
  }

  return result;
}

/**
 * Check if GeoIP databases are loaded.
 */
export function isGeoIPReady() {
  return geoipReady;
}
