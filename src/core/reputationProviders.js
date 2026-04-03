/**
 * Sample Reputation Provider: AbuseIPDB
 */
export class AbuseIPDBProvider {
  constructor(apiKey) {
    this.name = 'AbuseIPDB';
    this._apiKey = apiKey;
  }

  async check(ip) {
    if (!this._apiKey) return null;

    try {
      const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
        headers: {
          Key: this._apiKey,
          Accept: 'application/json',
        }
      });
      const { data } = await resp.json();
      
      // Map AbuseIPDB score (0-100) to our penalty system
      return {
        score:         data.abuseConfidenceScore,
        country:       data.countryCode,
        isPublic:      data.isPublic,
        usageType:     data.usageType,
        totalReports:  data.totalReports,
        severity:      data.abuseConfidenceScore > 50 ? 'high' : (data.abuseConfidenceScore > 10 ? 'medium' : 'low'),
        scoreDelta:    data.abuseConfidenceScore / 100, // Normalized penalty
      };
    } catch (err) {
      return null;
    }
  }
}
