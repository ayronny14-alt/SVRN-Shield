# @svrnsec/shield

**Host network defense for Node.js.** Port scan detection, honeypot mesh, exfiltration sentinel, DNS tunnel detection, behavioral rate limiting, threat reputation scoring, and a serverless P2P threat mesh that shares intelligence across all your nodes — zero external servers.

```
npm install @svrnsec/shield
```

---

## What it does

Shield is a full-stack network defense layer that runs embedded in your Node.js process. No agents, no SaaS, no $50k SIEM. Drop it in, wire up your events, and get:

| Module | What it catches |
|--------|----------------|
| **Port scan detector** | SYN scans, connect scans, XMAS/NULL/FIN probes, slow scans |
| **Honeypot mesh** | Real-service decoys (SSH, HTTP, FTP) that lure and fingerprint attackers |
| **Exfiltration sentinel** | Large/rapid outbound bursts, connection anomalies |
| **DNS monitor** | High-entropy queries, tunnel detection, domain generation algorithms |
| **Behavioral rate limiter** | Adaptive trust scoring, escalating backoff, auto-ban |
| **Threat intel** | Per-IP reputation with event history, blocklist integration |
| **Alert pipeline** | Multi-handler alerts, webhooks, automatic IP blocking via firewall |
| **ThreatMesh** | P2P threat sharing across all your nodes — no central server |

---

## Quick start

```js
import { Shield } from '@svrnsec/shield';

const shield = await Shield.create({
  honeypot: { ports: [2222, 8080, 2121] },
  mesh: { port: 41338, peers: ['10.0.0.2:41338'] },
});

shield.on('scan-detected', ({ ip, type, severity }) => {
  console.log(`[SCAN] ${type} from ${ip} — ${severity}`);
});

shield.on('threat-received', ({ ip, eventType, source }) => {
  console.log(`[MESH] Threat intel from peer ${source}: ${eventType} @ ${ip}`);
});

// Investigate any IP across all modules
const report = shield.investigate('203.0.113.50');
console.log(report);
```

---

## ThreatMesh — serverless P2P threat sharing

The standout feature. Every Shield node signs its threat events with Ed25519 and broadcasts them over a peer-to-peer mesh. No bootstrap server. No central authority. When one node sees a port scan, every node on the mesh knows within seconds.

**LAN (zero config):** Nodes find each other via UDP multicast automatically.

**Public internet:** Point at one peer; the Peer Exchange protocol propagates the rest.

```js
const shield = await Shield.create({
  mesh: {
    port: 41338,                         // TCP listen port for mesh sync
    peers: ['198.51.100.4:41338'],       // one bootstrap peer is enough
    keyFile: './shield-identity.json',   // Ed25519 keypair, auto-generated
  },
});

// Share a threat event to all peers
await shield.mesh.share({
  ip: '203.0.113.50',
  eventType: 'port-scan',
  severity: 'high',
  detail: 'SYN scan, 89 ports in 2s',
});

// Receive events from peers
shield.on('threat-received', (event) => {
  // event.ip, event.eventType, event.severity, event.nodeId, event.sig
  // Already verified against peer's Ed25519 public key
});
```

**Security properties:**
- Every event is signed — forged events are rejected
- Nodes authenticate each other on connect
- Peer exchange is rate-limited (30s cooldown, max 20 peers per exchange)
- Inbound connections capped at 10/min per source IP
- Wire buffer capped at 512KB — oversized messages drop the connection
- Sync limited to 1,000 events per request

---

## Alert pipeline

```js
import { AlertPipeline } from '@svrnsec/shield/alerts';

const alerts = new AlertPipeline({
  minSeverity: 'medium',   // suppress low-noise events
  cooldownMs: 10_000,      // deduplicate within 10s windows
  autoBlock: true,         // firewall-block IPs on critical alerts
});

// Webhook integration
alerts.onWebhook('https://hooks.slack.com/services/...', {
  headers: { Authorization: 'Bearer ...' },
});

// Custom handler
alerts.onAlert(async (alert) => {
  await db.insert('alerts', alert);
});

await alerts.fire({
  type: 'port-scan',
  severity: 'critical',
  ip: '203.0.113.50',
  detail: 'XMAS scan detected',
  duration: 3600,  // auto-block for 1h
});

// Manual firewall control (safe — validated before any shell call)
await alerts.blockIP('203.0.113.50', 7200);
await alerts.unblockIP('203.0.113.50');
```

`autoBlock: true` calls `netsh` on Windows or `iptables` on Linux/macOS. IPs are validated against a strict regex before any shell execution. Rule names use a SHA-256 hash of the IP — no user data reaches the shell argument list.

---

## Honeypot mesh

```js
import { HoneypotMesh } from '@svrnsec/shield/honeypot';

const honeypot = new HoneypotMesh({
  ports: [
    { port: 2222, service: 'ssh' },
    { port: 8080, service: 'http' },
    { port: 2121, service: 'ftp' },
  ],
});

await honeypot.start();

honeypot.on('connection', ({ ip, port, service, banner }) => {
  console.log(`Honeypot hit: ${ip} probed ${service} on :${port}`);
});
```

Sends realistic service banners (SSH, HTTP, FTP) to fool scanners into revealing their intent. Every connection is logged with timing, banner exchange, and any data sent by the attacker.

---

## DNS tunnel detection

```js
import { DNSMonitor } from '@svrnsec/shield/sentinel/dns';

const dns = new DNSMonitor({ entropyThreshold: 3.8, window: 60_000 });

dns.on('tunnel-suspected', ({ domain, entropy, ip }) => {
  console.log(`DNS tunnel: ${domain} (entropy ${entropy.toFixed(2)}) from ${ip}`);
});
```

Measures Shannon entropy of query labels. Legitimate domains cluster below 3.5 bits. DNS-over-TCP tunnels and DGA beacons spike above 4.0.

---

## Behavioral rate limiter

```js
import { BehavioralRateLimiter } from '@svrnsec/shield/rate-limit';

const limiter = new BehavioralRateLimiter({
  defaultRate: 100,   // requests per window
  window: 60_000,     // 1 minute
});

app.use((req, res, next) => {
  const result = limiter.check(req.ip);
  if (!result.allowed) return res.status(429).json({ error: result.reason });
  next();
});
```

Trust grows with clean behavior and decays with violations. Repeated offenders get exponentially shorter windows before escalating to an auto-ban.

---

## Pulse integration

If you're also running `@svrnsec/pulse` (physics-layer bot detection), Shield's `PulseShield` fuses both signals into a single trust verdict:

```js
import { PulseShield } from '@svrnsec/shield/pulse';
import { validateProof, computeTrustScore } from '@svrnsec/pulse/validator';

const gate = new PulseShield({
  shield,
  pulseVerify: validateProof,
  trustScore: computeTrustScore,
});

// Express middleware — fuses network reputation + physics proof
app.use(gate.middleware({ threshold: 0.5 }));
```

**Fusion weights (configurable):**

| Signal | Default weight |
|--------|---------------|
| Network reputation | 25% |
| Physics proof score | 35% |
| Behavioral rate trust | 15% |
| Honeypot history | 15% |
| Coordination signal | 10% |

Hard overrides: physics forgery caps score at 0.10. Blocklisted IPs cap at 0.05.

---

## Full API

### `Shield.create(opts)` — factory

```js
const shield = await Shield.create({
  scanner:    { portsPerWindow: 15, window: 10_000 },
  honeypot:   { ports: [2222, 8080] },
  sentinel:   { burstBytes: 5_000_000, burstWindow: 60_000 },
  dns:        { entropyThreshold: 3.8 },
  rateLimiter:{ defaultRate: 100, window: 60_000 },
  threatIntel:{},
  mesh:       { port: 41338, peers: [] },
});
```

### `shield.investigate(ip)`

Returns a cross-module report for any IP:

```js
{
  ip: '203.0.113.50',
  reputation: { score: 0.12, classification: 'malicious', events: [...] },
  scanActivity: { totalProbes: 89, ports: [...], lastSeen: 1712100000 },
  rateProfile: { trust: 0.1, violations: 12, escalationLevel: 3 },
  honeypotHits: 2,
  blocked: true,
}
```

### `shield.status`

Live snapshot of all module stats.

### Events

| Event | Source | Payload |
|-------|--------|---------|
| `scan-detected` | scanner | `{ ip, type, severity, ports }` |
| `honeypot-connection` | honeypot | `{ ip, port, service }` |
| `exfil-suspected` | sentinel | `{ ip, bytes, window }` |
| `dns-tunnel-suspected` | dns | `{ ip, domain, entropy }` |
| `rate-limited` | rateLimiter | `{ id, trust, reason }` |
| `alert` | alertPipeline | `{ type, severity, ip, ts }` |
| `threat-received` | mesh | `{ ip, eventType, severity, nodeId }` |
| `peer-joined` | mesh | `{ nodeId, address }` |
| `peer-left` | mesh | `{ nodeId }` |

---

## Security

Shield was built to not be a vulnerability surface:

- **No command injection** — shell calls (`netsh`/`iptables`) validate IPs against strict regex before execution; rule names use SHA-256 hashes, never raw user data
- **No prototype pollution** — incoming JSON from headers and mesh peers is sanitized with `Object.create(null)` and explicit key checking
- **No DoS via buffers** — wire buffer capped at 512KB, sync events capped at 1,000, connection rate capped at 10/min per source IP
- **Cryptographic identity** — each ThreatMesh node generates a persistent Ed25519 keypair; events are signed and verified before being trusted

---

## License

MIT © Aaron Miller
