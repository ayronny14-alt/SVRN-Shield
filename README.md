# @svrnsec/shield

Network defense that actually lives in your app. Port scans, honeypots, exfil detection, DNS tunneling, rate limiting — all wired together and running in-process. No agents, no dashboards, no SaaS subscription.

```sh
npm install @svrnsec/shield
```

---

## The idea

Most security tooling is something you bolt onto infrastructure. Shield is something you drop into code. It runs inside your Node.js process, hooks into what's already happening on the network, and emits events you can act on however you want — write to a database, call a webhook, firewall-block the IP, whatever.

It's also got a P2P threat mesh. If you're running Shield on multiple nodes, they talk to each other directly over TCP and share what they're seeing. One node catches a scanner, every node on the mesh knows about it within a few seconds. No central server involved.

---

## Getting started

```js
import { Shield } from '@svrnsec/shield';

const shield = await Shield.create({
  honeypot: { ports: [2222, 8080, 2121] },
  mesh: { port: 41338, peers: ['10.0.0.2:41338'] },
  persistence: { path: './data/shield.db' },   // optional — saves everything to SQLite
  logging: { file: './logs/shield.ndjson' },    // optional — NDJSON for SIEM ingestion
});

shield.on('scan', ({ ip, type, severity }) => {
  console.log(`port scan from ${ip}: ${type} (${severity})`);
});

shield.on('campaign-detected', (campaign) => {
  // IP has hit multiple kill-chain stages — this is real
  console.log(campaign);
});

// Investigate any IP across all modules
const report = shield.investigate('203.0.113.50');

// Full forensic bundle — reputation, connections, kill chain, alerts, everything
const evidence = shield.collectEvidence('203.0.113.50');
```

---

## What's included

**Port scan detector** — catches SYN scans, connect scans, XMAS/NULL/FIN probes, slow/distributed scans, UDP sweeps. Per-IP state tracking throughout.

**Honeypot mesh** — listens on unused ports with realistic service banners (SSH, HTTP, FTP, SMTP, MySQL, Redis, and more). Any connection to a honeypot port is an immediate signal. The `auto` mode picks decoy ports intelligently based on what's already running.

**Exfiltration sentinel** — watches for large outbound uploads, connections to unusual ports, destination bursts, asymmetric traffic ratios, and regular-interval beaconing. Learns per-process behavioral baselines so it stops crying wolf after a few minutes of warmup.

**DNS monitor** — flags high-entropy subdomains, deep nesting, base32/hex-encoded labels, TXT query abuse. All the classic DNS tunneling fingerprints. Adaptive baseline detection so it adjusts to your specific traffic pattern.

**Behavioral rate limiter** — tracks trust scores per identity. Good behavior raises the limit. Violations escalate — throttle, then backoff, then ban. Limits auto-adjust based on observed baseline rates.

**Threat intel** — per-IP reputation scoring with event history, decay over time, and blocklist integration. Private IPs are always trusted. Everything else starts at 0.5 and moves based on what you're seeing.

**Kill chain tracker** — maps events to MITRE ATT&CK techniques and correlates them across the recon → discovery → C&C → exfiltration chain. When an IP hits all four stages, it fires `campaign-detected` so you can escalate appropriately.

**Alert pipeline** — deduplicates, severity-filters, fires webhooks, writes to whatever handlers you attach. Can auto-block via `netsh` (Windows) or `iptables` (Linux).

**ThreatMesh** — P2P threat sharing over TCP with Ed25519 signed events. Peers find each other via UDP multicast on LAN or explicit peer list for public networks.

---

## ThreatMesh

The bit that makes this more interesting than a standalone detector.

Each Shield node generates an Ed25519 identity on first run and saves it to a keyfile. When it observes a threat, it signs the event and broadcasts it to peers. Peers verify the signature before acting on it. Forged events are dropped.

```js
const shield = await Shield.create({
  mesh: {
    port: 41338,
    peers: ['198.51.100.4:41338'],  // one peer is enough, PEX handles the rest
    keyFile: './shield-identity.json',
  },
});

// Share something you've seen
await shield.mesh.share({
  ip: '203.0.113.50',
  eventType: 'port-scan',
  severity: 'high',
  detail: 'SYN scan, 89 ports in 2s',
});

// Receive from peers
shield.on('threat-received', (event) => {
  // Already signature-verified by the time you get it
  console.log(event.ip, event.eventType, event.nodeId);
});
```

Security properties: events are signed and rejected if verification fails, connection rate is capped at 10/min per source, wire buffer is capped at 512KB (oversized messages drop the connection), peer exchange has a 30s cooldown and a max of 20 peers per exchange.

---

## Firewall integration

```js
import { AlertPipeline } from '@svrnsec/shield/alerts';

const alerts = new AlertPipeline({
  minSeverity: 'medium',
  cooldownMs: 10_000,
  autoBlock: true,  // calls netsh or iptables automatically on critical alerts
});

alerts.onAlert(async (alert) => {
  await db.insert('alerts', alert);
});

await alerts.fire({
  type: 'port-scan',
  severity: 'critical',
  ip: '203.0.113.50',
  duration: 3600,  // block for 1h
});

// Manual control
await alerts.blockIP('203.0.113.50', 7200);
await alerts.unblockIP('203.0.113.50');
```

IPs are validated against strict regex before any shell call. Rule names use a SHA-256 hash of the IP — no raw user data ever reaches the shell argument list.

---

## Forensic investigation

```js
// Cross-module snapshot for an IP
const report = shield.investigate('203.0.113.50');
// { reputation, connections, scanActivity, honeypotHits, alerts, rateLimit, killChain }

// Full forensic bundle
const evidence = shield.collectEvidence('203.0.113.50');
// {
//   metadata: { generatedAt, shieldVersion, targetIP },
//   summary: { threatScore, classification, killChainStage, totalAlerts },
//   evidence: { ...everything }
// }
```

Connections are also automatically enriched with process info — PID, PPID, and command line — so you know exactly what process opened a connection, not just that it happened.

---

## Persistence + logging

```js
const shield = await Shield.create({
  persistence: { path: './data/shield.db' },          // SQLite via better-sqlite3
  logging: {
    file: './logs/shield.ndjson',   // NDJSON — pipe to Splunk, ELK, Graylog, whatever
    level: 'info',
    console: true,
  },
});
```

Every alert, reputation change, kill-chain stage, and mesh event gets written to the DB automatically. The NDJSON log is designed to be machine-readable from the start — structured fields, ISO timestamps, consistent event names.

---

## Pulse integration

If you're running `@svrnsec/pulse` (physics-layer bot detection) alongside Shield, you can fuse both signals into a single trust verdict:

```js
import { PulseShield } from '@svrnsec/shield/pulse';
import { validateProof, computeTrustScore } from '@svrnsec/pulse/validator';

const gate = new PulseShield({
  shield,
  pulseVerify: validateProof,
  trustScore: computeTrustScore,
});

app.use(gate.middleware({ threshold: 0.5 }));
```

Default fusion weights: physics proof 35%, network reputation 25%, honeypot history 15%, behavioral rate trust 15%, coordination signal 10%. All configurable. Hard overrides: physics forgery caps score at 0.10, blocklisted IPs cap at 0.05.

---

## Events

| Event | Payload |
|-------|---------|
| `scan` | `{ ip, type, severity, portCount }` |
| `honeypot` | `{ ip, port, banner, ts }` |
| `exfil` | `{ pid, processName, type, severity, remoteAddr }` |
| `dns-tunnel` | `{ domain, score, reasons }` |
| `campaign-detected` | `{ ip, score, stages, stageCount, severity }` |
| `threat-received` | `{ ip, eventType, severity, nodeId }` |
| `peer-joined` | `{ nodeId, address }` |
| `new-connection` | `{ remoteAddr, pid, commandLine, ppid }` |

---

## Config reference

```js
await Shield.create({
  scanner:     { portsPerWindow: 15, window: 10_000 },
  honeypot:    { auto: true, exclude: [80, 443] },
  exfil:       { uploadBytesPerMin: 10_000_000 },
  dns:         { entropyThreshold: 3.8, whitelist: ['compute.amazonaws.com'] },
  rateLimit:   { defaultRate: 100, window: 60_000 },
  mesh:        { port: 41338, peers: [], keyFile: './shield.json' },
  persistence: { path: './shield.db' },
  logging:     { file: './shield.ndjson', level: 'info', console: false },
});
```

---

## Requirements

Node.js 18+. 

Optional deps (install if you want the feature):
- `better-sqlite3` — for persistence
- `maxmind` — for GeoIP enrichment

---

## Security

We take the security of Shield seriously. If you've found a vulnerability, please do NOT create a public issue. Instead, send an email to **admin@svrnsys.com**. See [SECURITY.md](./SECURITY.md) for full details.

---

## License

MIT © Aaron Miller
