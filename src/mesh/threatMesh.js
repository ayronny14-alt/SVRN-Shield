/**
 * ThreatMesh — P2P threat intelligence sharing, zero external servers.
 *
 * Discovery:  UDP multicast (LAN) + Peer Exchange / PEX (public internet)
 * Data sync:  Newline-delimited JSON over persistent TCP connections
 * Crypto:     Ed25519 via node:crypto — every event is signed and verified
 *
 * Public internet usage: give one node another node's address. On connect,
 * nodes automatically exchange peer lists (PEX), so the full network
 * propagates with no central server or broker required.
 */

import { EventEmitter } from 'node:events';
import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { RingBuffer } from '../utils/ringBuffer.js';

const PROTOCOL_VERSION     = '1';
const DEFAULT_MC_GROUP     = '239.0.0.251';
const DEFAULT_MC_PORT      = 41337;
const DEFAULT_MAX_PEERS    = 50;
const DEFAULT_SYNC_HISTORY = 500;
const ANNOUNCE_INTERVAL    = 15_000;
const PEX_INTERVAL         = 60_000;    // re-share peer list every minute
const PEX_MAX_PEERS        = 20;        // max peers shared per PEX message
const PEX_COOLDOWN_MS      = 30_000;    // min gap between PEX messages per peer
const SEEN_EVENTS_CAP      = 10_000;
const MSG_SIZE_LIMIT       = 512 * 1024; // 512 KB per message — drops peer if exceeded
const SYNC_EVENTS_LIMIT    = 1_000;      // max events accepted in a single sync_data
const CONNECT_RATE_WINDOW  = 60_000;     // 1-minute window for inbound connection rate
const CONNECT_RATE_LIMIT   = 10;         // max new inbound connections per IP per window

// Strict IPv4/IPv6 validation — no hostnames, no injection vectors
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;
function isValidIP(host) {
  if (typeof host !== 'string') return false;
  return IPV4_RE.test(host) || IPV6_RE.test(host);
}
function isValidPort(port) {
  return Number.isInteger(port) && port > 0 && port < 65536;
}

// ── Key Management ─────────────────────────────────────────────────────────────

function loadOrGenerateKeyPair(keyFile) {
  if (keyFile) {
    try {
      const raw = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      const privateKey = crypto.createPrivateKey({
        key: Buffer.from(raw.privateKey, 'hex'),
        format: 'der', type: 'pkcs8',
      });
      const publicKey = crypto.createPublicKey({
        key: Buffer.from(raw.publicKey, 'hex'),
        format: 'der', type: 'spki',
      });
      return { privateKey, publicKey, publicKeyHex: raw.publicKey };
    } catch { /* fall through to generate */ }
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  const pubDer  = publicKey.export({ type: 'spki',  format: 'der' }).toString('hex');

  if (keyFile) {
    try {
      fs.mkdirSync(path.dirname(keyFile), { recursive: true });
      fs.writeFileSync(keyFile, JSON.stringify({ privateKey: privDer, publicKey: pubDer }), 'utf8');
    } catch { /* non-fatal — key won't persist */ }
  }

  return { privateKey, publicKey, publicKeyHex: pubDer };
}

// ── Crypto Helpers ──────────────────────────────────────────────────────────────

function signEvent(event, privateKey) {
  const payload = `${event.ip}|${event.eventType}|${event.severity}|${event.ts}|${event.nodeId}`;
  return crypto.sign(null, Buffer.from(payload), privateKey).toString('hex');
}

function verifyEvent(event) {
  try {
    const { ip, eventType, severity, ts, nodeId, sig, publicKey: pubHex } = event;
    if (!ip || !eventType || !severity || !ts || !nodeId || !sig || !pubHex) return false;
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(pubHex, 'hex'),
      format: 'der', type: 'spki',
    });
    const payload = `${ip}|${eventType}|${severity}|${ts}|${nodeId}`;
    return crypto.verify(null, Buffer.from(payload), pubKey, Buffer.from(sig, 'hex'));
  } catch {
    return false;
  }
}

// ── ThreatMesh ─────────────────────────────────────────────────────────────────

export class ThreatMesh extends EventEmitter {
  constructor(opts = {}) {
    super();

    this._port         = opts.port          || 0;
    this._mcGroup      = opts.multicastGroup || DEFAULT_MC_GROUP;
    this._mcPort       = opts.multicastPort  || DEFAULT_MC_PORT;
    this._manualPeers  = opts.peers          || [];
    this._maxPeers     = opts.maxPeers       || DEFAULT_MAX_PEERS;
    this._syncHistory  = opts.syncHistory    || DEFAULT_SYNC_HISTORY;

    // Identity
    const kp           = loadOrGenerateKeyPair(opts.keyFile);
    this._privateKey   = kp.privateKey;
    this._publicKeyHex = kp.publicKeyHex;
    this._nodeId       = crypto.createHash('sha256')
                               .update(kp.publicKeyHex)
                               .digest('hex')
                               .slice(0, 16);

    // State
    this._peers         = new Map();          // nodeId (or tempKey) → peer object
    this._eventHistory  = new RingBuffer(this._syncHistory);
    this._seenEvents    = new Set();          // dedupe by canonical hash
    this._knownAddrs    = new Set();          // 'host:port' strings learned via PEX
    this._connectRates  = new Map();          // ip → [{ts}] — inbound connection rate limiting
    this._tcpServer     = null;
    this._udpSocket     = null;
    this._announceTimer = null;
    this._pexTimer      = null;
    this._running       = false;

    this._counters = {
      eventsShared:   0,
      eventsReceived: 0,
      eventsRejected: 0,
      syncsCompleted: 0,
      peersDiscovered: 0,
    };
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────────

  async start() {
    if (this._running) return this;
    this._running = true;
    await this._startTCP();
    this._startMulticast();
    this._connectManualPeers();

    // Periodically re-broadcast peer list to all connected peers
    this._pexTimer = setInterval(() => this._broadcastPeerList(), PEX_INTERVAL);
    this._pexTimer.unref?.();

    return this;
  }

  stop() {
    this._running = false;

    clearInterval(this._announceTimer);
    clearInterval(this._pexTimer);
    this._announceTimer = null;
    this._pexTimer      = null;

    for (const peer of this._peers.values()) {
      try { peer.socket.destroy(); } catch {}
    }
    this._peers.clear();

    if (this._tcpServer) {
      this._tcpServer.close();
      this._tcpServer = null;
    }

    if (this._udpSocket) {
      try { this._udpSocket.dropMembership(this._mcGroup); } catch {}
      this._udpSocket.close();
      this._udpSocket = null;
    }
  }

  // ── Public API ────────────────────────────────────────────────────────────────

  /**
   * Broadcast a threat event to all peers.
   * @param {{ ip: string, eventType: string, severity: string }} event
   * @returns {object} The signed event that was shared
   */
  share(event) {
    const full = {
      ip:        event.ip,
      eventType: event.eventType,
      severity:  event.severity,
      ts:        Date.now(),
      nodeId:    this._nodeId,
      publicKey: this._publicKeyHex,
    };
    full.sig = signEvent(full, this._privateKey);

    this._seenEvents.add(this._hash(full));
    this._trimSeenEvents();
    this._eventHistory.push(full);
    this._counters.eventsShared++;

    for (const peer of this._peers.values()) {
      if (peer.ready) this._send(peer, { type: 'event', event: full });
    }

    this.emit('threat-shared', full);
    return full;
  }

  getPeers() {
    return [...this._peers.values()]
      .filter(p => p.ready)
      .map(p => ({
        nodeId:         p.nodeId,
        address:        p.address,
        port:           p.port,
        connectedAt:    p.connectedAt,
        eventsReceived: p.eventsReceived,
      }));
  }

  get nodeId() { return this._nodeId; }

  get stats() {
    return {
      module:         'ThreatMesh',
      nodeId:         this._nodeId,
      peers:          [...this._peers.values()].filter(p => p.ready).length,
      knownAddresses: this._knownAddrs.size,
      eventHistory:   this._eventHistory.size,
      ...this._counters,
    };
  }

  // ── TCP Server ────────────────────────────────────────────────────────────────

  _startTCP() {
    return new Promise((resolve, reject) => {
      this._tcpServer = net.createServer(socket => this._onIncomingSocket(socket));
      this._tcpServer.on('error', reject);
      this._tcpServer.listen(this._port, () => {
        this._port = this._tcpServer.address().port;
        resolve();
      });
    });
  }

  _onIncomingSocket(socket) {
    const addr = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';

    // Reject if at peer cap
    if (this._peers.size >= this._maxPeers) { socket.destroy(); return; }

    // Inbound connection rate limit per source IP
    const now = Date.now();
    const window = now - CONNECT_RATE_WINDOW;
    const times = (this._connectRates.get(addr) || []).filter(t => t > window);
    if (times.length >= CONNECT_RATE_LIMIT) { socket.destroy(); return; }
    times.push(now);
    this._connectRates.set(addr, times);

    const key  = `in:${addr}:${socket.remotePort}`;
    const peer = this._makePeer(null, addr, socket.remotePort, socket, key);
    this._peers.set(key, peer);
    this._attachHandlers(peer);
    this._send(peer, this._helloMsg());
  }

  // ── Outbound Connection ───────────────────────────────────────────────────────

  _connectPeer(host, port) {
    if (!this._running || this._peers.size >= this._maxPeers) return;

    // Deduplicate by address+port
    for (const p of this._peers.values()) {
      if (p.address === host && p.port === port) return;
    }

    const socket = net.createConnection({ host, port });
    const key    = `out:${host}:${port}`;
    const peer   = this._makePeer(null, host, port, socket, key);
    this._peers.set(key, peer);

    socket.on('connect', () => {
      this._attachHandlers(peer);
      this._send(peer, this._helloMsg());
    });

    socket.on('error', () => {
      this._peers.delete(key);
    });
  }

  _makePeer(nodeId, address, port, socket, tempKey) {
    return {
      nodeId, address, port, socket,
      tempKey,
      ready:          false,
      connectedAt:    Date.now(),
      eventsReceived: 0,
      _buf:           '',
      _lastPexAt:     0,
    };
  }

  _attachHandlers(peer) {
    const { socket } = peer;
    socket.setEncoding('utf8');
    socket.setNoDelay(true);

    socket.on('data', chunk => {
      peer._buf += chunk;
      // Hard cap — a legitimate node never needs to send more than 512 KB at once
      if (peer._buf.length > MSG_SIZE_LIMIT) {
        socket.destroy();
        return;
      }
      const lines = peer._buf.split('\n');
      peer._buf = lines.pop();
      for (const line of lines) {
        if (line.trim()) this._handleMessage(peer, line);
      }
    });

    socket.on('close', () => this._onDisconnect(peer));
    socket.on('error', () => this._onDisconnect(peer));
  }

  _onDisconnect(peer) {
    if (peer.tempKey) this._peers.delete(peer.tempKey);
    if (peer.nodeId)  this._peers.delete(peer.nodeId);
    if (peer.ready) {
      this.emit('peer-left', {
        nodeId: peer.nodeId,
        address: peer.address,
        port: peer.port,
      });
    }
  }

  // ── Wire Protocol ─────────────────────────────────────────────────────────────

  _send(peer, msg) {
    try {
      if (!peer.socket.destroyed) {
        peer.socket.write(JSON.stringify(msg) + '\n');
      }
    } catch { /* peer gone */ }
  }

  _helloMsg() {
    return {
      type:      'hello',
      nodeId:    this._nodeId,
      publicKey: this._publicKeyHex,
      port:      this._port,
      version:   PROTOCOL_VERSION,
    };
  }

  _handleMessage(peer, line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }

    switch (msg.type) {
      case 'hello':     return this._onHello(peer, msg);
      case 'peers':     return this._onPeers(peer, msg);
      case 'sync_req':  return this._onSyncReq(peer, msg);
      case 'sync_data': return this._onSyncData(peer, msg);
      case 'event':     return this._onEvent(peer, msg);
    }
  }

  _onHello(peer, msg) {
    if (msg.version !== PROTOCOL_VERSION) { peer.socket.destroy(); return; }

    // Reject self-connections
    if (msg.nodeId === this._nodeId) {
      peer.socket.destroy();
      if (peer.tempKey) this._peers.delete(peer.tempKey);
      return;
    }

    // Reject duplicate node
    if (this._peers.has(msg.nodeId)) {
      peer.socket.destroy();
      if (peer.tempKey) this._peers.delete(peer.tempKey);
      return;
    }

    // Promote: remove tempKey, register under nodeId
    if (peer.tempKey) this._peers.delete(peer.tempKey);
    peer.nodeId  = msg.nodeId;
    peer.tempKey = null;
    peer.ready   = true;
    this._peers.set(msg.nodeId, peer);

    this.emit('peer-joined', {
      nodeId:  peer.nodeId,
      address: peer.address,
      port:    peer.port,
    });

    // Request historical events
    const oldest = this._eventHistory.oldest();
    this._send(peer, { type: 'sync_req', since: oldest?.ts ?? 0 });

    // Share our peer list with the new peer (PEX)
    this._send(peer, this._peerListMsg());
  }

  _onPeers(peer, msg) {
    // Rate limit: ignore repeated PEX floods from the same peer
    const now = Date.now();
    if (peer._lastPexAt && now - peer._lastPexAt < PEX_COOLDOWN_MS) return;
    peer._lastPexAt = now;

    const list = Array.isArray(msg.peers) ? msg.peers.slice(0, PEX_MAX_PEERS) : [];
    for (const entry of list) {
      const { host, port } = entry || {};
      // Only accept numeric IPs — no hostnames that could trigger DNS lookups to attacker-controlled servers
      if (!isValidIP(host) || !isValidPort(port)) continue;
      const key = `${host}:${port}`;
      if (this._knownAddrs.has(key)) continue;
      this._knownAddrs.add(key);
      this._counters.peersDiscovered++;
      this._connectPeer(host, port);
    }
  }

  _peerListMsg() {
    const peers = [...this._peers.values()]
      .filter(p => p.ready && p.port)
      .slice(0, PEX_MAX_PEERS)
      .map(p => ({ host: p.address, port: p.port }));
    return { type: 'peers', peers };
  }

  _broadcastPeerList() {
    const msg = this._peerListMsg();
    if (msg.peers.length === 0) return;
    for (const peer of this._peers.values()) {
      if (peer.ready) this._send(peer, msg);
    }
  }

  _onSyncReq(peer, msg) {
    const since  = msg.since || 0;
    const events = this._eventHistory.toArray().filter(e => e.ts >= since);
    this._send(peer, { type: 'sync_data', events });
  }

  _onSyncData(peer, msg) {
    const events  = Array.isArray(msg.events) ? msg.events.slice(0, SYNC_EVENTS_LIMIT) : [];
    let   ingested = 0;
    for (const evt of events) {
      if (this._ingestFromPeer(peer, evt)) ingested++;
    }
    this._counters.syncsCompleted++;
    this.emit('sync-complete', {
      nodeId:   peer.nodeId,
      received: events.length,
      ingested,
    });
  }

  _onEvent(peer, msg) {
    this._ingestFromPeer(peer, msg.event);
  }

  // ── Event Ingestion ───────────────────────────────────────────────────────────

  _ingestFromPeer(peer, event) {
    if (!this._ingest(event)) return false;
    peer.eventsReceived++;
    return true;
  }

  _ingest(event) {
    if (!event) return false;

    const hash = this._hash(event);
    if (this._seenEvents.has(hash)) return false;

    if (!verifyEvent(event)) {
      this._counters.eventsRejected++;
      return false;
    }

    this._seenEvents.add(hash);
    this._trimSeenEvents();
    this._eventHistory.push(event);
    this._counters.eventsReceived++;

    this.emit('threat-received', event);
    return true;
  }

  _hash(event) {
    return `${event.nodeId}|${event.ts}|${event.eventType}|${event.ip}`;
  }

  _trimSeenEvents() {
    if (this._seenEvents.size > SEEN_EVENTS_CAP) {
      // Remove oldest entries (Sets preserve insertion order)
      const toDelete = this._seenEvents.size - (SEEN_EVENTS_CAP / 2);
      let i = 0;
      for (const key of this._seenEvents) {
        if (i++ >= toDelete) break;
        this._seenEvents.delete(key);
      }
    }
  }

  // ── UDP Multicast ─────────────────────────────────────────────────────────────

  _startMulticast() {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this._udpSocket = sock;

    sock.on('message', (buf, rinfo) => {
      try {
        const ann = JSON.parse(buf.toString('utf8'));
        if (ann.type !== 'announce' || ann.nodeId === this._nodeId) return;
        if (typeof ann.port !== 'number') return;
        this._connectPeer(rinfo.address, ann.port);
      } catch { /* malformed, ignore */ }
    });

    sock.on('error', () => { /* multicast failure is non-fatal */ });

    sock.bind(this._mcPort, () => {
      try {
        sock.addMembership(this._mcGroup);
        sock.setMulticastTTL(1);
        sock.setMulticastLoopback(false);
      } catch { /* no multicast on this interface — WAN peers still work */ }

      this._sendAnnounce();
      this._announceTimer = setInterval(() => this._sendAnnounce(), ANNOUNCE_INTERVAL);
      this._announceTimer.unref?.();
    });
  }

  _sendAnnounce() {
    if (!this._udpSocket || !this._running) return;
    const buf = Buffer.from(JSON.stringify({
      type:   'announce',
      nodeId: this._nodeId,
      port:   this._port,
    }));
    try {
      this._udpSocket.send(buf, 0, buf.length, this._mcPort, this._mcGroup);
    } catch { /* ignore */ }
  }

  // ── Manual WAN Peers ──────────────────────────────────────────────────────────

  _connectManualPeers() {
    for (const peerStr of this._manualPeers) {
      const lastColon = peerStr.lastIndexOf(':');
      if (lastColon === -1) continue;
      const host = peerStr.slice(0, lastColon);
      const port = parseInt(peerStr.slice(lastColon + 1), 10);
      // Manual peers may be hostnames (user-configured, trusted) — allow them
      // but still validate port to avoid garbage
      if (!host || !isValidPort(port)) continue;
      this._knownAddrs.add(`${host}:${port}`);
      this._connectPeer(host, port);
    }
  }
}
