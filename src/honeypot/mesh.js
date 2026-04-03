import net from 'node:net';
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import { getBanner, listBanners } from './banners.js';

export class HoneypotMesh extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._ports = opts.ports || [];
    this._autoAssign = opts.auto !== false;
    this._excludePorts = new Set(opts.exclude || []);
    this._maxConnectionTime = opts.maxConnectionTime || 30_000;
    this._servers = new Map();
    this._connections = new Map();
    this._stats = { totalConnections: 0, uniqueIPs: new Set(), byPort: {} };
    this._portAssignments = new Map(); // port -> banner type
  }

  assignPorts(openPorts) {
    if (!this._autoAssign) return this._ports;

    const serviceMap = { 22: 'ssh', 80: 'http', 443: 'https', 21: 'ftp', 25: 'smtp', 23: 'telnet', 3306: 'mysql', 6379: 'redis', 53: 'dns' };
    const decoyPorts = [];
    const usedPorts = new Set(openPorts);

    // place decoys near real services
    for (const [port, service] of Object.entries(serviceMap)) {
      const p = parseInt(port, 10);
      if (usedPorts.has(p) || this._excludePorts.has(p)) continue;
      decoyPorts.push({ port: p, banner: service });
    }

    // add some random high ports with http/ssh banners
    const highPortBanners = ['http', 'ssh', 'redis', 'mysql'];
    const candidates = [8080, 8443, 8888, 9090, 9999, 2222, 3000, 4000, 5000, 6000, 7000];
    for (const p of candidates) {
      if (usedPorts.has(p) || this._excludePorts.has(p)) continue;
      const banner = highPortBanners[decoyPorts.length % highPortBanners.length];
      decoyPorts.push({ port: p, banner });
      if (decoyPorts.length >= 20) break;
    }

    // merge with explicit ports
    for (const p of this._ports) {
      if (!usedPorts.has(p) && !decoyPorts.some(d => d.port === p)) {
        decoyPorts.push({ port: p, banner: 'http' });
      }
    }

    return decoyPorts;
  }

  async start(openPorts = []) {
    const decoys = this.assignPorts(openPorts);

    for (const { port, banner } of decoys) {
      try {
        const bannerDef = getBanner(banner);
        if (!bannerDef) continue;

        if (bannerDef.proto === 'udp') {
          await this._startUDP(port, bannerDef, banner);
        } else {
          await this._startTCP(port, bannerDef, banner);
        }
        this._portAssignments.set(port, banner);
      } catch (err) {
        this.emit('port-error', { port, banner, error: err.message });
      }
    }

    this.emit('started', {
      ports: [...this._portAssignments.entries()].map(([port, banner]) => ({ port, banner })),
      count: this._portAssignments.size,
    });

    return this;
  }

  _startTCP(port, bannerDef, bannerName) {
    return new Promise((resolve, reject) => {
      const server = net.createServer((socket) => {
        const ip = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        const connId = `${ip}:${socket.remotePort}`;
        const connStart = Date.now();

        this._stats.totalConnections++;
        this._stats.uniqueIPs.add(ip);
        this._stats.byPort[port] = (this._stats.byPort[port] || 0) + 1;

        
        const connInfo = {
          ip,
          port,
          banner: bannerName,
          remotePort: socket.remotePort,
          startTime: connStart,
          bytesReceived: 0,
          bytesSent: 0,
          exchanges: 0,
        };
        this._connections.set(connId, connInfo);

        this.emit('connection', {
          ip, port, banner: bannerName,
          ts: connStart,
        });

        // send greeting if applicable
        if (bannerDef.greeting) {
          const greeting = typeof bannerDef.greeting === 'string'
            ? Buffer.from(bannerDef.greeting)
            : bannerDef.greeting;
          socket.write(greeting);
          connInfo.bytesSent += greeting.length;
        }

        // track data exchanges
        const bannerInstance = { ...bannerDef, _sentLogin: false, _sentPassword: false };
        socket.on('data', (chunk) => {
          connInfo.bytesReceived += chunk.length;
          connInfo.exchanges++;

          this.emit('data', {
            ip, port, banner: bannerName,
            bytes: chunk.length,
            preview: chunk.toString('utf8', 0, Math.min(chunk.length, 64)).replace(/[^\x20-\x7E]/g, '.'),
          });

          const result = bannerInstance.respond(chunk);
          const response = result?.response || (Buffer.isBuffer(result) ? result : null);
          const meta = result?.meta || null;

          if (meta) {
            this.emit('forensics', { ip, port, banner: bannerName, ...meta });
            connInfo.meta = { ...(connInfo.meta || {}), ...meta };
          }

          if (response) {
            socket.write(response);
            connInfo.bytesSent += response.length;
          }
        });

        // force-close after timeout (waste attacker's time, but not forever)
        const timeout = setTimeout(() => {
          socket.destroy();
        }, this._maxConnectionTime);

        socket.on('close', () => {
          clearTimeout(timeout);
          connInfo.duration = Date.now() - connStart;
          this._connections.delete(connId);

          this.emit('disconnect', {
            ip, port, banner: bannerName,
            duration: connInfo.duration,
            bytesReceived: connInfo.bytesReceived,
            bytesSent: connInfo.bytesSent,
            exchanges: connInfo.exchanges,
          });
        });

        socket.on('error', () => {
          clearTimeout(timeout);
          this._connections.delete(connId);
        });
      });

      server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          this.emit('port-in-use', { port, banner: bannerName });
          resolve();
        } else {
          reject(err);
        }
      });

      server.listen(port, () => {
        this._servers.set(port, server);
        resolve();
      });
    });
  }

  _startUDP(port, bannerDef, bannerName) {
    return new Promise((resolve, reject) => {
      const server = dgram.createSocket('udp4');

      server.on('message', (msg, rinfo) => {
        const ip = rinfo.address;
        this._stats.totalConnections++;
        this._stats.uniqueIPs.add(ip);
        this._stats.byPort[port] = (this._stats.byPort[port] || 0) + 1;


        this.emit('connection', {
          ip, port, banner: bannerName, proto: 'udp',
          ts: Date.now(),
        });

        const response = bannerDef.respond(msg);
        if (response) {
          server.send(response, rinfo.port, rinfo.address);
        }
      });

      server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          resolve();
        } else {
          reject(err);
        }
      });

      server.bind(port, () => {
        this._servers.set(port, server);
        resolve();
      });
    });
  }

  stop() {
    for (const [port, server] of this._servers) {
      if (server.close) server.close();
    }
    this._servers.clear();
    this._portAssignments.clear();
    this.emit('stopped');
  }

  get activePorts() {
    return [...this._portAssignments.entries()].map(([port, banner]) => ({ port, banner }));
  }

  get stats() {
    return {
      module: 'HoneypotMesh',
      ...this._stats,
      uniqueIPs: this._stats.uniqueIPs.size,
      activePorts: this._portAssignments.size,
      activeConnections: this._connections.size,
    };
  }

  getConnectionInfo(ip) {
    const conns = [];
    for (const [id, info] of this._connections) {
      if (info.ip === ip) conns.push(info);
    }
    return conns;
  }
}
