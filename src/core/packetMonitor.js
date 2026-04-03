import { EventEmitter } from 'node:events';

/**
 * Passive Packet Monitor (optional libpcap-based detection).
 * 
 * This module attempts to use 'cap' or 'node-pcap' to sniff raw traffic.
 * If dev dependencies aren't present, it stays dormant.
 */
export class PacketMonitor extends EventEmitter {
  constructor(opts = {}) {
    super();
    this._opts = {
      interface: opts.interface || 'any',
      filter:    opts.filter    || 'tcp or udp',
      ...opts
    };
    this._pcap = null;
    this._active = false;
  }

  async start() {
    try {
      // Try to load 'cap' (most stable in Node 18+)
      const { Cap } = await import('cap');
      this._pcap = new Cap();
      
      const device = this._opts.interface === 'any' 
        ? Cap.findDevice() 
        : this._opts.interface;

      const filter = this._opts.filter;
      const bufSize = 10 * 1024 * 1024;
      const buffer = Buffer.alloc(65535);

      const linkType = this._pcap.open(device, filter, bufSize, buffer);
      this._pcap.setMinBytes && this._pcap.setMinBytes(0);

      this._pcap.on('packet', (nbytes, trunc) => {
        if (linkType === 'ETHERNET') {
          this._processEthernet(buffer.slice(0, nbytes));
        }
      });

      this._active = true;
      return true;
    } catch (err) {
      // Graceful fallback if no pcap lib is present
      return false;
    }
  }

  _processEthernet(buf) {
    // Basic IP/TCP/UDP parsing
    // [Ethernet: 14] [IP: 20] [TCP: 20]
    if (buf.length < 34) return;
    
    const etherType = buf.readUInt16BE(12);
    if (etherType !== 0x0800) return; // Only IPv4 for now

    const ihl = (buf[14] & 0x0f) * 4;
    if (buf.length < 14 + ihl) return;

    const proto = buf[14 + 9];
    const srcIp = `${buf[14+12]}.${buf[14+13]}.${buf[14+14]}.${buf[14+15]}`;
    const dstIp = `${buf[14+16]}.${buf[14+17]}.${buf[14+18]}.${buf[14+19]}`;

    if (proto === 6 && buf.length >= 14 + ihl + 20) { // TCP
      const srcPort = buf.readUInt16BE(14 + ihl);
      const dstPort = buf.readUInt16BE(14 + ihl + 2);
      const flags = buf[14 + ihl + 13];
      
      this.emit('packet', {
        proto: 'tcp',
        srcIp, dstIp, srcPort, dstPort,
        flags: {
          syn: !!(flags & 0x02),
          ack: !!(flags & 0x10),
          fin: !!(flags & 0x01),
          rst: !!(flags & 0x04),
          psh: !!(flags & 0x08),
          urg: !!(flags & 0x20),
        },
        length: buf.length,
        payload: buf.slice(14 + ihl + 20)
      });
    } else if (proto === 17 && buf.length >= 14 + ihl + 8) { // UDP
      const srcPort = buf.readUInt16BE(14 + ihl);
      const dstPort = buf.readUInt16BE(14 + ihl + 2);
      
      this.emit('packet', {
        proto: 'udp',
        srcIp, dstIp, srcPort, dstPort,
        length: buf.length,
        payload: buf.slice(14 + ihl + 8)
      });
    }
  }

  get active() { return this._active; }
}
