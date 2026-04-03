/**
 * Compact bitfield for tracking port access (65536 ports).
 */
export class PortBitfield {
  constructor() {
    this._bits = new Uint32Array(2048); // 65536 / 32
    this._count = 0;
  }

  get count() { return this._count; }

  set(port) {
    const idx = port >>> 5;
    const bit = 1 << (port & 31);
    if (!(this._bits[idx] & bit)) {
      this._bits[idx] |= bit;
      this._count++;
      return true;
    }
    return false;
  }

  has(port) {
    return !!(this._bits[port >>> 5] & (1 << (port & 31)));
  }

  clear() {
    this._bits.fill(0);
    this._count = 0;
  }

  listSet() {
    const ports = [];
    for (let w = 0; w < 2048; w++) {
      if (this._bits[w] === 0) continue;
      for (let b = 0; b < 32; b++) {
        if (this._bits[w] & (1 << b)) ports.push((w << 5) | b);
      }
    }
    return ports;
  }

  union(other) {
    const result = new PortBitfield();
    for (let i = 0; i < 2048; i++) {
      result._bits[i] = this._bits[i] | other._bits[i];
    }
    result._count = result.listSet().length;
    return result;
  }

  intersection(other) {
    const result = new PortBitfield();
    for (let i = 0; i < 2048; i++) {
      result._bits[i] = this._bits[i] & other._bits[i];
    }
    result._count = result.listSet().length;
    return result;
  }
}
