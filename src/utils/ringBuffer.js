/**
 * Fixed-size circular buffer for streaming window operations.
 */
export class RingBuffer {
  constructor(capacity = 1024) {
    this._buf = new Array(capacity);
    this._cap = capacity;
    this._head = 0;
    this._size = 0;
  }

  get size() { return this._size; }
  get capacity() { return this._cap; }
  get full() { return this._size === this._cap; }

  push(item) {
    this._buf[this._head] = item;
    this._head = (this._head + 1) % this._cap;
    if (this._size < this._cap) this._size++;
    return this;
  }

  peek() {
    if (this._size === 0) return undefined;
    return this._buf[(this._head - 1 + this._cap) % this._cap];
  }

  oldest() {
    if (this._size === 0) return undefined;
    const start = (this._head - this._size + this._cap) % this._cap;
    return this._buf[start];
  }

  toArray() {
    const arr = new Array(this._size);
    const start = (this._head - this._size + this._cap) % this._cap;
    for (let i = 0; i < this._size; i++) {
      arr[i] = this._buf[(start + i) % this._cap];
    }
    return arr;
  }

  clear() {
    this._head = 0;
    this._size = 0;
    return this;
  }

  *[Symbol.iterator]() {
    const start = (this._head - this._size + this._cap) % this._cap;
    for (let i = 0; i < this._size; i++) {
      yield this._buf[(start + i) % this._cap];
    }
  }

  filter(fn) {
    const result = [];
    for (const item of this) {
      if (fn(item)) result.push(item);
    }
    return result;
  }

  countWhere(fn) {
    let c = 0;
    for (const item of this) if (fn(item)) c++;
    return c;
  }
}
