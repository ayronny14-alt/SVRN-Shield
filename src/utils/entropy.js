/**
 * Shannon entropy and related calculations for payload / DNS analysis.
 */

export function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const freq = new Float64Array(256);
  const len = buf.length;
  for (let i = 0; i < len; i++) freq[buf[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export function stringEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export function entropyRate(buf) {
  return buf.length === 0 ? 0 : shannonEntropy(buf) / 8;
}

export function isHighEntropy(buf, threshold = 7.2) {
  return shannonEntropy(buf) > threshold;
}

export function entropyGradient(chunks) {
  if (chunks.length < 2) return [];
  const vals = chunks.map(shannonEntropy);
  const grad = [];
  for (let i = 1; i < vals.length; i++) grad.push(vals[i] - vals[i - 1]);
  return grad;
}
