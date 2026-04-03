/**
 * Online Welford's algorithm for computing running mean and standard deviation.
 * Used for adaptive thresholds and behavioral baselining.
 */
export class BehavioralBaseline {
  constructor() {
    this.samples = 0;
    this.mean = 0;
    this.m2 = 0;
    this.stddev = 0;
    this.lastRefined = Date.now();
  }

  update(value) {
    this.samples++;
    const delta = value - this.mean;
    this.mean += delta / this.samples;
    const delta2 = value - this.mean;
    this.m2 += delta * delta2;
    this.stddev = this.samples > 1 ? Math.sqrt(this.m2 / (this.samples - 1)) : 0;
    this.lastRefined = Date.now();
    return this;
  }

  get threshold() {
    // 3 sigma (standard deviations) covers 99.7% of normal behavior
    return this.mean + this.stddev * 3;
  }

  isAnomalous(value, sensitivity = 3) {
    if (this.samples < 10) return false; // wait for enough data
    return value > this.mean + this.stddev * sensitivity;
  }

  toJSON() {
    return {
      samples: this.samples,
      mean: Math.round(this.mean * 100) / 100,
      stddev: Math.round(this.stddev * 100) / 100,
      threshold: Math.round(this.threshold * 100) / 100,
    };
  }
}
