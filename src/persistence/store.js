/**
 * SQLite persistence layer for Shield.
 *
 * Optional — when enabled, persists:
 *   - Threat intel reputation scores and events
 *   - Alert history
 *   - Kill chain state
 *   - ThreatMesh event archive
 *
 * Uses better-sqlite3 for synchronous, zero-overhead writes with WAL mode.
 * Persistence is OFF by default. Enable via:
 *   Shield.create({ persistence: { path: './shield.db' } })
 */

let Database;

export class PersistenceStore {
  constructor(opts = {}) {
    this._path = opts.path || ':memory:';
    this._db = null;
    this._ready = false;
    this._stmts = {};
  }

  async open() {
    // Dynamic import so better-sqlite3 is only required when persistence is enabled
    if (!Database) {
      try {
        const mod = await import('better-sqlite3');
        Database = mod.default || mod;
      } catch {
        throw new Error(
          '[Shield Persistence] better-sqlite3 is required for persistence. ' +
          'Install it: npm install better-sqlite3'
        );
      }
    }

    this._db = new Database(this._path);
    this._db.pragma('journal_mode = WAL');
    this._db.pragma('synchronous = NORMAL');
    this._db.pragma('foreign_keys = ON');
    this._createTables();
    this._prepareStatements();
    this._ready = true;
    return this;
  }

  _createTables() {
    this._db.exec(`
      CREATE TABLE IF NOT EXISTS alerts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        INTEGER NOT NULL,
        type      TEXT NOT NULL,
        severity  TEXT NOT NULL,
        ip        TEXT,
        detail    TEXT,
        module    TEXT,
        created   TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
      CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
      CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);

      CREATE TABLE IF NOT EXISTS reputation (
        ip         TEXT PRIMARY KEY,
        score      REAL NOT NULL DEFAULT 0.5,
        events     INTEGER NOT NULL DEFAULT 0,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        classification TEXT,
        detail     TEXT
      );

      CREATE TABLE IF NOT EXISTS threat_events (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        INTEGER NOT NULL,
        ip        TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity  TEXT NOT NULL,
        source    TEXT DEFAULT 'local',
        node_id   TEXT,
        detail    TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_events_ip ON threat_events(ip);
      CREATE INDEX IF NOT EXISTS idx_events_ts ON threat_events(ts);

      CREATE TABLE IF NOT EXISTS kill_chains (
        ip         TEXT PRIMARY KEY,
        score      REAL NOT NULL DEFAULT 0,
        stages     TEXT NOT NULL DEFAULT '{}',
        events     TEXT NOT NULL DEFAULT '[]',
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        alerted    INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS mesh_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         INTEGER NOT NULL,
        ip         TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity   TEXT NOT NULL,
        node_id    TEXT NOT NULL,
        sig        TEXT,
        public_key TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_mesh_ts ON mesh_events(ts);

      CREATE TABLE IF NOT EXISTS forensics (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER NOT NULL,
        ip      TEXT NOT NULL,
        port    INTEGER,
        banner  TEXT,
        detail  TEXT NOT NULL,
        created TEXT DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_forensics_ip ON forensics(ip);
      CREATE INDEX IF NOT EXISTS idx_forensics_ts ON forensics(ts);
    `);
  }

  _prepareStatements() {
    this._stmts = {
      insertAlert: this._db.prepare(`
        INSERT INTO alerts (ts, type, severity, ip, detail, module)
        VALUES (?, ?, ?, ?, ?, ?)
      `),

      queryAlerts: this._db.prepare(`
        SELECT * FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?
      `),

      queryAlertsByIP: this._db.prepare(`
        SELECT * FROM alerts WHERE ip = ? ORDER BY ts DESC LIMIT ?
      `),

      upsertReputation: this._db.prepare(`
        INSERT INTO reputation (ip, score, events, first_seen, last_seen, classification, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          score = excluded.score,
          events = excluded.events,
          last_seen = excluded.last_seen,
          classification = excluded.classification,
          detail = excluded.detail
      `),

      getReputation: this._db.prepare(`
        SELECT * FROM reputation WHERE ip = ?
      `),

      insertThreatEvent: this._db.prepare(`
        INSERT INTO threat_events (ts, ip, event_type, severity, source, node_id, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `),

      upsertKillChain: this._db.prepare(`
        INSERT INTO kill_chains (ip, score, stages, events, first_seen, last_seen, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          score = excluded.score,
          stages = excluded.stages,
          events = excluded.events,
          last_seen = excluded.last_seen,
          alerted = excluded.alerted
      `),

      getKillChain: this._db.prepare(`
        SELECT * FROM kill_chains WHERE ip = ?
      `),

      getAllKillChains: this._db.prepare(`
        SELECT * FROM kill_chains ORDER BY score DESC LIMIT ?
      `),

      insertMeshEvent: this._db.prepare(`
        INSERT INTO mesh_events (ts, ip, event_type, severity, node_id, sig, public_key)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `),

      getMeshEvents: this._db.prepare(`
        SELECT * FROM mesh_events WHERE ts >= ? ORDER BY ts DESC LIMIT ?
      `),

      countAlerts: this._db.prepare(`SELECT COUNT(*) as count FROM alerts`),
      countEvents: this._db.prepare(`SELECT COUNT(*) as count FROM threat_events`),
      countReputations: this._db.prepare(`SELECT COUNT(*) as count FROM reputation`),

      insertForensics: this._db.prepare(`
        INSERT INTO forensics (ts, ip, port, banner, detail)
        VALUES (?, ?, ?, ?, ?)
      `),
      getForensics: this._db.prepare(`
        SELECT * FROM forensics WHERE ip = ? ORDER BY ts DESC LIMIT ?
      `),
    };
  }

  // ── Alert Persistence ────────────────────────────────────────

  saveAlert(alert) {
    if (!this._ready) return;
    this._stmts.insertAlert.run(
      alert.ts || Date.now(),
      alert.type,
      alert.severity,
      alert.ip || null,
      JSON.stringify(alert),
      alert.module || null,
    );
  }

  getAlerts(opts = {}) {
    if (!this._ready) return [];
    const since = opts.since || 0;
    const limit = opts.limit || 100;
    if (opts.ip) {
      return this._stmts.queryAlertsByIP.all(opts.ip, limit)
        .map(r => ({ ...r, detail: JSON.parse(r.detail || '{}') }));
    }
    return this._stmts.queryAlerts.all(since, limit)
      .map(r => ({ ...r, detail: JSON.parse(r.detail || '{}') }));
  }

  // ── Reputation Persistence ───────────────────────────────────

  saveReputation(ip, data) {
    if (!this._ready) return;
    this._stmts.upsertReputation.run(
      ip,
      data.score,
      data.totalEvents || 0,
      data.firstSeen || Date.now(),
      data.lastSeen || Date.now(),
      data.classification || null,
      JSON.stringify(data.events?.slice(-20) || []),
    );
  }

  getReputation(ip) {
    if (!this._ready) return null;
    const row = this._stmts.getReputation.get(ip);
    if (!row) return null;
    return {
      ...row,
      detail: JSON.parse(row.detail || '[]'),
    };
  }

  // ── Threat Event Persistence ─────────────────────────────────

  saveThreatEvent(event) {
    if (!this._ready) return;
    this._stmts.insertThreatEvent.run(
      event.ts || Date.now(),
      event.ip,
      event.eventType || event.type,
      event.severity,
      event.source || 'local',
      event.nodeId || null,
      JSON.stringify(event),
    );
  }

  // ── Kill Chain Persistence ───────────────────────────────────

  saveKillChain(chain) {
    if (!this._ready) return;
    this._stmts.upsertKillChain.run(
      chain.ip,
      chain.score,
      JSON.stringify(chain.stages || {}),
      JSON.stringify(chain.events?.slice(-200) || []),
      chain.firstSeen || Date.now(),
      chain.lastSeen || Date.now(),
      chain.alerted ? 1 : 0,
    );
  }

  getKillChain(ip) {
    if (!this._ready) return null;
    const row = this._stmts.getKillChain.get(ip);
    if (!row) return null;
    return {
      ...row,
      stages: JSON.parse(row.stages),
      events: JSON.parse(row.events),
      alerted: !!row.alerted,
    };
  }

  getActiveKillChains(limit = 100) {
    if (!this._ready) return [];
    return this._stmts.getAllKillChains.all(limit).map(row => ({
      ...row,
      stages: JSON.parse(row.stages),
      events: JSON.parse(row.events),
      alerted: !!row.alerted,
    }));
  }

  // ── Mesh Event Persistence ───────────────────────────────────

  saveMeshEvent(event) {
    if (!this._ready) return;
    this._stmts.insertMeshEvent.run(
      event.ts || Date.now(),
      event.ip,
      event.eventType,
      event.severity,
      event.nodeId,
      event.sig || null,
      event.publicKey || null,
    );
  }

  getMeshEvents(opts = {}) {
    if (!this._ready) return [];
    return this._stmts.getMeshEvents.all(opts.since || 0, opts.limit || 100);
  }

  // ── Forensic Persistence ────────────────────────────────────

  saveForensicRecord(record) {
    if (!this._ready) return;
    this._stmts.insertForensics.run(
      record.ts || Date.now(),
      record.ip,
      record.port || null,
      record.banner || null,
      JSON.stringify(record),
    );
  }

  getForensics(ip, limit = 50) {
    if (!this._ready) return [];
    return this._stmts.getForensics.all(ip, limit).map(row => ({
      ...row,
      detail: JSON.parse(row.detail),
    }));
  }

  // ── Stats ────────────────────────────────────────────────────

  get stats() {
    if (!this._ready) return { ready: false };
    return {
      ready: true,
      path: this._path,
      alerts: this._stmts.countAlerts.get().count,
      threatEvents: this._stmts.countEvents.get().count,
      reputations: this._stmts.countReputations.get().count,
    };
  }

  // ── Lifecycle ────────────────────────────────────────────────

  close() {
    if (this._db) {
      this._db.close();
      this._db = null;
      this._ready = false;
    }
  }

  vacuum() {
    if (this._ready) this._db.exec('VACUUM');
  }
}
