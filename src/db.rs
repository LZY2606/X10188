use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS source (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                       -- pack | idx | loose
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    path TEXT NOT NULL,
    version INTEGER,
    object_count INTEGER,
    pack_checksum_hex TEXT,
    stored_checksum_hex TEXT,
    checksum_ok INTEGER,
    parse_status TEXT NOT NULL,
    parse_detail TEXT NOT NULL DEFAULT '',
    pair_source_id INTEGER REFERENCES source(id),
    pairing_note TEXT NOT NULL DEFAULT '',
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS candidate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
    pack_offset INTEGER,
    declared_oid_hex TEXT,
    computed_oid_hex TEXT,
    obj_type TEXT NOT NULL,
    claimed_size INTEGER NOT NULL DEFAULT 0,
    inflated_size INTEGER NOT NULL DEFAULT 0,
    compressed_len INTEGER NOT NULL DEFAULT 0,
    header_len INTEGER NOT NULL DEFAULT 0,
    entry_crc32 INTEGER,
    idx_crc32 INTEGER,
    crc_ok INTEGER,
    ofs_base_offset INTEGER,
    ref_base_oid_hex TEXT,
    parse_status TEXT NOT NULL,
    parse_detail TEXT NOT NULL DEFAULT '',
    pinned INTEGER NOT NULL DEFAULT 0,
    UNIQUE(source_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS resolution (
    candidate_id INTEGER PRIMARY KEY REFERENCES candidate(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    resolved_type TEXT,
    content_len INTEGER NOT NULL DEFAULT 0,
    content_path TEXT,
    oid_hex TEXT,
    oid_match INTEGER,
    depth INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    blockers_json TEXT NOT NULL DEFAULT '[]',
    steps_json TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS candidate_edge (
    from_candidate_id INTEGER NOT NULL REFERENCES candidate(id) ON DELETE CASCADE,
    to_candidate_id INTEGER,           -- resolved at build time if same source
    to_oid_hex TEXT,                   -- declared base identity for ref-deltas
    to_offset INTEGER,                 -- ofs-delta absolute offset
    kind TEXT NOT NULL,                -- ofs | ref
    PRIMARY KEY (from_candidate_id)
);

CREATE TABLE IF NOT EXISTS budget_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    used_bytes INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO budget_usage(id, used_bytes) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS setting (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidate_source ON candidate(source_id);
CREATE INDEX IF NOT EXISTS idx_candidate_decl ON candidate(declared_oid_hex);
CREATE INDEX IF NOT EXISTS idx_candidate_comp ON candidate(computed_oid_hex);
CREATE INDEX IF NOT EXISTS idx_edge_to ON candidate_edge(to_candidate_id);
CREATE INDEX IF NOT EXISTS idx_edge_to_oid ON candidate_edge(to_oid_hex);
"#;

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    pub fn open_in_dir(dir: &Path) -> Result<Db> {
        std::fs::create_dir_all(dir)?;
        Db::open(&dir.join("microscope.db"))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("db mutex poisoned")
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let c = self.lock();
        Ok(c
            .query_row(
                "SELECT value FROM setting WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO setting(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn used_bytes(&self) -> Result<u64> {
        let c = self.lock();
        Ok(c.query_row("SELECT used_bytes FROM budget_usage WHERE id = 1", [], |r| {
            r.get::<_, i64>(0)
        })? as u64)
    }

    pub fn set_used_bytes(&self, v: u64) -> Result<()> {
        let c = self.lock();
        c.execute("UPDATE budget_usage SET used_bytes = ?1 WHERE id = 1", params![v as i64])?;
        Ok(())
    }

    pub fn reset_usage(&self) -> Result<()> {
        self.set_used_bytes(0)
    }

    pub fn ensure_no_tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let c = self.lock();
        f(&c)
    }
}

/// Map rusqlite errors to our error type.
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Io(format!("sqlite: {e}"))
    }
}
