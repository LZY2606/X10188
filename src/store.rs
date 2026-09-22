//! SQLite persistence. All imported bytes live under the project data
//! directory; the database only stores metadata, evidence, resolution
//! state and delta-step audit records.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const DEFAULT_MAX_DEPTH: i64 = 16;
pub const DEFAULT_MAX_TOTAL_EXPANDED: i64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_SINGLE_RATIO: f64 = 256.0;

pub struct Store {
    pub conn: Connection,
}

pub fn open_or_init(db_path: &Path) -> rusqlite::Result<Store> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    let mut store = Store { conn };
    store.migrate()?;
    Ok(store)
}

impl Store {
    fn migrate(&mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                kind TEXT NOT NULL,           -- pack | idx | loose
                sha256 TEXT NOT NULL UNIQUE,
                byte_len INTEGER NOT NULL,
                stored_path TEXT NOT NULL,
                pack_version INTEGER,
                pack_object_count INTEGER,
                trailer_ok INTEGER,
                fanout TEXT,                  -- JSON array of 256 counts (idx)
                linked_pack_sha TEXT,          -- idx: git checksum of matched pack
                pack_checksum TEXT,            -- pack: git pack checksum
                imported_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS idx_anchors (
                id INTEGER PRIMARY KEY,
                idx_source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                oid TEXT NOT NULL,
                offset INTEGER NOT NULL,
                crc32 INTEGER NOT NULL,
                matched_candidate_id INTEGER,
                UNIQUE(idx_source_id, offset)
            );

            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,           -- pack | loose | anchor
                "offset" INTEGER NOT NULL DEFAULT -1,
                oid TEXT,                     -- null until assigned (deltas)
                obj_type TEXT,
                declared_size INTEGER NOT NULL DEFAULT 0,
                actual_size INTEGER NOT NULL DEFAULT 0,
                zlib_ok INTEGER NOT NULL DEFAULT 1,
                size_ok INTEGER NOT NULL DEFAULT 1,
                crc_ok INTEGER,
                hash_ok INTEGER,
                base_offset INTEGER,
                ofs_distance INTEGER,
                ref_base TEXT,
                inflated BLOB,
                sort_key TEXT NOT NULL DEFAULT '',
                UNIQUE(source_id, "offset", kind)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY,
                severity TEXT NOT NULL,      -- error | warning | info
                code TEXT NOT NULL,
                message TEXT NOT NULL,
                source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
                candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
                "offset" INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS branches (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS branch_pins (
                branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
                oid TEXT NOT NULL,
                candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                PRIMARY KEY (branch_id, oid)
            );

            CREATE TABLE IF NOT EXISTS resolutions (
                candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                oid TEXT,
                obj_type TEXT,
                size INTEGER NOT NULL DEFAULT 0,
                content_key TEXT,
                hash_ok INTEGER,
                reason TEXT,
                blocked_chain TEXT NOT NULL DEFAULT '[]',
                recompute_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (candidate_id, branch_id)
            );

            CREATE TABLE IF NOT EXISTS content_cache (
                content_key TEXT PRIMARY KEY,  -- sha1 hex of stored bytes
                content BLOB NOT NULL,
                byte_len INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS delta_steps (
                candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
                step_index INTEGER NOT NULL,
                kind TEXT NOT NULL,
                insn_start INTEGER NOT NULL,
                insn_end INTEGER NOT NULL,
                src_start INTEGER,
                src_len INTEGER,
                out_start INTEGER NOT NULL,
                out_end INTEGER NOT NULL,
                base_oid TEXT,
                base_input_len INTEGER NOT NULL,
                result_len INTEGER NOT NULL,
                verified INTEGER NOT NULL,
                PRIMARY KEY (candidate_id, branch_id, step_index)
            );

            CREATE TABLE IF NOT EXISTS engine_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        let exists: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM branches WHERE id = 1", [], |r| r.get(0))?;
        if exists == 0 {
            self.conn.execute(
                "INSERT INTO branches(id, name) VALUES(1, '默认分支')",
                [],
            )?;
        }
        self.ensure_kv("max_depth", &DEFAULT_MAX_DEPTH.to_string())?;
        self.ensure_kv(
            "max_total_expanded",
            &DEFAULT_MAX_TOTAL_EXPANDED.to_string(),
        )?;
        self.ensure_kv("max_single_ratio", &DEFAULT_MAX_SINGLE_RATIO.to_string())?;
        self.ensure_kv("total_expanded", "0")?;
        self.ensure_kv("recompute_events", "0")?;
        Ok(())
    }

    fn ensure_kv(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO engine_state(key, value) VALUES(?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> rusqlite::Result<String> {
        self.conn
            .query_row("SELECT value FROM engine_state WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
    }

    pub fn kv_set(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO engine_state(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn source_by_sha(&self, sha: &str) -> rusqlite::Result<Option<(i64, String)>> {
        self.conn
            .query_row(
                "SELECT id, stored_path FROM sources WHERE sha256 = ?1",
                params![sha],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    pub fn get_content(&self, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT content FROM content_cache WHERE content_key = ?1",
                params![key],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
    }
}
