//! SQLite persistence. Sources and derived analysis results live in tables;
//! imported bytes live under the project `data/` directory.

use crate::oid::Oid;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Db { conn: Arc::new(Mutex::new(conn)) };
        db.init()?;
        Ok(db)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    fn init(&self) -> rusqlite::Result<()> {
        let c = self.lock();
        c.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL CHECK (kind IN ('pack','idx','loose')),
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                size INTEGER NOT NULL,
                imported_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                paired_pack_fp TEXT,
                parse_summary TEXT NOT NULL DEFAULT '{}',
                UNIQUE(fingerprint)
            );

            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                locator TEXT NOT NULL,
                entry_offset INTEGER,
                obj_type TEXT NOT NULL,
                oid TEXT,
                declared_size INTEGER,
                actual_size INTEGER,
                zlib_start INTEGER,
                zlib_end INTEGER,
                crc_expected INTEGER,
                crc_actual INTEGER,
                delta_type TEXT,
                delta_base_locator TEXT,
                parse_issue TEXT,
                status TEXT NOT NULL DEFAULT 'parsed',
                resolution_oid TEXT,
                resolved_type TEXT,
                resolved_size INTEGER,
                resolved_preview TEXT,
                block_reason TEXT,
                UNIQUE(source_id, locator)
            );

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY,
                child_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                parent_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
                parent_oid TEXT,
                kind TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS delta_steps (
                id INTEGER PRIMARY KEY,
                candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                depth INTEGER NOT NULL,
                base_oid TEXT,
                base_locator TEXT,
                delta_type TEXT,
                base_size INTEGER,
                output_size INTEGER,
                cmd_count INTEGER,
                cmd_ranges TEXT,
                input_crc32 INTEGER,
                output_sha TEXT,
                expected_oid TEXT,
                oid_match INTEGER,
                state TEXT NOT NULL DEFAULT 'applied'
            );

            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY,
                code TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
                candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS objects (
                oid TEXT PRIMARY KEY,
                obj_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                preview TEXT NOT NULL,
                content_path TEXT NOT NULL,
                picked_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS pins (
                oid TEXT PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                locator TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS analysis_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                status TEXT NOT NULL,
                max_depth INTEGER NOT NULL,
                max_bytes INTEGER NOT NULL,
                max_share REAL NOT NULL,
                bytes_spent INTEGER NOT NULL DEFAULT 0,
                scope TEXT NOT NULL DEFAULT '[]',
                paused_chain TEXT NOT NULL DEFAULT '[]',
                message TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_cand_oid ON candidates(oid);
            CREATE INDEX IF NOT EXISTS idx_cand_source ON candidates(source_id);
            CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
            CREATE INDEX IF NOT EXISTS idx_issues_candidate ON issues(candidate_id);
            "#,
        )?;
        Ok(())
    }
}

pub fn parse_stored_oid(s: &str) -> Option<Oid> {
    Oid::parse_hex(s)
}

pub fn source_count(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row("SELECT COUNT(*) FROM sources", params![], |r| r.get(0))
}
