//! SQLite persistence and on-disk ingestion of imported source files.
//!
//! All imported bytes stay inside the project data directory under
//! `<data>/files/<source_id>_<sanitized filename>`.

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct SourceFile {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub rel_path: String,
    pub bytes: i64,
    pub sha1: String,
    pub import_seq: i64,
    pub note: String,
}

pub struct Db {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                 -- pack | idx | loose
    filename TEXT NOT NULL,
    rel_path TEXT NOT NULL UNIQUE,
    bytes INTEGER NOT NULL,
    sha1 TEXT NOT NULL,
    import_seq INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    trailer_oid TEXT NOT NULL DEFAULT ''   -- pack trailer SHA / idx pack checksum
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    entry_kind TEXT NOT NULL,          -- pack | loose
    claimed_oid TEXT,                  -- from idx or loose path (NULL until known)
    obj_type TEXT NOT NULL,
    declared_size INTEGER,
    raw_offset INTEGER,                -- header offset inside pack (0 for loose)
    data_start INTEGER,
    data_end INTEGER,
    ofs_base_offset INTEGER,
    ofs_distance INTEGER,
    ref_base_oid TEXT,
    crc32_expected INTEGER,
    crc32_actual INTEGER,
    inflate_ok INTEGER NOT NULL DEFAULT 0,
    inflate_size INTEGER,
    parse_error TEXT,
    parse_seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_entries_claimed ON entries(claimed_oid);
CREATE TABLE IF NOT EXISTS candidates (
    entry_id INTEGER PRIMARY KEY,
    oid TEXT NOT NULL,
    content_sha1 TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    source_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    created_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS edges (
    entry_id INTEGER NOT NULL,
    edge_kind TEXT NOT NULL,           -- ofs | ref
    target_entry_id INTEGER,           -- resolved structural target
    target_oid TEXT,                   -- for ref edges
    PRIMARY KEY (entry_id, edge_kind, target_oid, target_entry_id)
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    status TEXT NOT NULL,              -- completed | paused
    max_depth INTEGER NOT NULL,
    max_expand INTEGER NOT NULL,
    max_single INTEGER NOT NULL,
    spent_expand INTEGER NOT NULL,
    created_seq INTEGER NOT NULL,
    report TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS results (
    branch_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    status TEXT NOT NULL,              -- resolved | paused | blocked | corrupt
    obj_type TEXT,
    size INTEGER,
    oid TEXT,
    content_sha1 TEXT,
    depth INTEGER,
    error_code TEXT,
    error_message TEXT,
    blocking_chain TEXT,               -- JSON
    run_id INTEGER,
    analysis_seq INTEGER NOT NULL,
    PRIMARY KEY (branch_id, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_results_oid ON results(oid);
CREATE TABLE IF NOT EXISTS steps (
    branch_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    base_kind TEXT NOT NULL,
    base_ref TEXT NOT NULL,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    copy_ops INTEGER NOT NULL,
    insert_ops INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    expected_size INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    detail TEXT NOT NULL,
    PRIMARY KEY (branch_id, entry_id, ordinal)
);
CREATE TABLE IF NOT EXISTS contents (
    branch_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY (branch_id, entry_id)
);
CREATE TABLE IF NOT EXISTS analysis_meta (
    branch_id INTEGER PRIMARY KEY,
    analysis_seq INTEGER NOT NULL DEFAULT 0
);
"#;

impl Db {
    pub fn open(data_dir: &Path) -> Result<Db> {
        std::fs::create_dir_all(data_dir).context("creating data dir")?;
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir).context("creating files dir")?;
        let db_path = data_dir.join("packscope.sqlite");
        let mut conn = Connection::open(db_path).context("opening sqlite")?;
        conn.pragma_update(None, "foreign_keys", 1)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(SCHEMA)?;
        Db::seed(&mut conn)?;
        Ok(Db {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
            files_dir,
        })
    }

    fn seed(conn: &mut Connection) -> Result<()> {
        let defaults = [
            ("budget_depth", "50"),
            ("budget_expand", "67108864"),
            ("budget_single_ratio", "0.5"),
            ("parse_inflate_cap", "268435456"),
        ];
        for (k, v) in defaults {
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?1,?2)",
                rusqlite::params![k, v],
            )?;
        }
        let seq = next_seq(conn)?;
        conn.execute(
            "INSERT OR IGNORE INTO branches(id,name,note,created_seq) VALUES(1,'default','默认分析分支',?1)",
            rusqlite::params![seq],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO analysis_meta(branch_id,analysis_seq) VALUES(1,0)",
            [],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT value FROM settings WHERE key=?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .with_context(|| format!("setting {key}"))
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Persist an imported file into the data dir (content-addressed copy).
    pub fn store_import(&self, filename: &str, data: &[u8]) -> Result<(PathBuf, String)> {
        let safe: String = filename
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let digest = hex::encode(crate::gitfmt::sha1_bytes(data));
        let rel = format!("{digest}_{safe}");
        let path = self.files_dir.join(&rel);
        if !path.exists() {
            std::fs::write(&path, data).context("writing imported file")?;
        }
        Ok((path, rel))
    }

    pub fn read_source_bytes(&self, rel_path: &str) -> Result<Vec<u8>> {
        let p = self.files_dir.join(rel_path);
        std::fs::read(p).context("reading source file")
    }
}

/// Global monotonic sequence used so tie-breaking never depends on import order.
pub fn next_seq(conn: &Connection) -> Result<i64> {
    // Rows in `runs`/`entries` share one logical clock via sqlite_sequence-free
    // counter stored as max(id)+1 style values; use a dedicated setting.
    let cur: Option<String> = conn
        .query_row("SELECT value FROM settings WHERE key='seq_clock'", [], |r| {
            r.get(0)
        })
        .ok();
    let next = cur.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0) + 1;
    conn.execute(
        "INSERT INTO settings(key,value) VALUES('seq_clock',?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![next.to_string()],
    )?;
    Ok(next)
}
