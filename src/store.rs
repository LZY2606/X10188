//! SQLite persistence: imported sources, object candidates, branches/pins,
//! resolution runs and the reconstructed delta DAG.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::git::idx::{parse_idx, ParsedIdx};
use crate::git::loose::parse_loose;
use crate::git::pack::{parse_pack, ParseBudget, ParsedPack, RawEntry};
use crate::git::{git_oid, GitType};

/// Default analysis budget (overridable per run via the API).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_expand_bytes: u64,
    pub max_single_bytes: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            max_expand_bytes: 64 * 1024 * 1024,
            max_single_bytes: 16 * 1024 * 1024,
        }
    }
}

pub const DEFAULT_BRANCH: &str = "main";

#[derive(Debug)]
pub struct Store {
    pub db: Mutex<Connection>,
    pub data_dir: PathBuf,
}

/// One imported file (pack / idx / loose object), kept under `data/`.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub stored_path: String,
    pub size: i64,
    pub sha256: String,
    /// For idx: pack checksum it claims; for pack: pack sha1; else null.
    pub checksum: Option<String>,
    pub paired_source_id: Option<i64>,
    pub parse_summary: String,
    pub parse_errors: String,
}

/// A single candidate location for a given git object id.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub id: i64,
    pub oid: String,
    pub source_id: i64,
    pub locator: String,
    pub kind_name: String,
    pub offset: i64,
    pub raw_size: i64,
    pub inflate_size: i64,
    pub crc_ok: Option<bool>,
    pub parse_error: Option<String>,
    /// delta nodes: claimed base (oid or "ofs:<offset>").
    pub base_ref: Option<String>,
    pub base_offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    pub id: i64,
    pub branch: String,
    pub oid: String,
    pub candidate_id: i64,
    pub kind_name: String,
    pub depth: i64,
    pub content_len: i64,
    pub oid_ok: bool,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRow {
    pub id: i64,
    pub branch: String,
    pub status: String,
    pub budget: String,
    pub depth_used: i64,
    pub bytes_used: i64,
    pub summary: String,
    pub created_at: String,
}

pub fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

impl Store {
    pub fn open(data_dir: &Path) -> anyhow::Result<Store> {
        std::fs::create_dir_all(data_dir.join("files"))?;
        let db_path = data_dir.join("microscope.db");
        let mut conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        migrate(&mut conn)?;
        Ok(Store {
            db: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT OR IGNORE INTO branches(name) VALUES (?1)",
        params![DEFAULT_BRANCH],
    )?;
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('pack','idx','loose')),
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    checksum TEXT,
    paired_source_id INTEGER REFERENCES sources(id),
    parse_summary TEXT NOT NULL DEFAULT '',
    parse_errors TEXT NOT NULL DEFAULT '',
    fanout BLOB,
    imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY,
    oid TEXT NOT NULL,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    locator TEXT NOT NULL,
    kind_name TEXT NOT NULL,
    "offset" INTEGER NOT NULL,
    raw_size INTEGER NOT NULL DEFAULT 0,
    inflate_size INTEGER NOT NULL DEFAULT 0,
    crc_ok INTEGER,
    parse_error TEXT,
    base_ref TEXT,
    base_offset INTEGER,
    claimed_oid INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE INDEX IF NOT EXISTS idx_objects_source ON objects(source_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_locator
    ON objects(source_id, locator);

CREATE TABLE IF NOT EXISTS branches (
    name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY,
    branch TEXT NOT NULL REFERENCES branches(name) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(branch, oid)
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    branch TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('complete','paused','failed')),
    budget TEXT NOT NULL,
    depth_used INTEGER NOT NULL DEFAULT 0,
    bytes_used INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resolved (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    kind_name TEXT NOT NULL,
    depth INTEGER NOT NULL,
    content_len INTEGER NOT NULL,
    oid_ok INTEGER NOT NULL,
    content BLOB NOT NULL,
    UNIQUE(run_id, oid)
);
CREATE INDEX IF NOT EXISTS idx_resolved_branch ON resolved(branch, oid);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    step INTEGER NOT NULL,
    child_candidate_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
    base_candidate_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
    base_oid TEXT,
    cmd_start INTEGER NOT NULL,
    cmd_end INTEGER NOT NULL,
    cmd_count INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    verify TEXT NOT NULL,
    UNIQUE(run_id, oid, step)
);

CREATE TABLE IF NOT EXISTS delta_commands (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    step INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    cmd_start INTEGER NOT NULL,
    cmd_end INTEGER NOT NULL,
    src_offset INTEGER NOT NULL,
    src_len INTEGER NOT NULL,
    out_offset INTEGER NOT NULL,
    out_len INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delta_cmds ON delta_commands(run_id, oid, step);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    oid TEXT,
    level TEXT NOT NULL,
    message TEXT NOT NULL
);
"#;
