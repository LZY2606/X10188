//! SQLite persistence for imported artifacts, nodes, candidates, per-branch
//! resolution results, delta step provenance and resume checkpoints.

use crate::model::*;
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,            -- pack | idx | loose
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- idx linkage:
    linked_pack_source_id INTEGER,
    idx_checksum_ok INTEGER,
    pack_checksum_matches INTEGER,
    parse_errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS pack_scan (
    source_id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    object_count INTEGER NOT NULL,
    raw_len INTEGER NOT NULL,
    trailer_sha TEXT NOT NULL,
    trailer_ok INTEGER NOT NULL,
    scan_errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    pack_offset INTEGER NOT NULL,      -- -1 for loose
    kind TEXT NOT NULL,                -- full | ofs-delta | ref-delta | loose
    object_type INTEGER,               -- 1..=4 when known
    declared_size INTEGER,
    inflated_size INTEGER,
    payload BLOB,                      -- inflated object/delta bytes
    header_len INTEGER,
    compressed_len INTEGER,
    record_crc INTEGER,
    expected_crc INTEGER,
    crc_ok INTEGER,
    base_ofs INTEGER,                  -- absolute pack offset for ofs-delta
    base_ref_oid TEXT,                 -- hex oid for ref-delta
    parse_errors TEXT NOT NULL DEFAULT '[]',
    UNIQUE(source_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    oid TEXT NOT NULL,
    node_id INTEGER NOT NULL,
    node_source_id INTEGER NOT NULL,
    node_offset INTEGER NOT NULL,
    origin TEXT NOT NULL,             -- idx|loose-path|hash|ref-inferred|forced
    source_label TEXT NOT NULL,
    hash_match INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    sort_key INTEGER NOT NULL,
    UNIQUE(oid, node_id, origin, source_label)
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    is_trunk INTEGER NOT NULL,
    pinned_node_id INTEGER,           -- node whose source candidate is forced
    pinned_oid TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS resolutions (
    branch_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    object_type INTEGER,
    resolved_oid TEXT,
    content BLOB,
    chain_depth INTEGER,
    base_node_id INTEGER,
    blocked_chain TEXT,               -- JSON
    error TEXT,
    bytes_charged INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (branch_id, node_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    base_node_id INTEGER,
    kind TEXT NOT NULL,
    delta_start INTEGER NOT NULL,
    delta_end INTEGER NOT NULL,
    copy_offset INTEGER,
    size INTEGER NOT NULL,
    input_pos INTEGER NOT NULL,
    output_len_after INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    check_error TEXT
);

CREATE TABLE IF NOT EXISTS checkpoints (
    branch_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    next_node_id INTEGER,
    bytes_used INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // Seed trunk branch.
        conn.execute(
            "INSERT OR IGNORE INTO branches(id,name,is_trunk) VALUES(1,'trunk',1)",
            [],
        )?;
        Ok(Db(Mutex::new(conn)))
    }
}

// Convenience helpers kept tiny on purpose; the engine module owns the SQL.
pub fn now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{secs}")
}

#[allow(dead_code)]
pub fn jstr(v: &impl serde::Serialize) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

#[allow(dead_code)]
pub fn node_pk(source_id: i64, offset: i64) -> (i64, i64) {
    (source_id, offset)
}

#[allow(dead_code)]
pub fn budget_defaults() -> Budgets {
    Budgets::defaults()
}

#[allow(dead_code)]
pub fn status_str(s: ResolveStatus) -> &'static str {
    s.as_str()
}

#[allow(dead_code)]
pub fn p<T>(v: Vec<T>) -> Vec<T> {
    v
}

#[allow(dead_code)]
pub fn q() {
    let _ = params![];
}
