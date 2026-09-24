//! SQLite persistence layer.

use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('pack','idx','loose')),
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    -- linkage
    pack_source_id INTEGER REFERENCES sources(id),
    idx_source_id INTEGER REFERENCES sources(id),
    pack_sha TEXT,
    idx_matches_pack INTEGER,
    parse_ok INTEGER NOT NULL DEFAULT 1,
    parse_error TEXT,
    version INTEGER,
    object_count INTEGER,
    trailer_sha_ok INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fanouts (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    count INTEGER NOT NULL,
    UNIQUE(source_id, bucket)
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('pack','loose')),
    entry_index INTEGER,
    header_offset INTEGER,
    data_offset INTEGER,
    end_offset INTEGER,
    compressed_len INTEGER,
    type_code INTEGER,
    claimed_oid TEXT,
    declared_size INTEGER,
    actual_size INTEGER,
    base_offset INTEGER,
    base_oid TEXT,
    index_crc TEXT,
    actual_crc TEXT,
    -- loose only
    computed_oid TEXT,
    parse_error TEXT,
    raw BLOB
);
CREATE INDEX IF NOT EXISTS idx_candidates_claimed ON candidates(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE INDEX IF NOT EXISTS idx_candidates_base ON candidates(base_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_packoff ON candidates(source_id, header_offset);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
    base_oid TEXT,
    ref_kind TEXT NOT NULL CHECK(ref_kind IN ('ofs','ref')),
    valid INTEGER NOT NULL DEFAULT 1,
    detail TEXT,
    UNIQUE(candidate_id, ref_kind)
);
CREATE INDEX IF NOT EXISTS idx_edges_base ON edges(base_candidate_id);
CREATE INDEX IF NOT EXISTS idx_edges_baseoid ON edges(base_oid);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    parent_id INTEGER REFERENCES branches(id),
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    UNIQUE(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS budgets (
    id INTEGER PRIMARY KEY,
    scope_branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE,
    max_depth INTEGER NOT NULL,
    max_total_bytes INTEGER NOT NULL,
    max_single_ratio REAL NOT NULL,
    total_used INTEGER NOT NULL DEFAULT 0,
    UNIQUE(scope_branch_id)
);

CREATE TABLE IF NOT EXISTS branch_states (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    oid TEXT,
    chosen_base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK(status IN
       ('resolved','blocked_missing_base','blocked_corrupt_base','blocked_cycle',
        'blocked_bad_object','paused_budget','pending')),
    depth INTEGER,
    expanded_bytes INTEGER,
    oid_ok INTEGER,
    blocker_chain TEXT,
    detail TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(branch_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS idx_bs_oid ON branch_states(branch_id, oid);
CREATE INDEX IF NOT EXISTS idx_bs_status ON branch_states(status);

CREATE TABLE IF NOT EXISTS contents (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    type_code INTEGER NOT NULL,
    data BLOB NOT NULL,
    UNIQUE(branch_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    depth INTEGER NOT NULL,
    base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
    base_oid TEXT,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    instr_range_start INTEGER NOT NULL,
    instr_range_end INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    check_detail TEXT,
    seq INTEGER NOT NULL,
    UNIQUE(branch_id, candidate_id, seq)
);

CREATE TABLE IF NOT EXISTS recompute_log (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    seed_count INTEGER NOT NULL,
    affected_count INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory database used by tests.
    pub fn open_memory() -> rusqlite::Result<Db> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// Ensure the default branch and its budget row exist.
    pub fn ensure_defaults(&self, budget: crate::git::base::Budget) -> rusqlite::Result<()> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO branches(id, name, note) VALUES (1, 'default', '主分析线（自动排序候选）')",
            [],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO budgets(scope_branch_id, max_depth, max_total_bytes, max_single_ratio)
             VALUES (1, ?1, ?2, ?3)",
            params![budget.max_depth, budget.max_total_bytes, budget.max_single_ratio],
        )?;
        Ok(())
    }
}

/// Format 20 byte sha1 as lowercase hex.
pub fn hex20(b: &[u8; 20]) -> String {
    hex::encode(b)
}

/// Parse lowercase hex sha1.
pub fn parse_oid(s: &str) -> Option<[u8; 20]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 20 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    Some(a)
}
