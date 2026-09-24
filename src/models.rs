use crate::git::oid::Oid;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,              -- pack | index | loose
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    imported_seq INTEGER NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}',
    parse_error TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,              -- computed oid (loose claim verified into same value)
    claimed_oid TEXT,
    object_type TEXT,               -- commit|tree|blob|tag|ofs_delta|ref_delta
    location TEXT NOT NULL,         -- pack:<off> | loose | index:<i>
    payload_path TEXT,
    payload_len INTEGER,
    decl_size INTEGER,
    base_oid TEXT,
    base_offset INTEGER,
    crc_ok INTEGER,
    oid_ok INTEGER,
    parse_bad INTEGER NOT NULL DEFAULT 0,
    bad_reason TEXT,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    rank_blob TEXT NOT NULL,
    UNIQUE(source_id, location)
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    PRIMARY KEY (branch_id, oid)
);

-- One resolved chain per (branch, candidate).
CREATE TABLE IF NOT EXISTS resolutions (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    state TEXT NOT NULL,           -- resolved|blocked|bad|paused
    error_code TEXT,
    chain_json TEXT,
    final_type TEXT,
    final_len INTEGER,
    content_path TEXT,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    depth INTEGER NOT NULL DEFAULT 0,
    recompute_count INTEGER NOT NULL DEFAULT 0,
    updated_seq INTEGER NOT NULL,
    PRIMARY KEY (branch_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(SCHEMA)?;
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM branches", [], |r| r.get(0))?;
    if n == 0 {
        conn.execute(
            "INSERT INTO branches(name, created_seq) VALUES('default', 0)",
            [],
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateEvidence {
    pub level: String,
    pub code: String,
    pub detail: String,
}

pub fn oid_str(o: Oid) -> String {
    o.hex()
}
