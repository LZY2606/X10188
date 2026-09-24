//! SQLite persistence. All analysis state lives under the project data dir.

use rusqlite::Connection;
use std::path::Path;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,            -- pack | idx | loose
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    pack_sha TEXT,                 -- idx: pack sha it belongs to; pack: own trailer sha
    loose_oid TEXT,                -- loose: oid from path (if any)
    imported_at INTEGER NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS idx_entries (
    source_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    oid TEXT NOT NULL,
    offset INTEGER NOT NULL,
    crc32 INTEGER NOT NULL,
    PRIMARY KEY (source_id, ordinal)
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    kind TEXT NOT NULL,            -- pack | loose
    pack_offset INTEGER,           -- pack candidate: offset
    path TEXT NOT NULL,            -- human-readable stable location
    sort_key TEXT NOT NULL,        -- import-order-independent ranking key
    type_name TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    actual_size INTEGER NOT NULL,
    size_ok INTEGER NOT NULL,
    parse_error TEXT,
    delta_data BLOB,               -- zlib-decompressed delta payload
    ofs_distance INTEGER,
    base_offset INTEGER,
    ref_base TEXT,
    ofs_in_bounds INTEGER,
    crc_actual INTEGER,
    crc_idx INTEGER,
    crc_ok INTEGER,
    computed_oid TEXT,             -- null until resolved
    claimed_oid TEXT,              -- idx claim (pack) or path oid (loose)
    content BLOB,                  -- resolved content only
    evidence_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (source_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS branch_pins (
    branch_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL,
    PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolutions (
    branch_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    status TEXT NOT NULL,         -- resolved | missing | cyclic | bad | paused
    type_name TEXT,
    resolved_oid TEXT,
    output_size INTEGER,
    depth INTEGER,
    chain_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (branch_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    step INTEGER NOT NULL,
    base_candidate_id INTEGER,
    base_oid TEXT,
    op_count INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    check_message TEXT,
    ops_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS missing_refs (
    branch_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    referencer_id INTEGER NOT NULL,
    PRIMARY KEY (branch_id, oid, referencer_id)
);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"#;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "on")?;
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT OR IGNORE INTO branches(id, name, created_at) VALUES (1, 'default', 0)",
        [],
    )?;
    Ok(conn)
}
