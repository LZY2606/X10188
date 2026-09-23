use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    digest TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
    parse_status TEXT NOT NULL,
    parse_error TEXT
);
CREATE TABLE IF NOT EXISTS packs (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id),
    version INTEGER NOT NULL,
    num_objects INTEGER NOT NULL,
    data_len INTEGER NOT NULL,
    trailer_offset INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    checksum_ok INTEGER,
    linked_idx_source_id INTEGER
);
CREATE TABLE IF NOT EXISTS indexes (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id),
    version INTEGER NOT NULL,
    num_objects INTEGER NOT NULL,
    pack_checksum TEXT NOT NULL,
    idx_checksum_ok INTEGER NOT NULL,
    linked_pack_source_id INTEGER,
    match_kind TEXT
);
CREATE TABLE IF NOT EXISTS idx_fanout (
    idx_source_id INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    cumulative INTEGER NOT NULL,
    PRIMARY KEY (idx_source_id, bucket)
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    pack_source_id INTEGER NOT NULL REFERENCES sources(id),
    offset INTEGER NOT NULL,
    header_len INTEGER NOT NULL,
    obj_type INTEGER NOT NULL,
    type_name TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    delta_kind TEXT,
    base_offset INTEGER,
    base_oid TEXT,
    comp_start INTEGER NOT NULL,
    comp_end INTEGER NOT NULL,
    compressed_len INTEGER NOT NULL,
    crc32 INTEGER NOT NULL,
    idx_crc32 INTEGER,
    crc_ok INTEGER,
    inflated_len INTEGER,
    inflate_error TEXT,
    size_spoof INTEGER,
    parse_error TEXT,
    UNIQUE (pack_source_id, offset)
);
CREATE TABLE IF NOT EXISTS loose_objects (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    claimed_oid TEXT,
    obj_type INTEGER NOT NULL,
    size INTEGER NOT NULL,
    oid TEXT NOT NULL,
    oid_matches_filename INTEGER,
    UNIQUE (source_id)
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    oid TEXT NOT NULL,
    origin TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    entry_id INTEGER,
    loose_id INTEGER,
    obj_type INTEGER
);
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id),
    PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS object_state (
    branch_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    status TEXT NOT NULL,
    obj_type INTEGER,
    resolved_len INTEGER,
    depth INTEGER,
    expanded_bytes INTEGER,
    candidate_id INTEGER,
    blocking_chain TEXT,
    error_code TEXT,
    error_detail TEXT,
    recompute_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    entry_id INTEGER,
    base_oid TEXT,
    base_offset INTEGER,
    delta_kind TEXT,
    instr_start INTEGER,
    instr_end INTEGER,
    input_len INTEGER,
    output_len INTEGER,
    checks TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    branch_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    max_depth INTEGER NOT NULL,
    max_total_bytes INTEGER NOT NULL,
    max_object_ratio TEXT NOT NULL,
    used_depth INTEGER NOT NULL DEFAULT 0,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    total_input_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "on")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT OR IGNORE INTO branches(id, name) VALUES (1, 'main')",
            params![],
        )?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }
}
