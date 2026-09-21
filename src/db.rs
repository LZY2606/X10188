use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    size INTEGER NOT NULL,
    path TEXT NOT NULL,
    imported_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    version INTEGER,
    object_count INTEGER,
    trailer_sha1 TEXT,
    computed_sha1 TEXT,
    checksum_ok INTEGER,
    errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_id INTEGER NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    obj_type TEXT NOT NULL,
    declared_size INTEGER,
    header_len INTEGER,
    base_offset INTEGER,
    base_oid TEXT,
    data_start INTEGER,
    data_len INTEGER,
    inflated BLOB,
    zlib_ok INTEGER NOT NULL DEFAULT 1,
    size_ok INTEGER NOT NULL DEFAULT 1,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_pack ON entries(pack_id, offset);

CREATE TABLE IF NOT EXISTS idx_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    offset INTEGER NOT NULL,
    crc32 INTEGER,
    matched_entry_id INTEGER,
    crc_ok INTEGER
);
CREATE INDEX IF NOT EXISTS idx_idx_entries_source ON idx_entries(source_id);

CREATE TABLE IF NOT EXISTS loose (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    claimed_oid TEXT,
    obj_type TEXT,
    size INTEGER,
    content BLOB,
    ok INTEGER NOT NULL DEFAULT 1,
    error TEXT
);

CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'main',
    oid TEXT,
    obj_type TEXT,
    size INTEGER,
    content BLOB,
    status TEXT NOT NULL,
    reason TEXT,
    chain TEXT NOT NULL DEFAULT '[]',
    needed_oids TEXT NOT NULL DEFAULT '[]',
    deps TEXT NOT NULL DEFAULT '[]',
    warnings TEXT NOT NULL DEFAULT '[]',
    source_name TEXT,
    source_digest TEXT,
    offset INTEGER,
    updated_at INTEGER NOT NULL,
    UNIQUE(provider, branch)
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid, branch, status);

CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    step_no INTEGER NOT NULL,
    base_desc TEXT,
    base_oid TEXT,
    base_offset INTEGER,
    base_provider TEXT,
    instr_start INTEGER,
    instr_end INTEGER,
    input_len INTEGER,
    output_len INTEGER,
    ok INTEGER NOT NULL DEFAULT 1,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_object ON steps(object_id);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch TEXT NOT NULL DEFAULT 'main',
    status TEXT NOT NULL,
    budgets TEXT NOT NULL,
    spent_bytes INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch TEXT NOT NULL,
    oid TEXT NOT NULL,
    object_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(branch, oid)
);
"#;

pub fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    init(&conn)?;
    Ok(conn)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
