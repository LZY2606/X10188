//! SQLite persistence layer. All forensic state lives here; object
//! bodies live in the project data directory under `objects/<cid>`.

use rusqlite::Connection;

pub const SCHEMA_VERSION: i64 = 1;

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 10_000)?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0);
    if version >= SCHEMA_VERSION {
        return Ok(());
    }
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,            -- pack | index | loose | unknown
    stored_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    parse_summary TEXT NOT NULL,   -- JSON
    pack_checksum TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,           -- deterministic, import-order independent
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    entry_kind TEXT NOT NULL,      -- plain | ofs_delta | ref_delta | loose | parse_error
    raw_type_code INTEGER,
    obj_type TEXT,
    header_offset INTEGER,
    header_len INTEGER,
    data_offset INTEGER,
    zlib_end INTEGER,
    declared_size INTEGER,
    expected_oid TEXT,             -- claimed by a paired index or loose path
    actual_oid TEXT,               -- recomputed after resolution
    status TEXT NOT NULL,
    error_code TEXT,
    error_message TEXT,
    evidence_hex TEXT,
    blocking_chain TEXT,           -- JSON array of candidate ids
    content_len INTEGER,
    is_text INTEGER NOT NULL DEFAULT 0,
    inflated_len INTEGER,          -- size of the zlib payload (delta/frame length)
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
    child_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    parent_id TEXT REFERENCES candidates(id) ON DELETE CASCADE,
    base_ref TEXT,                 -- oid claimed by ref-delta / unresolved
    base_source_offset INTEGER,    -- ofs base claim
    PRIMARY KEY (child_id, parent_id, base_ref)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    step INTEGER NOT NULL,         -- depth index along the chain (1-based)
    base_candidate_id TEXT,
    base_oid TEXT,
    base_offset INTEGER,
    delta_range_start INTEGER NOT NULL,
    delta_range_end INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    op_count INTEGER NOT NULL,
    ops_json TEXT NOT NULL,
    check_ok INTEGER NOT NULL,
    check_note TEXT
);

CREATE TABLE IF NOT EXISTS pins (
    oid TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    pinned_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_candidates_actual ON candidates(actual_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_expected ON candidates(expected_oid);
CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);
CREATE INDEX IF NOT EXISTS idx_delta_steps_cand ON delta_steps(candidate_id);
"#,
    )?;
    conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    Ok(())
}
