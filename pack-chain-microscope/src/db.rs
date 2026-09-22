use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

pub fn open(data_dir: &Path) -> rusqlite::Result<Connection> {
    std::fs::create_dir_all(data_dir.join("imports")).ok();
    std::fs::create_dir_all(data_dir.join("objects")).ok();
    std::fs::create_dir_all(data_dir.join("partial")).ok();
    let conn = Connection::open(data_dir.join("microscope.db"))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- pack | index | loose
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    size INTEGER NOT NULL,
    imported_seq INTEGER NOT NULL,
    linked_pack_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS packs (
    source_id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    declared_count INTEGER NOT NULL,
    parsed_count INTEGER NOT NULL,
    trailer_offset INTEGER NOT NULL,
    file_len INTEGER NOT NULL,
    checksum_expected TEXT NOT NULL,
    checksum_actual TEXT NOT NULL,
    checksum_ok INTEGER NOT NULL,
    errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS pack_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_source_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    obj_type INTEGER NOT NULL,
    declared_size INTEGER NOT NULL,
    inflated_len INTEGER NOT NULL,
    inflated_path TEXT,
    zlib_start INTEGER NOT NULL,
    zlib_end INTEGER NOT NULL,
    crc32 INTEGER NOT NULL,
    crc_index_expected INTEGER,
    adler_ok INTEGER NOT NULL,
    base_offset INTEGER,
    base_ref TEXT,
    delta_base_size INTEGER,
    delta_result_size INTEGER,
    UNIQUE(pack_source_id, offset)
);

CREATE TABLE IF NOT EXISTS index_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    index_source_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    oid TEXT NOT NULL,
    offset INTEGER NOT NULL,
    crc32 INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS index_fanout (
    index_source_id INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    cumulative INTEGER NOT NULL,
    PRIMARY KEY (index_source_id, bucket)
);

CREATE TABLE IF NOT EXISTS indexes (
    source_id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    object_count INTEGER NOT NULL,
    pack_checksum TEXT NOT NULL,
    checksum_expected TEXT NOT NULL,
    checksum_actual TEXT NOT NULL,
    checksum_ok INTEGER NOT NULL,
    errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS loose_objects (
    source_id INTEGER PRIMARY KEY,
    obj_type INTEGER NOT NULL,
    declared_len INTEGER NOT NULL,
    content_path TEXT NOT NULL,
    oid_path TEXT NOT NULL,
    oid_computed TEXT NOT NULL,
    oid_matches INTEGER NOT NULL,
    adler_ok INTEGER NOT NULL,
    errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    claimed_oid TEXT,                   -- oid asserted by idx / loose path / ref target
    computed_oid TEXT,                  -- recomputed after full reconstruction
    kind TEXT NOT NULL,                 -- commit|tree|blob|tag
    origin TEXT NOT NULL,               -- pack|loose
    source_id INTEGER NOT NULL,
    pack_entry_id INTEGER,
    loose_source_id INTEGER,
    offset INTEGER,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|resolved|error|paused|blocked
    status_detail TEXT NOT NULL DEFAULT '',
    depth INTEGER NOT NULL DEFAULT 0,
    output_len INTEGER NOT NULL DEFAULT 0,
    output_path TEXT,
    oid_verified INTEGER NOT NULL DEFAULT 0,
    expansion_bytes INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0,
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    error_offset INTEGER
);

CREATE TABLE IF NOT EXISTS delta_edges (
    child_id INTEGER NOT NULL,
    base_kind TEXT NOT NULL,            -- ofs | ref
    base_offset INTEGER,
    base_ref TEXT,
    PRIMARY KEY (child_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER NOT NULL,
    depth INTEGER NOT NULL,             -- 0 = first delta applied at this candidate
    base_candidate_id INTEGER,
    base_oid TEXT,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    payload_sha1 TEXT NOT NULL,
    size_ok INTEGER NOT NULL,
    instructions TEXT NOT NULL DEFAULT '[]',
    check_result TEXT NOT NULL DEFAULT '',
    UNIQUE(candidate_id, depth)
);

CREATE TABLE IF NOT EXISTS blockers (
    candidate_id INTEGER NOT NULL,
    chain_json TEXT NOT NULL,           -- ordered chain from the object to the root blocker
    reason TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (candidate_id)
);

CREATE TABLE IF NOT EXISTS pins (
    oid TEXT PRIMARY KEY,
    candidate_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#,
    )?;
    Ok(())
}

pub fn get_kv(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get::<_, String>(0))
        .optional()
}

pub fn set_kv(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO kv(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )?;
    Ok(())
}
