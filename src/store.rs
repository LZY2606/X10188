//! SQLite persistence. All state lives in one database file inside the
//! project data directory; imported source bytes are also copied there.

use rusqlite::{params, Connection, OptionalExtension};

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,              -- pack | idx | loose
    name TEXT NOT NULL,
    digest TEXT NOT NULL,            -- sha-256 of content
    path TEXT NOT NULL,              -- path inside data dir
    size INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'  -- json: pack header, fanout, parse errors
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,         -- offset of entry inside the source
    obj_type TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    data_offset INTEGER NOT NULL,
    data_len INTEGER NOT NULL,
    ofs_distance INTEGER,            -- ofs-delta: encoded distance
    ref_base TEXT,                   -- ref-delta: base oid hex
    crc32 INTEGER,                   -- computed crc32 of raw entry bytes
    idx_crc32 INTEGER,               -- crc32 recorded by a matching idx
    raw BLOB NOT NULL,               -- raw entry bytes (header..zlib end)
    UNIQUE(source_id, offset)
);
CREATE TABLE IF NOT EXISTS resolutions (
    entry_id INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    status TEXT NOT NULL,            -- ok | paused | blocked | error
    oid TEXT,                        -- computed git object id (status ok only)
    depth INTEGER NOT NULL DEFAULT 0,
    steps TEXT NOT NULL DEFAULT '[]',
    error TEXT,                      -- json evidence
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contents (
    entry_id INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    content BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS partials (
    entry_id INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    chain TEXT NOT NULL,             -- json array of entry ids, base first
    next_idx INTEGER NOT NULL,       -- index of next delta in chain to apply
    cur_type TEXT NOT NULL,
    buffer BLOB NOT NULL,            -- intermediate reconstruction bytes
    steps TEXT NOT NULL DEFAULT '[]',
    depth_used INTEGER NOT NULL DEFAULT 0,
    bytes_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS edges (
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    base_entry_id INTEGER,           -- null while base is unknown/missing
    base_kind TEXT NOT NULL,         -- ofs | ref
    base_ref TEXT NOT NULL,          -- offset (decimal) or oid hex
    PRIMARY KEY (entry_id, base_ref)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    source_id INTEGER,
    entry_id INTEGER,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
    oid TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    branch TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (oid, branch)
);
"#;

pub fn now() -> String {
    // Seconds since epoch; good enough for ordering evidence.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

#[derive(Debug, Clone)]
pub struct EntryRow {
    pub id: i64,
    pub source_id: i64,
    pub offset: u64,
    pub obj_type: String,
    pub declared_size: u64,
    pub data_offset: u64,
    pub data_len: u64,
    pub ofs_distance: Option<u64>,
    pub ref_base: Option<String>,
    pub crc32: Option<u32>,
    pub idx_crc32: Option<u32>,
    pub raw: Vec<u8>,
}

pub fn get_entry(conn: &Connection, id: i64) -> rusqlite::Result<Option<EntryRow>> {
    conn.query_row(
        "SELECT id, source_id, offset, obj_type, declared_size, data_offset, data_len,
                ofs_distance, ref_base, crc32, idx_crc32, raw FROM entries WHERE id=?1",
        params![id],
        |r| {
            Ok(EntryRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                offset: r.get::<_, i64>(2)? as u64,
                obj_type: r.get(3)?,
                declared_size: r.get::<_, i64>(4)? as u64,
                data_offset: r.get::<_, i64>(5)? as u64,
                data_len: r.get::<_, i64>(6)? as u64,
                ofs_distance: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                ref_base: r.get(8)?,
                crc32: r.get::<_, Option<i64>>(9)?.map(|v| v as u32),
                idx_crc32: r.get::<_, Option<i64>>(10)?.map(|v| v as u32),
                raw: r.get(11)?,
            })
        },
    )
    .optional()
}

pub fn add_evidence(
    conn: &Connection,
    source_id: Option<i64>,
    entry_id: Option<i64>,
    kind: &str,
    message: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO evidence(source_id, entry_id, kind, message, created_at)
         VALUES(?1,?2,?3,?4,?5)",
        params![source_id, entry_id, kind, message, now()],
    )?;
    Ok(())
}

/// Deterministic candidate ordering: by source digest, then offset, then id.
/// Import order (source id / insertion time) never affects this.
pub const CANDIDATE_ORDER: &str =
    "ORDER BY (SELECT digest FROM sources s WHERE s.id = e.source_id), e.offset, e.id";
