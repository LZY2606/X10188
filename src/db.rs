use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    import_seq INTEGER NOT NULL UNIQUE,
    kind TEXT NOT NULL,                 -- pack | index | loose
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    paired_pack_id INTEGER,            -- index -> pack source id
    pack_checksum TEXT,                -- parsed index header checksum (hex)
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    kind TEXT NOT NULL,
    pack_offset INTEGER,
    raw_range_end INTEGER,
    declared_size INTEGER,
    actual_size INTEGER,
    crc32 INTEGER,
    base_offset INTEGER,
    base_ref TEXT,
    claimed_oid TEXT,
    computed_oid TEXT,                 -- loose only
    parse_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_entries_offset ON entries(source_id, pack_offset);
CREATE INDEX IF NOT EXISTS idx_entries_claimed ON entries(claimed_oid);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    oid TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id),
    source_id INTEGER NOT NULL REFERENCES sources(id),
    origin TEXT NOT NULL,             -- index | pack-implicit | loose
    rank_priority INTEGER NOT NULL,
    rank_score INTEGER NOT NULL,
    parse_error TEXT,
    UNIQUE(oid, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_cand_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_cand_entry ON candidates(entry_id);

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

CREATE TABLE IF NOT EXISTS resolved (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    entry_id INTEGER NOT NULL REFERENCES entries(id),
    oid TEXT,
    kind TEXT,
    size INTEGER,
    depth INTEGER,
    status TEXT NOT NULL,             -- resolved | bad | blocked | paused
    chosen_candidate_id INTEGER,
    error TEXT,
    content_path TEXT,
    preview TEXT,
    delta_chain_json TEXT,
    updated_seq INTEGER NOT NULL,
    UNIQUE(branch_id, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_resolved_status ON resolved(branch_id, status);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    step INTEGER NOT NULL,
    base_kind TEXT,
    base_entry_id INTEGER,
    delta_entry_id INTEGER,
    base_size INTEGER,
    result_size INTEGER,
    instruction_count INTEGER,
    instruction_range_json TEXT,
    input_consumed INTEGER,
    verify_ok INTEGER,
    error TEXT,
    UNIQUE(branch_id, entry_id, step)
);

CREATE TABLE IF NOT EXISTS blockers (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    blocker_oid TEXT,
    blocker_entry_id INTEGER,
    reason TEXT NOT NULL,
    chain_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blockers_entry ON blockers(branch_id, entry_id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "On")?;
        conn.execute_batch(SCHEMA)?;
        let exists: i64 =
            conn.query_row("SELECT COUNT(*) FROM branches WHERE id=1", [], |r| r.get(0))?;
        if exists == 0 {
            conn.execute("INSERT INTO branches(id,name) VALUES(1,'default')", [])?;
        }
        Ok(Db(Mutex::new(conn)))
    }
}

pub fn get_setting(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM settings WHERE key=?1", params![key], |r| r.get(0))
        .ok()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}
