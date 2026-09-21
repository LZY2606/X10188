use rusqlite::Connection;
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    otype TEXT NOT NULL,
    hdr_size INTEGER NOT NULL,
    base_ofs INTEGER,
    base_oid TEXT,
    comp_start INTEGER NOT NULL,
    comp_len INTEGER NOT NULL,
    idx_crc INTEGER,
    data_crc INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    oid TEXT,
    final_type TEXT,
    content BLOB,
    gen INTEGER NOT NULL DEFAULT 0,
    UNIQUE(file_id, offset)
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE INDEX IF NOT EXISTS idx_objects_status ON objects(status);

CREATE TABLE IF NOT EXISTS idx_entries (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    offset INTEGER NOT NULL,
    crc32 INTEGER NOT NULL,
    object_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_idx_entries_oid ON idx_entries(oid);

-- 已还原 delta 使用的 base 链接(用于 DAG、删除级联、pin 分支重算)。
CREATE TABLE IF NOT EXISTS links (
    object_id INTEGER PRIMARY KEY,
    base_object_id INTEGER NOT NULL,
    base_oid TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_base ON links(base_object_id);

-- 未还原对象的阻塞依赖:oid:<hex> / obj:<id>。
CREATE TABLE IF NOT EXISTS blocking (
    object_id INTEGER NOT NULL,
    dep TEXT NOT NULL,
    note TEXT,
    PRIMARY KEY(object_id, dep)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    object_id INTEGER NOT NULL,
    step INTEGER NOT NULL,
    base_desc TEXT NOT NULL,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    in_len INTEGER NOT NULL,
    out_len INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_object ON delta_steps(object_id);

CREATE TABLE IF NOT EXISTS pins (
    oid TEXT PRIMARY KEY,
    object_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS budget (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    max_depth INTEGER NOT NULL,
    max_total_bytes INTEGER NOT NULL,
    max_ratio REAL NOT NULL,
    used_bytes INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO budget(id, max_depth, max_total_bytes, max_ratio, used_bytes)
VALUES (1, 64, 67108864, 1000.0, 0);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    file_id INTEGER,
    object_id INTEGER,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    init(&conn)?;
    Ok(conn)
}

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)
}
