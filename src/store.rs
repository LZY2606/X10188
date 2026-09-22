//! SQLite 持久层：来源、pack、index、对象候选、delta 步骤、分析分支与预算。

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::Serialize;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    orig_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT
);
CREATE TABLE IF NOT EXISTS packs (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    version INTEGER,
    object_count INTEGER,
    trailer_sha1 TEXT,
    trailer_ok INTEGER,
    trailing_bytes INTEGER DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS pack_indexes (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    object_count INTEGER,
    pack_checksum TEXT,
    index_checksum TEXT,
    fanout_ok INTEGER,
    checksum_ok INTEGER,
    fanout_json TEXT,
    match_status TEXT,
    match_detail TEXT
);
CREATE TABLE IF NOT EXISTS index_entries (
    index_id INTEGER NOT NULL REFERENCES pack_indexes(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    oid TEXT NOT NULL,
    crc32 INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    PRIMARY KEY (index_id, ordinal)
);
CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,
    entry_index INTEGER,
    pack_offset INTEGER,
    obj_type INTEGER NOT NULL,
    declared_size INTEGER NOT NULL,
    data_offset INTEGER,
    data_len INTEGER,
    end_offset INTEGER,
    crc32 INTEGER,
    base_kind TEXT,
    base_ofs_distance INTEGER,
    base_offset INTEGER,
    base_oid TEXT,
    base_object_id INTEGER,
    oid TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    depth INTEGER,
    content_size INTEGER,
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS contents (
    object_id INTEGER PRIMARY KEY REFERENCES objects(id) ON DELETE CASCADE,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    step_no INTEGER NOT NULL,
    base_object_id INTEGER,
    base_desc TEXT NOT NULL,
    instr_offset INTEGER NOT NULL,
    instr_len INTEGER NOT NULL,
    copy_count INTEGER NOT NULL,
    insert_count INTEGER NOT NULL,
    base_size INTEGER NOT NULL,
    declared_out_size INTEGER NOT NULL,
    actual_out_size INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    oid TEXT NOT NULL,
    object_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS budgets (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_depth INTEGER NOT NULL,
    max_expand_bytes INTEGER NOT NULL,
    max_ratio REAL NOT NULL
);
INSERT OR IGNORE INTO budgets (id, max_depth, max_expand_bytes, max_ratio)
VALUES (1, 64, 67108864, 1000.0);
CREATE INDEX IF NOT EXISTS idx_objects_source ON objects(source_id);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE INDEX IF NOT EXISTS idx_objects_status ON objects(status);
CREATE INDEX IF NOT EXISTS idx_index_entries_oid ON index_entries(oid);
"#;

pub fn open(db_path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub path: String,
    pub orig_name: String,
    pub kind: String,
    pub size: i64,
    pub sha256: String,
    pub imported_at: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub source_id: i64,
    pub origin: String,
    pub entry_index: Option<i64>,
    pub pack_offset: Option<i64>,
    pub obj_type: i64,
    pub declared_size: i64,
    pub data_offset: Option<i64>,
    pub data_len: Option<i64>,
    pub end_offset: Option<i64>,
    pub crc32: Option<i64>,
    pub base_kind: Option<String>,
    pub base_ofs_distance: Option<i64>,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub base_object_id: Option<i64>,
    pub oid: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub depth: Option<i64>,
    pub content_size: Option<i64>,
    pub resolved_at: Option<String>,
}

const OBJ_COLS: &str = "id,source_id,origin,entry_index,pack_offset,obj_type,declared_size,\
data_offset,data_len,end_offset,crc32,base_kind,base_ofs_distance,base_offset,base_oid,base_object_id,\
oid,status,error,depth,content_size,resolved_at";
const OBJ_COLS_P: &str = "o.id,o.source_id,o.origin,o.entry_index,o.pack_offset,o.obj_type,o.declared_size,\
o.data_offset,o.data_len,o.end_offset,o.crc32,o.base_kind,o.base_ofs_distance,o.base_offset,o.base_oid,o.base_object_id,\
o.oid,o.status,o.error,o.depth,o.content_size,o.resolved_at";

pub fn map_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectRow> {
    Ok(ObjectRow {
        id: row.get(0)?,
        source_id: row.get(1)?,
        origin: row.get(2)?,
        entry_index: row.get(3)?,
        pack_offset: row.get(4)?,
        obj_type: row.get(5)?,
        declared_size: row.get(6)?,
        data_offset: row.get(7)?,
        data_len: row.get(8)?,
        end_offset: row.get(9)?,
        crc32: row.get(10)?,
        base_kind: row.get(11)?,
        base_ofs_distance: row.get(12)?,
        base_offset: row.get(13)?,
        base_oid: row.get(14)?,
        base_object_id: row.get(15)?,
        oid: row.get(16)?,
        status: row.get(17)?,
        error: row.get(18)?,
        depth: row.get(19)?,
        content_size: row.get(20)?,
        resolved_at: row.get(21)?,
    })
}

pub fn get_object(conn: &Connection, id: i64) -> Result<Option<ObjectRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {OBJ_COLS} FROM objects WHERE id = ?1"))?;
    let mut rows = stmt.query(params![id])?;
    if let Some(r) = rows.next()? {
        Ok(Some(map_object(r)?))
    } else {
        Ok(None)
    }
}

pub fn pending_objects(conn: &Connection) -> Result<Vec<ObjectRow>> {
    let mut stmt =
        conn.prepare(&format!("SELECT {OBJ_COLS} FROM objects WHERE status='pending' ORDER BY id"))?;
    let rows = stmt.query_map([], map_object)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// 候选排序与导入顺序无关：oid → origin → 来源内容 sha256 → pack 偏移。
pub fn objects_by_oid(conn: &Connection, oid: &str) -> Result<Vec<ObjectRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM objects o JOIN sources s ON s.id=o.source_id \
         WHERE o.oid=?1 ORDER BY o.origin, s.sha256, o.pack_offset",
        cols = OBJ_COLS_P
    ))?;
    let rows = stmt.query_map(params![oid], map_object)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[derive(Debug, Clone, Serialize)]
pub struct Budgets {
    pub max_depth: i64,
    pub max_expand_bytes: i64,
    pub max_ratio: f64,
}

pub fn get_budgets(conn: &Connection) -> Result<Budgets> {
    conn.query_row(
        "SELECT max_depth,max_expand_bytes,max_ratio FROM budgets WHERE id=1",
        [],
        |r| {
            Ok(Budgets {
                max_depth: r.get(0)?,
                max_expand_bytes: r.get(1)?,
                max_ratio: r.get(2)?,
            })
        },
    )
    .map_err(Into::into)
}

pub fn set_budgets(conn: &Connection, b: &Budgets) -> Result<()> {
    conn.execute(
        "UPDATE budgets SET max_depth=?1,max_expand_bytes=?2,max_ratio=?3 WHERE id=1",
        params![b.max_depth, b.max_expand_bytes, b.max_ratio],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusSummary {
    pub sources: i64,
    pub packs: i64,
    pub indexes: i64,
    pub objects: i64,
    pub resolved: i64,
    pub pending: i64,
    pub paused: i64,
    pub blocked: i64,
    pub errored: i64,
    pub distinct_oids: i64,
}

pub fn status_summary(conn: &Connection) -> Result<StatusSummary> {
    let mut s = StatusSummary::default();
    s.sources = conn.query_row("SELECT COUNT(*) FROM sources", [], |r| r.get(0))?;
    s.packs = conn.query_row("SELECT COUNT(*) FROM packs", [], |r| r.get(0))?;
    s.indexes = conn.query_row("SELECT COUNT(*) FROM pack_indexes", [], |r| r.get(0))?;
    s.objects = conn.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
    for (count, state) in [
        (&mut s.resolved, "resolved"),
        (&mut s.pending, "pending"),
        (&mut s.paused, "paused"),
        (&mut s.blocked, "blocked"),
        (&mut s.errored, "error"),
    ] {
        *count = conn.query_row(
            "SELECT COUNT(*) FROM objects WHERE status=?1",
            params![state],
            |r| r.get(0),
        )?;
    }
    s.distinct_oids =
        conn.query_row("SELECT COUNT(DISTINCT oid) FROM objects WHERE oid IS NOT NULL", [], |r| r.get(0))?;
    Ok(s)
}

pub fn source_exists_by_sha256(conn: &Connection, digest: &str) -> Result<Option<i64>> {
    conn.query_row("SELECT id FROM sources WHERE sha256=?1", params![digest], |r| r.get(0))
        .optional()
}

use rusqlite::OptionalExtension;

pub fn list_sources(conn: &Connection) -> Result<Vec<SourceRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,path,orig_name,kind,size,sha256,imported_at,status,error \
         FROM sources ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(SourceRow {
            id: r.get(0)?,
            path: r.get(1)?,
            orig_name: r.get(2)?,
            kind: r.get(3)?,
            size: r.get(4)?,
            sha256: r.get(5)?,
            imported_at: r.get(6)?,
            status: r.get(7)?,
            error: r.get(8)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_source_path(conn: &Connection, id: i64) -> Result<Option<String>> {
    conn.query_row("SELECT path FROM sources WHERE id=?1", params![id], |r| r.get(0))
        .optional()
        .map_err(Into::into)
}
