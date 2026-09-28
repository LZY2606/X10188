//! SQLite 持久化 + 项目数据目录中的原始文件 / 展开内容存储。

use crate::types::{Budget, Evidence, ObjOrigin, ObjState};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    pub data_dir: PathBuf,
    pub conn: Mutex<Connection>,
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Store {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir.join("files"))?;
        std::fs::create_dir_all(data_dir.join("inflated"))?;
        let db_path = data_dir.join("packscope.db");
        let mut conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        migrate(&mut conn)?;
        Ok(Store {
            data_dir: data_dir.to_path_buf(),
            conn: Mutex::new(conn),
        })
    }

    pub fn files_dir(&self) -> PathBuf {
        self.data_dir.join("files")
    }

    pub fn inflated_path(&self, object_id: i64) -> PathBuf {
        self.data_dir.join("inflated").join(format!("{object_id:010}.bin"))
    }

    pub fn resolved_path(&self, branch_id: i64, oid_hex: &str) -> PathBuf {
        self.data_dir
            .join("inflated")
            .join(format!("b{branch_id}_{oid_hex}.bin"))
    }

    pub fn write_inflated(&self, object_id: i64, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.inflated_path(object_id), data)
    }

    pub fn read_inflated(&self, object_id: i64) -> Option<Vec<u8>> {
        std::fs::read(self.inflated_path(object_id)).ok()
    }

    pub fn write_resolved(
        &self,
        branch_id: i64,
        oid_hex: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        std::fs::write(self.resolved_path(branch_id, oid_hex), data)
    }

    pub fn read_resolved(&self, branch_id: i64, oid_hex: &str) -> Option<Vec<u8>> {
        std::fs::read(self.resolved_path(branch_id, oid_hex)).ok()
    }

    pub fn remove_resolved_for_branch(&self, branch_id: i64) {
        let prefix = format!("b{branch_id}_");
        if let Ok(rd) = std::fs::read_dir(self.data_dir.join("inflated")) {
            for ent in rd.flatten() {
                if let Some(name) = ent.file_name().to_str() {
                    if name.starts_with(&prefix) {
                        std::fs::remove_file(ent.path()).ok();
                    }
                }
            }
        }
    }
}

fn migrate(conn: &mut Connection) -> std::io::Result<()> {
    conn.execute_batch(SCHEMA).map_err(io_err)?;
    let has_default: Option<i64> = conn
        .query_row("SELECT id FROM branches WHERE id=1", [], |r| r.get(0))
        .optional()
        .map_err(io_err)?;
    if has_default.is_none() {
        conn.execute(
            "INSERT INTO branches(id, name, note, created_at) VALUES(1, 'default', '默认分析分支', ?1)",
            params![now_ms()],
        )
        .map_err(io_err)?;
        let b = Budget::defaults();
        conn.execute(
            "INSERT INTO budget(branch_id, max_depth, total_bytes, spent_bytes, per_object_ratio)
             VALUES(1, ?1, ?2, ?3, ?4)",
            params![b.max_depth, b.total_bytes, b.spent_bytes, b.per_object_ratio],
        )
        .map_err(io_err)?;
    }
    Ok(())
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,                 -- pack | idx | loose | unknown
    pack_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    imported_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS source_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    detail TEXT NOT NULL,
    offset_value INTEGER
);

CREATE TABLE IF NOT EXISTS objects (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,               -- ObjOrigin JSON
    entry_kind TEXT NOT NULL,          -- commit|tree|blob|tag|ofs_delta|ref_delta|loose
    entry_offset INTEGER,
    zlib_offset INTEGER,
    zlib_len INTEGER,
    declared_size INTEGER,
    inflated_size INTEGER,
    adler_ok INTEGER NOT NULL DEFAULT 0,
    idx_crc_ok INTEGER,
    computed_oid TEXT,                  -- 非 delta 重算结果
    claimed_oid TEXT,                   -- idx / loose 路径声称
    ofs_base_offset INTEGER,
    ref_base_oid TEXT,
    raw_state TEXT NOT NULL,           -- raw|corrupt|paused
    evidences TEXT NOT NULL DEFAULT '[]',
    raw_order INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_objects_source ON objects(source_id);
CREATE INDEX IF NOT EXISTS idx_objects_computed ON objects(computed_oid);
CREATE INDEX IF NOT EXISTS idx_objects_claimed ON objects(claimed_oid);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    note TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS budget (
    branch_id INTEGER PRIMARY KEY REFERENCES branches(id) ON DELETE CASCADE,
    max_depth INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    spent_bytes INTEGER NOT NULL,
    per_object_ratio REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS resolutions (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    state TEXT NOT NULL,               -- resolved|corrupt|blocked|paused
    result_oid TEXT,
    type TEXT,
    result_size INTEGER,
    depth INTEGER,
    blocked_chain TEXT,                -- JSON: 阻塞链
    evidences TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (branch_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_res_state ON resolutions(branch_id, state);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL,
    object_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    base TEXT NOT NULL,
    cmd_ranges TEXT NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    base_size_declared INTEGER NOT NULL,
    result_size_declared INTEGER NOT NULL,
    verify TEXT NOT NULL,
    UNIQUE(branch_id, object_id, step_index)
);
"#;

/// 行类型（store -> importer/resolver/web 之间传输）。
#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub id: i64,
    pub source_id: i64,
    pub origin: ObjOrigin,
    pub entry_kind: String,
    pub entry_offset: Option<i64>,
    pub zlib_offset: Option<i64>,
    pub zlib_len: Option<i64>,
    pub declared_size: Option<i64>,
    pub inflated_size: Option<i64>,
    pub adler_ok: bool,
    pub idx_crc_ok: Option<bool>,
    pub computed_oid: Option<String>,
    pub claimed_oid: Option<String>,
    pub ofs_base_offset: Option<i64>,
    pub ref_base_oid: Option<String>,
    pub raw_state: String,
    pub evidences: Vec<Evidence>,
}

impl Store {
    pub fn get_object(&self, id: i64) -> Option<ObjectRow> {
        let conn = self.conn.lock().unwrap();
        read_object(&conn, id)
    }

    pub fn list_objects(&self) -> Vec<ObjectRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM objects ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([], map_object)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        rows
    }

    pub fn budget(&self, branch_id: i64) -> Budget {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT max_depth, total_bytes, spent_bytes, per_object_ratio
             FROM budget WHERE branch_id=?1",
            params![branch_id],
            |r| {
                Ok(Budget {
                    max_depth: r.get(0)?,
                    total_bytes: r.get(1)?,
                    spent_bytes: r.get(2)?,
                    per_object_ratio: r.get(3)?,
                })
            },
        )
        .unwrap_or_else(|_| Budget::defaults())
    }

    pub fn set_budget(&self, branch_id: i64, b: Budget) {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE budget SET max_depth=?1, total_bytes=?2, spent_bytes=?3,
             per_object_ratio=?4 WHERE branch_id=?5",
            params![
                b.max_depth,
                b.total_bytes,
                b.spent_bytes,
                b.per_object_ratio,
                branch_id
            ],
        )
        .unwrap();
    }

    pub fn add_spent(&self, branch_id: i64, bytes: i64) {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE budget SET spent_bytes = spent_bytes + ?1 WHERE branch_id=?2",
            params![bytes, branch_id],
        )
        .unwrap();
    }

    pub fn active_branch(&self) -> i64 {
        1
    }
}

pub(crate) fn map_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectRow> {
    let origin_str: String = row.get("origin")?;
    let ev_str: String = row.get("evidences")?;
    Ok(ObjectRow {
        id: row.get("id")?,
        source_id: row.get("source_id")?,
        origin: ObjOrigin::decode(&origin_str)
            .unwrap_or(ObjOrigin::Loose { source_id: row.get("source_id")? }),
        entry_kind: row.get("entry_kind")?,
        entry_offset: row.get("entry_offset")?,
        zlib_offset: row.get("zlib_offset")?,
        zlib_len: row.get("zlib_len")?,
        declared_size: row.get("declared_size")?,
        inflated_size: row.get("inflated_size")?,
        adler_ok: row.get::<_, i64>("adler_ok")? != 0,
        idx_crc_ok: row
            .get::<_, Option<i64>>("idx_crc_ok")?
            .map(|v| v != 0),
        computed_oid: row.get("computed_oid")?,
        claimed_oid: row.get("claimed_oid")?,
        ofs_base_offset: row.get("ofs_base_offset")?,
        ref_base_oid: row.get("ref_base_oid")?,
        raw_state: row.get("raw_state")?,
        evidences: Evidence::decode(&ev_str),
    })
}

pub(crate) fn read_object(conn: &Connection, id: i64) -> Option<ObjectRow> {
    conn.query_row("SELECT * FROM objects WHERE id=?1", params![id], map_object)
        .ok()
}

pub fn state_name(s: ObjState) -> &'static str {
    s.name()
}
