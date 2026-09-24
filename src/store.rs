//! SQLite-backed persistence. Everything stays inside the project data dir:
//! original imports under `imports/`, expanded content under `objects/`,
//! and the database at `microscope.db`.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SCHEMA: &str = include_str!("schema.sql");

#[derive(Debug, Clone)]
pub struct DbSource {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub sha256: String,
    pub size: i64,
    pub imported_at: String,
}

#[derive(Debug, Clone)]
pub struct DbEntry {
    pub id: i64,
    pub source_id: i64,
    pub pack_source_id: Option<i64>,
    pub oid: String,
    pub kind: String,
    pub role: String,
    pub offset: Option<i64>,
    pub data_offset: Option<i64>,
    pub compressed_len: Option<i64>,
    pub declared_size: i64,
    pub ofs_distance: Option<i64>,
    pub ref_base: Option<String>,
    pub has_payload: bool,
    pub parse_error: Option<String>,
    pub idx_crc_ok: Option<bool>,
    pub content_blob: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DbResolution {
    pub branch: String,
    pub entry_id: i64,
    pub status: String,
    pub depth: i64,
    pub content_sha256: Option<String>,
    pub content_len: i64,
    pub git_oid: Option<String>,
    pub oid_ok: bool,
    pub error: Option<String>,
    pub blocking_chain: Option<String>,
}

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

impl Store {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir.join("imports"))?;
        std::fs::create_dir_all(data_dir.join("objects"))?;
        let db_path = data_dir.join("microscope.db");
        let conn = Connection::open(db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode=WAL;")
            .map_err(io_err)?;
        conn.execute_batch(SCHEMA).map_err(io_err)?;
        Ok(Store {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.data_dir.join("objects")
    }

    pub fn imports_dir(&self) -> PathBuf {
        self.data_dir.join("imports")
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap()
    }

    pub fn set_setting(&self, key: &str, value: &str) {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .unwrap();
    }

    pub fn list_sources(&self) -> Vec<DbSource> {
        self.conn
            .lock()
            .unwrap()
            .prepare("SELECT id,filename,kind,sha256,size,imported_at FROM sources ORDER BY id")
            .unwrap()
            .query_map([], |r| {
                Ok(DbSource {
                    id: r.get(0)?,
                    filename: r.get(1)?,
                    kind: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get(4)?,
                    imported_at: r.get(5)?,
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    pub fn source_by_id(&self, id: i64) -> Option<DbSource> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id,filename,kind,sha256,size,imported_at FROM sources WHERE id=?1",
                params![id],
                |r| {
                    Ok(DbSource {
                        id: r.get(0)?,
                        filename: r.get(1)?,
                        kind: r.get(2)?,
                        sha256: r.get(3)?,
                        size: r.get(4)?,
                        imported_at: r.get(5)?,
                    })
                },
            )
            .optional()
            .unwrap()
    }

    pub fn source_by_sha(&self, sha: &str) -> Option<DbSource> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id,filename,kind,sha256,size,imported_at FROM sources WHERE sha256=?1",
                params![sha],
                |r| {
                    Ok(DbSource {
                        id: r.get(0)?,
                        filename: r.get(1)?,
                        kind: r.get(2)?,
                        sha256: r.get(3)?,
                        size: r.get(4)?,
                        imported_at: r.get(5)?,
                    })
                },
            )
            .optional()
            .unwrap()
    }

    pub fn entries_of_source(&self, source_id: i64) -> Vec<DbEntry> {
        self.query_entries("WHERE source_id=?1 ORDER BY id", params![source_id])
    }

    pub fn all_entries(&self) -> Vec<DbEntry> {
        self.query_entries("ORDER BY oid, id", params![])
    }

    pub fn entry_by_id(&self, id: i64) -> Option<DbEntry> {
        self.query_entries("WHERE id=?1", params![id]).pop()
    }

    fn query_entries(&self, tail: &str, p: &[&dyn rusqlite::ToSql]) -> Vec<DbEntry> {
        let sql = format!(
            "SELECT id,source_id,pack_source_id,oid,kind,role,offset,data_offset,\
                    compressed_len,declared_size,ofs_distance,ref_base,has_payload,\
                    parse_error,idx_crc_ok,content FROM entries {tail}"
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt
            .query_map(p, |r| {
                Ok(DbEntry {
                    id: r.get(0)?,
                    source_id: r.get(1)?,
                    pack_source_id: r.get(2)?,
                    oid: r.get(3)?,
                    kind: r.get(4)?,
                    role: r.get(5)?,
                    offset: r.get(6)?,
                    data_offset: r.get(7)?,
                    compressed_len: r.get(8)?,
                    declared_size: r.get(9)?,
                    ofs_distance: r.get(10)?,
                    ref_base: r.get(11)?,
                    has_payload: r.get(12)?,
                    parse_error: r.get(13)?,
                    idx_crc_ok: r.get(14)?,
                    content_blob: r.get(15)?,
                })
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    pub fn resolution(&self, branch: &str, entry_id: i64) -> Option<DbResolution> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT branch,entry_id,status,depth,content_sha256,content_len,git_oid,\
                        oid_ok,error,blocking_chain FROM resolutions \
                 WHERE branch=?1 AND entry_id=?2",
                params![branch, entry_id],
                map_resolution,
            )
            .optional()
            .unwrap()
    }

    pub fn resolutions_of(&self, branch: &str) -> Vec<DbResolution> {
        self.conn
            .lock()
            .unwrap()
            .prepare(
                "SELECT branch,entry_id,status,depth,content_sha256,content_len,git_oid,\
                        oid_ok,error,blocking_chain FROM resolutions \
                 WHERE branch=?1 ORDER BY entry_id",
            )
            .unwrap()
            .query_map(params![branch], map_resolution)
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    pub fn branches(&self) -> Vec<String> {
        self.conn
            .lock()
            .unwrap()
            .prepare("SELECT name FROM branches ORDER BY created_at, name")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    pub fn source_pack_match(&self, source_id: i64) -> Option<i64> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT pack_source_id FROM sources WHERE id=?1 AND pack_source_id IS NOT NULL",
                params![source_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .unwrap()
    }
}

fn map_resolution(r: &rusqlite::Row<'_>) -> rusqlite::Result<DbResolution> {
    Ok(DbResolution {
        branch: r.get(0)?,
        entry_id: r.get(1)?,
        status: r.get(2)?,
        depth: r.get(3)?,
        content_sha256: r.get(4)?,
        content_len: r.get(5)?,
        git_oid: r.get(6)?,
        oid_ok: r.get(7)?,
        error: r.get(8)?,
        blocking_chain: r.get(9)?,
    })
}

pub fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
