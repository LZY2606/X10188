use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::git::ObjType;

pub mod import;
pub mod resolve;
pub mod query;

pub const DEFAULT_BRANCH: &str = "DEFAULT_MARK";
pub const DEFAULT_MAX_DEPTH: i64 = 50;
pub const DEFAULT_MAX_TOTAL_EXPAND: i64 = 256 * 1024 * 1024;
pub const DEFAULT_SINGLE_OBJECT_RATIO: i64 = 10;
pub const HARD_INFLATE_CAP: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Budget {
    pub max_depth: i64,
    pub max_total_expand: i64,
    pub single_object_ratio: i64,
}

pub struct Engine {
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
    pub conn: Mutex<Connection>,
}

pub fn kind_str(t: ObjType) -> &'static str {
    match t {
        ObjType::Commit => "commit",
        ObjType::Tree => "tree",
        ObjType::Blob => "blob",
        ObjType::Tag => "tag",
        ObjType::OfsDelta => "ofs_delta",
        ObjType::RefDelta => "ref_delta",
    }
}

pub fn parse_kind(s: &str) -> Option<ObjType> {
    Some(match s {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        "ofs_delta" => ObjType::OfsDelta,
        "ref_delta" => ObjType::RefDelta,
        _ => return None,
    })
}

impl Engine {
    pub fn open(data_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir)?;
        let db_path = data_dir.join("microscope.db");
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", "on")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(crate::schema::MIGRATIONS)?;
        let engine = Engine {
            data_dir,
            files_dir,
            conn: Mutex::new(conn),
        };
        engine.bootstrap()?;
        Ok(engine)
    }

    fn bootstrap(&self) -> rusqlite::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO branches(id,name,note) VALUES(1,'main','默认分析分支')",
            [],
        )?;
        let defaults = [
            ("max_depth", DEFAULT_MAX_DEPTH.to_string()),
            ("max_total_expand", DEFAULT_MAX_TOTAL_EXPAND.to_string()),
            (
                "single_object_ratio",
                DEFAULT_SINGLE_OBJECT_RATIO.to_string(),
            ),
        ];
        for (k, v) in defaults {
            db.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?1,?2)",
                params![k, v],
            )?;
        }
        Ok(())
    }

    pub fn budget(&self) -> rusqlite::Result<Budget> {
        let db = self.conn.lock().unwrap();
        Ok(Budget {
            max_depth: self.get_setting(&db, "max_depth", DEFAULT_MAX_DEPTH)?,
            max_total_expand: self
                .get_setting(&db, "max_total_expand", DEFAULT_MAX_TOTAL_EXPAND)?,
            single_object_ratio: self
                .get_setting(&db, "single_object_ratio", DEFAULT_SINGLE_OBJECT_RATIO)?,
        })
    }

    fn get_setting(&self, db: &Connection, key: &str, default: i64) -> rusqlite::Result<i64> {
        let v: Option<String> = db
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .ok();
        Ok(v.and_then(|s| s.parse().ok()).unwrap_or(default))
    }

    pub fn set_budget(
        &self,
        max_depth: Option<i64>,
        max_total_expand: Option<i64>,
        single_object_ratio: Option<i64>,
    ) -> rusqlite::Result<()> {
        let db = self.conn.lock().unwrap();
        let upserts = [
            ("max_depth", max_depth),
            ("max_total_expand", max_total_expand),
            ("single_object_ratio", single_object_ratio),
        ];
        for (k, v) in upserts {
            if let Some(n) = v {
                db.execute(
                    "INSERT INTO settings(key,value) VALUES(?1,?2)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    params![k, n.to_string()],
                )?;
            }
        }
        Ok(())
    }

    pub fn ledger_used(&self, branch_id: i64) -> rusqlite::Result<i64> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT COALESCE(SUM(cost),0) FROM budget_ledger WHERE branch_id=?1",
            params![branch_id],
            |r| r.get(0),
        )
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Deterministic candidate ordering. The import order never participates.
pub fn candidate_rank_key(
    origin: &str,
    idx_present: bool,
    crc_ok: Option<bool>,
    source_id: i64,
    offset: Option<i64>,
) -> String {
    let tier = match (origin, idx_present, crc_ok) {
        ("index", true, Some(true)) => 0,
        ("index", true, Some(false)) => 1,
        ("computed", true, _) => 2,
        ("computed", false, _) => 3,
        ("index", false, _) => 9,
        _ => 5,
    };
    format!("{tier}:{source_id:010}:{:020}", offset.unwrap_or(i64::MAX))
}
