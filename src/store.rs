use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::schema::MIGRATION;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
}

impl Config {
    pub fn new(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir)?;
        Ok(Self { data_dir, files_dir })
    }
}

pub struct Store {
    pub conn: Mutex<Connection>,
    pub config: Config,
}

impl Store {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let config = Config::new(data_dir)?;
        let path = config.data_dir.join("microscope.sqlite");
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(MIGRATION)?;
        Ok(Self {
            conn: Mutex::new(conn),
            config,
        })
    }

    pub fn in_dir(path: &Path) -> PathBuf {
        path.join("microscope.sqlite")
    }
}

pub fn next_import_seq(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COALESCE(MAX(import_seq), 0) + 1 FROM sources", [], |r| r.get(0))?)
}

pub fn optional_string(value: Option<String>) -> Option<String> {
    value
}

pub fn store_err<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Sql(message.into()))
}

#[allow(dead_code)]
pub fn params_opt<'a>(value: &'a Option<String>) -> &'a dyn rusqlite::ToSql {
    if let Some(v) = value {
        v
    } else {
        &rusqlite::types::Null
    }
}
