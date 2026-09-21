//! SQLite + content-addressed object storage under the project data dir.

use crate::error::{AppError, AppResult};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Store {
    pub data_dir: PathBuf,
    pub objects_dir: PathBuf,
}

impl Store {
    pub fn open(data_dir: &Path) -> AppResult<(Connection, Store)> {
        fs::create_dir_all(data_dir)?;
        let objects_dir = data_dir.join("objects");
        fs::create_dir_all(&objects_dir)?;
        let db_path = data_dir.join("microscope.db");
        let mut conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let schema = include_str!("schema.sql");
        conn.execute_batch(schema)?;
        Ok((
            conn,
            Store {
                data_dir: data_dir.to_path_buf(),
                objects_dir,
            },
        ))
    }

    pub fn sha256(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    /// Hash-addressed content write (idempotent). Returns relative path.
    pub fn write_content(&self, data: &[u8]) -> AppResult<(String, String)> {
        let hash = Self::sha256(data);
        let rel = format!("{}/{}", &hash[0..2], &hash[2..]);
        let full = self.objects_dir.join(&rel);
        if !full.exists() {
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&full, data)?;
        }
        Ok((hash, rel))
    }

    pub fn read_content(&self, rel: &str) -> AppResult<Vec<u8>> {
        Ok(fs::read(self.objects_dir.join(rel))?)
    }

    pub fn preview(rel: &str) -> std::borrow::Cow<'static, str> {
        String::new().into()
    }
}

pub fn next_seq(conn: &Connection, key: &str) -> AppResult<i64> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER)+1 AS TEXT)",
        [key],
    )?;
    let v: String = conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| {
        r.get(0)
    })?;
    Ok(v.parse().unwrap_or(1))
}

pub fn current_seq(conn: &Connection, key: &str) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0)
}

pub fn ensure_default_branch(conn: &Connection) -> AppResult<()> {
    let exists: i64 =
        conn.query_row("SELECT COUNT(*) FROM branches WHERE name='default'", [], |r| {
            r.get(0)
        })?;
    if exists == 0 {
        conn.execute(
            "INSERT INTO branches(name, created_seq, depth_limit, byte_budget, ratio_limit)
             VALUES('default', 0, ?1, ?2, ?3)",
            rusqlite::params![16, 16 * 1024 * 1024, 32],
        )?;
        let bid: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO budget(branch_id, depth_limit, byte_budget, ratio_limit)
             VALUES(?1, 16, 16*1024*1024, 32)",
            [bid],
        )?;
    }
    Ok(())
}

pub fn db_err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::Db(e.to_string())
}
