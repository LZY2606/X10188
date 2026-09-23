//! SQLite 存储层：源文件、pack entry、index、loose、候选、还原结果、delta 步骤、分支。
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

pub struct Store {
    pub conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL,
  size INTEGER NOT NULL,
  note TEXT,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pack_meta(
  source_id INTEGER PRIMARY KEY,
  version INTEGER,
  declared_count INTEGER,
  parsed_count INTEGER,
  trailer TEXT,
  trailer_ok INTEGER,
  error TEXT
);
CREATE TABLE IF NOT EXISTS pack_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  kind_code INTEGER NOT NULL,
  kind TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  header_len INTEGER NOT NULL,
  data_offset INTEGER NOT NULL,
  compressed_len INTEGER NOT NULL,
  base_offset INTEGER,
  base_distance INTEGER,
  base_oid TEXT,
  error TEXT,
  data BLOB,
  raw BLOB
);
CREATE TABLE IF NOT EXISTS idx_meta(
  source_id INTEGER PRIMARY KEY,
  version INTEGER,
  pack_checksum TEXT,
  checksum_ok INTEGER,
  fanout TEXT,
  error TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  matched_pack_source_id INTEGER,
  crc_ok INTEGER,
  note TEXT
);
CREATE TABLE IF NOT EXISTS loose_objects(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  content BLOB,
  error TEXT
);
CREATE TABLE IF NOT EXISTS candidates(
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  origin TEXT NOT NULL UNIQUE,
  source_id INTEGER,
  sort_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolutions(
  candidate_id INTEGER PRIMARY KEY,
  status TEXT NOT NULL,
  kind TEXT,
  content BLOB,
  content_len INTEGER,
  computed_oid TEXT,
  oid_ok INTEGER,
  error TEXT,
  blocking TEXT,
  depth INTEGER,
  seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delta_steps(
  candidate_id INTEGER NOT NULL,
  step INTEGER NOT NULL,
  base_desc TEXT,
  base_candidate_id INTEGER,
  base_oid TEXT,
  instr_start INTEGER,
  instr_end INTEGER,
  instr_count INTEGER,
  input_len INTEGER,
  output_len INTEGER,
  ok INTEGER,
  error TEXT
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  oid TEXT NOT NULL,
  pinned_origin TEXT NOT NULL,
  affected TEXT,
  created INTEGER NOT NULL
);
"#;

pub fn pack_origin(digest: &str, offset: u64) -> String {
    format!("pack:{digest}:{offset}")
}
pub fn loose_origin(digest: &str, oid: &str) -> String {
    format!("loose:{digest}:{oid}")
}
pub fn idx_origin(digest: &str, oid: &str) -> String {
    format!("idx:{digest}:{oid}")
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    pub fn get_meta(&self, key: &str) -> Option<String> {
        let conn = self.lock();
        conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0))
            .ok()
    }

    pub fn set_meta(&self, key: &str, value: &str) {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )
        .unwrap();
    }

    pub fn next_seq(&self) -> i64 {
        let cur: i64 = self
            .get_meta("seq")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let next = cur + 1;
        self.set_meta("seq", &next.to_string());
        next
    }
}
