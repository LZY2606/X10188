//! SQLite persistence. All imported bytes and derived state live under the
//! project data directory (`data/`), never outside it.

use crate::error::Result;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    pub conn: Mutex<Connection>,
}

pub const SCHEMA_VERSION: i64 = 1;

pub fn open(db_path: &Path) -> Result<Store> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "on")?;
    let store = Store {
        conn: Mutex::new(conn),
    };
    store.migrate()?;
    Ok(store)
}

impl Store {
    fn migrate(&self) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                 -- pack | idx | loose | unknown
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha1 BLOB NOT NULL,
  imported_at INTEGER NOT NULL,
  pack_source_id INTEGER REFERENCES sources(id),
  pair_note TEXT,
  pack_version INTEGER,
  object_count INTEGER,
  pack_sha_claimed BLOB,
  pack_sha_computed BLOB,
  pack_sha_ok INTEGER,
  idx_version INTEGER,
  idx_sha_ok INTEGER,
  fanout TEXT
);

CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  kind TEXT NOT NULL,                 -- pack | loose
  offset INTEGER NOT NULL DEFAULT 0,
  end_offset INTEGER NOT NULL DEFAULT 0,
  type TEXT NOT NULL,                 -- blob|tree|commit|tag|ofs-delta|ref-delta
  declared_size INTEGER,
  inflated BLOB,
  inflated_len INTEGER NOT NULL DEFAULT 0,
  zlib_len INTEGER,
  crc_computed INTEGER,
  crc_idx INTEGER,
  crc_ok INTEGER,
  ofs_neg INTEGER,
  ref_base BLOB,
  loose_oid BLOB,
  claimed_oid BLOB,
  claim_kind TEXT,                    -- idx | loose-name
  computed_oid BLOB,
  out_type TEXT,
  out_content BLOB,
  out_len INTEGER,
  status INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  parse_error TEXT,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_entries_status ON entries(status);
CREATE INDEX IF NOT EXISTS idx_entries_computed ON entries(computed_oid);
CREATE INDEX IF NOT EXISTS idx_entries_claimed ON entries(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_entries_offset ON entries(source_id, offset);

CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL REFERENCES entries(id),
  step INTEGER NOT NULL,
  base_entry_id INTEGER REFERENCES entries(id),
  base_oid BLOB,
  base_offset INTEGER,
  base_kind TEXT,
  delta_cmd_range_start INTEGER,
  delta_cmd_range_end INTEGER,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  instructions TEXT NOT NULL,
  base_hash_input TEXT,
  base_hash_output TEXT,
  output_hash TEXT,
  verified INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_entry ON delta_steps(entry_id);

CREATE TABLE IF NOT EXISTS pins (
  oid BLOB PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id),
  created_at INTEGER NOT NULL
);
"#,
        )?;
        let v: i64 = c
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if v < SCHEMA_VERSION {
            c.execute(
                "INSERT INTO meta(key,value) VALUES('schema_version',?1)
                 ON CONFLICT(key) DO UPDATE SET value=?1",
                [SCHEMA_VERSION.to_string()],
            )?;
        }
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Option<String> {
        self.conn
            .lock()
            .unwrap()
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .ok()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=?2",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }
}
