//! SQLite persistence: schema and small helpers. Everything stays inside the
//! project data directory.

use rusqlite::{Connection, Result};

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sha1 TEXT NOT NULL,
  kind TEXT NOT NULL,             -- pack | idx | loose
  size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packs(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  num_objects INTEGER NOT NULL,
  trailer_ok INTEGER,
  idx_source_id INTEGER,
  idx_status TEXT NOT NULL DEFAULT 'none'  -- none | matched | mismatched
);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY,
  pack_id INTEGER NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  type_id INTEGER NOT NULL,
  declared_size INTEGER NOT NULL,
  hdr_len INTEGER NOT NULL,
  comp_len INTEGER NOT NULL,
  crc32 INTEGER NOT NULL,
  idx_crc32 INTEGER,
  crc_ok INTEGER,
  base_offset INTEGER,
  base_oid TEXT,
  claimed_oid TEXT,
  inflated BLOB,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS loose_objects(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  claimed_oid TEXT,
  actual_oid TEXT,
  type_name TEXT,
  content BLOB,
  error TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  matched_entry_id INTEGER
);
CREATE TABLE IF NOT EXISTS idx_meta(
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  count INTEGER NOT NULL,
  fanout_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolved(
  key TEXT PRIMARY KEY,           -- 'e:<id>' | 'l:<id>'
  oid TEXT NOT NULL,
  type_name TEXT NOT NULL DEFAULT 'blob',
  content BLOB NOT NULL,
  depth INTEGER NOT NULL,
  run_id INTEGER
);
CREATE TABLE IF NOT EXISTS entry_status(
  key TEXT PRIMARY KEY,
  status TEXT NOT NULL,           -- resolved | error | blocked
  error_kind TEXT,
  error_msg TEXT,
  blockers TEXT                   -- JSON array of chain steps
);
CREATE TABLE IF NOT EXISTS deps(
  child TEXT NOT NULL,
  parent TEXT NOT NULL,
  PRIMARY KEY(child, parent)
);
CREATE TABLE IF NOT EXISTS delta_steps(
  id INTEGER PRIMARY KEY,
  entry_key TEXT NOT NULL,
  base_key TEXT,
  base_oid TEXT,
  instr_offset INTEGER,
  instr_len INTEGER,
  src_size INTEGER,
  tgt_size INTEGER,
  in_len INTEGER,
  out_len INTEGER,
  src_ok INTEGER,
  tgt_ok INTEGER,
  oid TEXT,
  run_id INTEGER
);
CREATE TABLE IF NOT EXISTS pins(
  oid TEXT PRIMARY KEY,
  entry_key TEXT NOT NULL,
  branch TEXT NOT NULL DEFAULT 'default'
);
CREATE TABLE IF NOT EXISTS meta(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY,
  status TEXT NOT NULL,           -- done | paused
  max_depth INTEGER NOT NULL,
  max_total_bytes INTEGER NOT NULL,
  max_object_pct INTEGER NOT NULL,
  expanded_bytes INTEGER NOT NULL DEFAULT 0,
  resolved_count INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub fn open(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn open_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}
