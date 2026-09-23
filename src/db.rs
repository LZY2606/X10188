use rusqlite::Connection;
use std::path::Path;

pub const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packs(
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER, declared_count INTEGER, parsed_count INTEGER,
  trailer TEXT, trailer_actual TEXT, trailer_ok INTEGER, parse_error TEXT
);
CREATE TABLE IF NOT EXISTS pack_objects(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  type TEXT NOT NULL,
  declared_size INTEGER,
  inflated_size INTEGER,
  data_offset INTEGER,
  compressed_len INTEGER,
  base_kind TEXT,
  base_ofs INTEGER,
  base_oid TEXT,
  size_fraud INTEGER DEFAULT 0,
  crc_idx INTEGER,
  crc_actual INTEGER,
  crc_ok INTEGER,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER,
  offset INTEGER
);
CREATE TABLE IF NOT EXISTS idx_meta(
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  fanout_json TEXT,
  pack_sha1 TEXT,
  idx_sha1_ok INTEGER,
  matched_pack_source_id INTEGER,
  match_status TEXT
);
CREATE TABLE IF NOT EXISTS objects(
  oid TEXT PRIMARY KEY,
  type TEXT,
  size INTEGER,
  status TEXT NOT NULL,
  has_conflict INTEGER DEFAULT 0,
  content_path TEXT
);
CREATE TABLE IF NOT EXISTS candidates(
  id INTEGER PRIMARY KEY,
  oid TEXT,
  type TEXT,
  size INTEGER,
  pack_object_id INTEGER REFERENCES pack_objects(id) ON DELETE CASCADE,
  loose_source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  source_id INTEGER,
  offset INTEGER,
  recomputed_oid TEXT,
  check_status TEXT NOT NULL,
  error_kind TEXT,
  error_detail TEXT,
  blocking_json TEXT,
  chain_sources TEXT,
  content_path TEXT
);
CREATE TABLE IF NOT EXISTS delta_steps(
  id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  step INTEGER,
  base_desc TEXT,
  instr_json TEXT,
  input_len INTEGER,
  output_len INTEGER,
  result_oid TEXT,
  check TEXT
);
CREATE TABLE IF NOT EXISTS paused_states(
  candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
  pack_object_id INTEGER,
  chain_json TEXT,
  applied INTEGER,
  intermediate_path TEXT,
  expanded_bytes INTEGER,
  budget_kind TEXT
);
CREATE TABLE IF NOT EXISTS missing_deps(
  pack_object_id INTEGER NOT NULL REFERENCES pack_objects(id) ON DELETE CASCADE,
  missing_oid TEXT NOT NULL,
  UNIQUE(pack_object_id, missing_oid)
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  pins_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn open_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}
