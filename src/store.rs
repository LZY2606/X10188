//! SQLite persistence. All imported bytes stay inside the project data dir.
use rusqlite::Connection;

pub const SCHEMA: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  pack_sha1 TEXT,
  status TEXT NOT NULL DEFAULT 'ok',
  error TEXT,
  imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  type TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  data_offset INTEGER NOT NULL,
  compressed_len INTEGER NOT NULL,
  ofs_distance INTEGER,
  base_offset INTEGER,
  base_oid TEXT,
  crc32 INTEGER NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  raw BLOB NOT NULL,
  UNIQUE(source_id, offset)
);
CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  content BLOB NOT NULL,
  depth INTEGER NOT NULL DEFAULT 0,
  entry_id INTEGER,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE TABLE IF NOT EXISTS delta_steps(
  id INTEGER PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  base_desc TEXT NOT NULL,
  base_oid TEXT,
  base_entry_id INTEGER,
  base_object_id INTEGER,
  instr_range TEXT NOT NULL,
  instr_json TEXT NOT NULL,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_entry ON delta_steps(entry_id);
CREATE TABLE IF NOT EXISTS blocks(
  id INTEGER PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  ref TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS errors(
  id INTEGER PRIMARY KEY,
  source_id INTEGER,
  entry_id INTEGER,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence TEXT
);
CREATE TABLE IF NOT EXISTS idx_files(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  pack_sha1 TEXT NOT NULL,
  idx_sha1 TEXT NOT NULL,
  trailer_ok INTEGER NOT NULL,
  fanout_json TEXT NOT NULL,
  matched_source_id INTEGER
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  idx_id INTEGER NOT NULL REFERENCES idx_files(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pins(
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL UNIQUE,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

pub fn open(path: &std::path::Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("open db: {}", e))?;
    conn.execute_batch(SCHEMA).map_err(|e| format!("schema: {}", e))?;
    Ok(conn)
}

pub fn open_memory() -> Result<Connection, String> {
    let conn = Connection::open_in_memory().map_err(|e| format!("open db: {}", e))?;
    conn.execute_batch(SCHEMA).map_err(|e| format!("schema: {}", e))?;
    Ok(conn)
}
