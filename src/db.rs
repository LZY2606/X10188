use rusqlite::Connection;

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha1 TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL,
  stored_path TEXT NOT NULL,
  link_checksum TEXT,
  imported_at TEXT NOT NULL,
  parse_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pack_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  kind TEXT NOT NULL,
  size_declared INTEGER NOT NULL,
  base_offset INTEGER,
  base_distance INTEGER,
  base_oid TEXT,
  inflated BLOB,
  delta_base_size INTEGER,
  delta_result_size INTEGER,
  crc32 INTEGER NOT NULL DEFAULT 0,
  claimed_oid TEXT,
  idx_crc32 INTEGER,
  crc_ok INTEGER,
  parse_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_source ON pack_entries(source_id, offset);
CREATE TABLE IF NOT EXISTS loose_objects(
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  kind TEXT,
  size_declared INTEGER,
  payload BLOB,
  claimed_oid TEXT,
  computed_oid TEXT,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS objects(
  oid TEXT PRIMARY KEY,
  kind TEXT,
  size INTEGER,
  status TEXT NOT NULL,
  content BLOB,
  steps_json TEXT NOT NULL DEFAULT '[]',
  blocked_json TEXT NOT NULL DEFAULT '[]',
  error TEXT,
  occ_key TEXT,
  updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidates(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  oid TEXT NOT NULL,
  occ_key TEXT NOT NULL,
  source_id INTEGER NOT NULL,
  source_name TEXT NOT NULL,
  entry_id INTEGER,
  offset INTEGER NOT NULL DEFAULT 0,
  claimed INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  crc_ok INTEGER,
  UNIQUE(oid, occ_key)
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE TABLE IF NOT EXISTS edges(
  parent TEXT NOT NULL,
  child TEXT NOT NULL,
  PRIMARY KEY(parent, child)
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  pins_json TEXT NOT NULL DEFAULT '{}'
);
"#;

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}
