use rusqlite::Connection;

pub const SCHEMA: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL,
  kind TEXT NOT NULL,            -- pack | idx | loose
  sha256 TEXT NOT NULL,          -- 内容摘要 (sha1 of file bytes)
  size INTEGER NOT NULL,
  imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  origin TEXT NOT NULL,          -- pack | loose
  offset INTEGER NOT NULL,       -- 原始偏移
  raw_type INTEGER NOT NULL DEFAULT 0,
  type_name TEXT,
  declared_size INTEGER NOT NULL DEFAULT 0,
  data_offset INTEGER NOT NULL DEFAULT 0,
  data_len INTEGER NOT NULL DEFAULT 0,
  inflated_size INTEGER NOT NULL DEFAULT 0,
  base_offset INTEGER,
  base_oid TEXT,
  size_spoof INTEGER NOT NULL DEFAULT 0,
  idx_crc INTEGER,
  crc_ok INTEGER,
  parse_error TEXT,
  known_oid TEXT
);
CREATE TABLE IF NOT EXISTS resolutions(
  id INTEGER PRIMARY KEY,
  entry_id INTEGER NOT NULL UNIQUE REFERENCES entries(id) ON DELETE CASCADE,
  oid TEXT,
  status TEXT NOT NULL,          -- ok | blocked | error | paused
  result_type TEXT,
  result_size INTEGER,
  depth INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  run_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS steps(
  id INTEGER PRIMARY KEY,
  resolution_id INTEGER NOT NULL REFERENCES resolutions(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  base_desc TEXT,
  instr_start INTEGER,
  instr_end INTEGER,
  input_len INTEGER,
  output_len INTEGER,
  check_ok INTEGER,
  note TEXT
);
CREATE TABLE IF NOT EXISTS blocks(
  id INTEGER PRIMARY KEY,
  resolution_id INTEGER NOT NULL REFERENCES resolutions(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  reason TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS deps(
  resolution_id INTEGER NOT NULL REFERENCES resolutions(id) ON DELETE CASCADE,
  used_entry_id INTEGER NOT NULL,
  UNIQUE(resolution_id, used_entry_id)
);
CREATE TABLE IF NOT EXISTS pins(
  oid TEXT PRIMARY KEY,
  entry_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS conflicts(
  oid TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  chosen INTEGER NOT NULL DEFAULT 0,
  UNIQUE(oid, entry_id)
);
CREATE TABLE IF NOT EXISTS idx_info(
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  pack_checksum TEXT,
  self_ok INTEGER,
  matched_source_id INTEGER,
  fanout TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT
);
"#;

pub fn open(path: &std::path::Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("打开数据库失败: {e}"))?;
    conn.execute_batch(SCHEMA).map_err(|e| format!("初始化数据库失败: {e}"))?;
    Ok(conn)
}
