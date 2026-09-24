use rusqlite::Connection;
use std::path::Path;

pub fn open(path: &Path) -> Connection {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("创建数据目录失败");
    }
    let conn = Connection::open(path).expect("打开 SQLite 失败");
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .expect("pragma 失败");
    init(&conn);
    conn
}

pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("内存数据库");
    init(&conn);
    conn
}

pub fn init(conn: &Connection) {
    conn.execute_batch(SCHEMA).expect("初始化 schema 失败");
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL,
  kind TEXT NOT NULL,           -- pack | index | loose | unknown
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS packs(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  version INTEGER,
  num_objects INTEGER,
  trailer TEXT,
  checksum_ok INTEGER NOT NULL DEFAULT 1,
  error TEXT
);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY,
  pack_id INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  header_len INTEGER NOT NULL,
  data_offset INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  otype TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  base_offset INTEGER,
  base_oid TEXT,
  raw BLOB,
  raw_len INTEGER NOT NULL DEFAULT 0,
  parse_error TEXT,
  crc_actual INTEGER,
  crc_expected INTEGER,
  crc_ok INTEGER
);
CREATE TABLE IF NOT EXISTS indexes_t(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  pack_source_id INTEGER,
  count INTEGER NOT NULL DEFAULT 0,
  fanout TEXT NOT NULL DEFAULT '[]',
  pack_checksum TEXT,
  self_ok INTEGER NOT NULL DEFAULT 1,
  error TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  index_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS loose_t(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  oid TEXT,
  otype TEXT,
  size INTEGER,
  content BLOB,
  error TEXT
);
CREATE TABLE IF NOT EXISTS resolutions(
  node_kind TEXT NOT NULL,      -- entry | loose
  node_id INTEGER NOT NULL,
  oid TEXT,
  status TEXT NOT NULL,         -- resolved | blocked | paused
  otype TEXT,
  size INTEGER,
  content BLOB,
  depth INTEGER NOT NULL DEFAULT 0,
  block_reason TEXT,
  blocking_chain TEXT,
  pause_state TEXT,
  run_id INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(node_kind, node_id)
);
CREATE TABLE IF NOT EXISTS steps(
  id INTEGER PRIMARY KEY,
  owner_kind TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  base_desc TEXT,
  instr_offset INTEGER,
  instr_len INTEGER,
  input_len INTEGER,
  output_len INTEGER,
  result_oid TEXT,
  ok INTEGER NOT NULL DEFAULT 1,
  note TEXT
);
CREATE TABLE IF NOT EXISTS uses(
  owner_kind TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  used_kind TEXT NOT NULL,
  used_id INTEGER NOT NULL,
  PRIMARY KEY(owner_kind, owner_id, used_kind, used_id)
);
CREATE TABLE IF NOT EXISTS needs(
  owner_kind TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  need_oid TEXT NOT NULL,
  PRIMARY KEY(owner_kind, owner_id, need_oid)
);
CREATE TABLE IF NOT EXISTS errors(
  id INTEGER PRIMARY KEY,
  scope TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence TEXT,
  run_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS budgets(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  max_depth INTEGER NOT NULL,
  max_total_bytes INTEGER NOT NULL,
  max_ratio REAL NOT NULL
);
INSERT OR IGNORE INTO budgets(id, max_depth, max_total_bytes, max_ratio)
VALUES(1, 64, 268435456, 1000.0);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL
);
INSERT OR IGNORE INTO branches(id, name) VALUES(1, 'main');
CREATE TABLE IF NOT EXISTS pins(
  branch_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  node_kind TEXT NOT NULL,
  node_id INTEGER NOT NULL,
  PRIMARY KEY(branch_id, oid)
);
"#;

pub fn meta_get(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .ok()
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) {
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![key, value],
    )
    .expect("meta 写入失败");
}
