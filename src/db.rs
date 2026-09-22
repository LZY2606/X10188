use rusqlite::Connection;

pub fn schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL,
  imported_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  type_code INTEGER NOT NULL,
  declared_size INTEGER NOT NULL,
  data_start INTEGER NOT NULL,
  data_len INTEGER,
  base_offset INTEGER,
  base_oid TEXT,
  crc_expected INTEGER,
  crc_actual INTEGER,
  status TEXT NOT NULL DEFAULT 'parsed',
  error TEXT,
  block_chain TEXT,
  raw BLOB
);
CREATE INDEX IF NOT EXISTS idx_entries_src_off ON entries(source_id, offset);
CREATE TABLE IF NOT EXISTS idx_entries(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idx_meta(
  source_id INTEGER PRIMARY KEY,
  fanout TEXT NOT NULL,
  count INTEGER NOT NULL,
  pack_source_id INTEGER,
  matched INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  type TEXT NOT NULL,
  content BLOB NOT NULL,
  entry_id INTEGER NOT NULL UNIQUE,
  depth INTEGER NOT NULL,
  checksum_ok INTEGER NOT NULL DEFAULT 1,
  resolved_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE TABLE IF NOT EXISTS deps(
  child INTEGER NOT NULL,
  parent INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS delta_steps(
  id INTEGER PRIMARY KEY,
  object_id INTEGER NOT NULL,
  base_desc TEXT NOT NULL,
  instr_json TEXT NOT NULL,
  base_len INTEGER NOT NULL,
  delta_len INTEGER NOT NULL,
  out_len INTEGER NOT NULL,
  checksum_ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY,
  budget TEXT NOT NULL,
  consumed INTEGER NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  oid TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
",
    )
}
