use rusqlite::Connection;
use std::path::Path;

pub const DEFAULT_BRANCH: i64 = 1;

pub fn open(data_dir: &Path) -> rusqlite::Result<Connection> {
    std::fs::create_dir_all(data_dir.join("objects")).ok();
    let db_path = data_dir.join("microscope.db");
    let mut conn = Connection::open(db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)?;
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM branch WHERE id = ?1",
        rusqlite::params![DEFAULT_BRANCH],
        |r| r.get(0),
    )?;
    if exists == 0 {
        conn.execute(
            "INSERT INTO branch(id, name, created_at) VALUES(?1, 'default', strftime('%s','now'))",
            rusqlite::params![DEFAULT_BRANCH],
        )?;
    }
    let defaults = [
        ("max_depth", "16"),
        ("total_budget_bytes", "16777216"),
        ("single_ratio", "0.5"),
    ];
    for (k, v) in defaults {
        conn.execute(
            "INSERT OR IGNORE INTO setting(key, value) VALUES(?1, ?2)",
            rusqlite::params![k, v],
        )?;
    }
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS source_file (
  id INTEGER PRIMARY KEY,
  object_path TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha1 TEXT NOT NULL,
  imported_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  parse_note TEXT
);

CREATE TABLE IF NOT EXISTS pack_file (
  file_id INTEGER PRIMARY KEY REFERENCES source_file(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  num_entries INTEGER NOT NULL,
  pack_sha TEXT NOT NULL,
  parse_error TEXT
);

CREATE TABLE IF NOT EXISTS idx_file (
  file_id INTEGER PRIMARY KEY REFERENCES source_file(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  num_records INTEGER NOT NULL,
  pack_sha TEXT NOT NULL,
  idx_sha TEXT NOT NULL,
  matched_pack_file INTEGER REFERENCES source_file(id) ON DELETE SET NULL,
  parse_note TEXT
);

CREATE TABLE IF NOT EXISTS loose_object (
  file_id INTEGER PRIMARY KEY REFERENCES source_file(id) ON DELETE CASCADE,
  kind INTEGER,
  declared_size INTEGER,
  computed_oid TEXT,
  claimed_oid TEXT,
  content BLOB,
  parse_error TEXT
);

CREATE TABLE IF NOT EXISTS object_provider (
  id INTEGER PRIMARY KEY,
  kind INTEGER NOT NULL,
  is_delta INTEGER NOT NULL,
  source INTEGER NOT NULL,
  file_id INTEGER NOT NULL REFERENCES source_file(id) ON DELETE CASCADE,
  pack_offset INTEGER,
  claimed_oid TEXT,
  computed_oid TEXT,
  inflated_size INTEGER,
  header_size INTEGER,
  compressed_len INTEGER,
  payload BLOB,
  ofs_target_offset INTEGER,
  ref_target_oid TEXT,
  crc INTEGER,
  crc_ok INTEGER,
  parse_error_code TEXT,
  parse_error TEXT,
  UNIQUE(file_id, pack_offset)
);

CREATE INDEX IF NOT EXISTS idx_provider_claimed ON object_provider(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_provider_computed ON object_provider(computed_oid);

CREATE TABLE IF NOT EXISTS branch (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS pin (
  branch_id INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  provider_id INTEGER NOT NULL REFERENCES object_provider(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolve_run (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  started_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  status TEXT NOT NULL,
  budget_total INTEGER,
  budget_single_cap INTEGER,
  budget_max_depth INTEGER,
  budget_used INTEGER,
  recomputed INTEGER,
  reused INTEGER,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS resolve_result (
  branch_id INTEGER NOT NULL REFERENCES branch(id) ON DELETE CASCADE,
  provider_id INTEGER NOT NULL REFERENCES object_provider(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  depth INTEGER,
  kind INTEGER,
  computed_oid TEXT,
  base_provider_id INTEGER,
  output BLOB,
  output_len INTEGER,
  error_code TEXT,
  error_message TEXT,
  blocking_chain TEXT,
  candidate_json TEXT,
  updated_run INTEGER,
  PRIMARY KEY (branch_id, provider_id)
);

CREATE TABLE IF NOT EXISTS delta_step (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL,
  provider_id INTEGER NOT NULL,
  step INTEGER NOT NULL,
  base_provider_id INTEGER,
  base_oid TEXT,
  body_offset INTEGER,
  body_len INTEGER,
  input_len INTEGER,
  output_len INTEGER,
  verify TEXT,
  UNIQUE(branch_id, provider_id, step)
);

CREATE TABLE IF NOT EXISTS delta_instr (
  step_id INTEGER NOT NULL REFERENCES delta_step(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  op TEXT NOT NULL,
  delta_offset INTEGER,
  delta_len INTEGER,
  src_offset INTEGER,
  src_len INTEGER,
  out_offset INTEGER,
  out_len INTEGER
);

CREATE TABLE IF NOT EXISTS setting (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"#;
