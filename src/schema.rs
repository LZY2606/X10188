use rusqlite::Connection;
use std::path::Path;

pub fn open_conn(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    init(&conn)?;
    Ok(conn)
}

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(r#"
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  original_name TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at INTEGER NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}',
  paired_source_id INTEGER,
  errors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  kind TEXT NOT NULL,
  claimed_oid TEXT,
  actual_oid TEXT,
  object_type TEXT,
  pack_offset INTEGER,
  payload_offset INTEGER,
  end_offset INTEGER,
  header_size INTEGER,
  inflated_size INTEGER,
  compressed_size INTEGER,
  base_claim TEXT,
  base_offset INTEGER,
  integrity TEXT NOT NULL DEFAULT 'unverified',
  status TEXT NOT NULL DEFAULT 'discovered',
  error TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  UNIQUE(source_id, kind, pack_offset)
);
CREATE INDEX IF NOT EXISTS idx_candidates_claimed ON candidates(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_actual ON candidates(actual_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id),
  PRIMARY KEY(branch_id, oid)
);
CREATE TABLE IF NOT EXISTS resolutions (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id),
  run_id INTEGER NOT NULL,
  state TEXT NOT NULL,
  actual_oid TEXT,
  object_type TEXT,
  content_path TEXT,
  output_size INTEGER,
  delta_depth INTEGER NOT NULL DEFAULT 0,
  charged_bytes INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  PRIMARY KEY(branch_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS idx_res_oid ON resolutions(branch_id, actual_oid, state);
CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL,
  candidate_id INTEGER NOT NULL,
  position INTEGER NOT NULL,
  base_candidate_id INTEGER,
  base_oid TEXT,
  instruction_start INTEGER NOT NULL,
  instruction_end INTEGER NOT NULL,
  base_size INTEGER NOT NULL,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  check_ok INTEGER NOT NULL,
  details TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
  branch_id INTEGER NOT NULL,
  candidate_id INTEGER NOT NULL,
  base_candidate_id INTEGER,
  base_oid TEXT,
  PRIMARY KEY(branch_id, candidate_id, base_candidate_id, base_oid)
);
CREATE TABLE IF NOT EXISTS blockers (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL,
  candidate_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  base_candidate_id INTEGER,
  base_oid TEXT,
  reason TEXT NOT NULL,
  chain TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS runs (
  branch_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  state TEXT NOT NULL,
  used_bytes INTEGER NOT NULL,
  queue TEXT NOT NULL DEFAULT '[]',
  active_chain TEXT NOT NULL DEFAULT '[]',
  updated_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO branches(id,name,created_at) VALUES (1,'默认',strftime('%s','now'));
"#)
}
