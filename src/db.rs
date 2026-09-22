use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub fn connect(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "on")?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  stored_path TEXT NOT NULL,
  import_order INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packs (
  source_id TEXT PRIMARY KEY REFERENCES sources(source_id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  entry_count INTEGER NOT NULL,
  checksum TEXT,
  index_source_id TEXT,
  parse_errors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS entries (
  node TEXT PRIMARY KEY,
  pack_source TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  header_end INTEGER NOT NULL,
  compressed_start INTEGER NOT NULL,
  compressed_end INTEGER NOT NULL,
  type_code INTEGER NOT NULL,
  type_name TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  base_offset INTEGER,
  base_oid TEXT,
  expected_oid TEXT,
  parse_error TEXT,
  UNIQUE(pack_source, offset)
);
CREATE TABLE IF NOT EXISTS indexes (
  source_id TEXT PRIMARY KEY REFERENCES sources(source_id) ON DELETE CASCADE,
  pack_source_id TEXT REFERENCES sources(source_id) ON DELETE SET NULL,
  record_count INTEGER NOT NULL,
  pack_checksum TEXT,
  index_checksum TEXT,
  fanout TEXT NOT NULL,
  parse_errors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS index_records (
  index_source TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  offset INTEGER NOT NULL,
  crc INTEGER NOT NULL,
  crc_error TEXT,
  PRIMARY KEY(index_source, offset)
);
CREATE TABLE IF NOT EXISTS loose_objects (
  node TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  type_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS dependencies (
  node TEXT NOT NULL,
  branch_id TEXT NOT NULL DEFAULT 'default',
  base_node TEXT,
  base_oid TEXT,
  kind TEXT NOT NULL,
  PRIMARY KEY(node, branch_id)
);
CREATE TABLE IF NOT EXISTS candidates (
  oid TEXT NOT NULL,
  node TEXT NOT NULL,
  branch_id TEXT NOT NULL DEFAULT 'default',
  source_id TEXT NOT NULL,
  origin_rank INTEGER NOT NULL,
  kind TEXT,
  verified INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0,
  sort_key TEXT NOT NULL,
  PRIMARY KEY(oid, node, branch_id)
);
CREATE TABLE IF NOT EXISTS branches (
  branch_id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  pinned_oid TEXT,
  pinned_node TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS resolved (
  node TEXT NOT NULL,
  branch_id TEXT NOT NULL DEFAULT 'default',
  oid TEXT,
  type_name TEXT,
  size INTEGER,
  status TEXT NOT NULL,
  content BLOB,
  check_ok INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  chain_json TEXT NOT NULL DEFAULT '[]',
  expanded_bytes INTEGER NOT NULL DEFAULT 0,
  depth INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(node, branch_id)
);
CREATE TABLE IF NOT EXISTS delta_steps (
  branch_id TEXT NOT NULL DEFAULT 'default',
  node TEXT NOT NULL,
  step INTEGER NOT NULL,
  base_node TEXT NOT NULL,
  delta_node TEXT NOT NULL,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  instruction_count INTEGER NOT NULL,
  instruction_ranges TEXT NOT NULL,
  check_ok INTEGER NOT NULL,
  check_oid TEXT,
  PRIMARY KEY(branch_id, node, step)
);
CREATE TABLE IF NOT EXISTS blockers (
  branch_id TEXT NOT NULL DEFAULT 'default',
  node TEXT NOT NULL,
  seq INTEGER NOT NULL,
  reason TEXT NOT NULL,
  blocked_node TEXT,
  blocked_oid TEXT,
  chain_json TEXT NOT NULL,
  PRIMARY KEY(branch_id, node, seq)
);
CREATE TABLE IF NOT EXISTS analysis_runs (
  branch_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  total_expanded INTEGER NOT NULL DEFAULT 0,
  max_depth INTEGER NOT NULL DEFAULT 0,
  budget_total INTEGER NOT NULL,
  budget_depth INTEGER NOT NULL,
  budget_single INTEGER NOT NULL,
  budget_ratio INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid, branch_id, origin_rank, sort_key);
CREATE INDEX IF NOT EXISTS idx_entries_base_oid ON entries(base_oid);
CREATE INDEX IF NOT EXISTS idx_resolved_status ON resolved(branch_id, status);
INSERT OR IGNORE INTO branches(branch_id,label) VALUES('default','默认候选');
INSERT OR IGNORE INTO analysis_runs(branch_id,status,total_expanded,max_depth,budget_total,budget_depth,budget_single,budget_ratio)
VALUES('default','idle',0,0,67108864,16,16777216,100);
"#,
    )?;
    Ok(())
}

pub fn next_import_order(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COALESCE(MAX(import_order)+1,0) FROM sources", [], |r| r.get(0))
}

pub fn clear_analysis_for_branch(conn: &Connection, branch: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM delta_steps WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM blockers WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM resolved WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM dependencies WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM candidates WHERE branch_id=?1", params![branch])?;
    Ok(())
}

pub fn upsert_branch_pin(conn: &Connection, oid: &str, node: &str) -> rusqlite::Result<String> {
    let branch = format!("pin-{}", &node.replace(|c: char| !c.is_ascii_alphanumeric(), "-")[..node.len().min(40)]);
    conn.execute(
        "INSERT INTO branches(branch_id,label,pinned_oid,pinned_node) VALUES(?1,?2,?3,?4)
         ON CONFLICT(branch_id) DO UPDATE SET pinned_oid=excluded.pinned_oid,pinned_node=excluded.pinned_node",
        params![branch, format!("固定 {node}"), oid, node],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO analysis_runs(branch_id,status,total_expanded,max_depth,budget_total,budget_depth,budget_single,budget_ratio)
         SELECT ?1,'idle',0,0,budget_total,budget_depth,budget_single,budget_ratio FROM analysis_runs WHERE branch_id='default'",
        params![branch],
    )?;
    Ok(branch)
}

pub fn branch_exists(conn: &Connection, branch: &str) -> rusqlite::Result<bool> {
    Ok(conn.query_row("SELECT 1 FROM branches WHERE branch_id=?1", params![branch], |_| Ok(())).optional()?.is_some())
}
