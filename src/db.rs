use rusqlite::Connection;
use std::path::Path;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,               -- pack | idx | loose
  filename TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  imported_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS packs (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  count INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  trailer_sha TEXT NOT NULL,
  trailer_ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idx_files (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  count INTEGER NOT NULL,
  pack_sha TEXT NOT NULL,
  idx_checksum_ok INTEGER NOT NULL,
  linked_pack_id INTEGER REFERENCES packs(id) ON DELETE SET NULL,
  mismatch_reason TEXT,
  fanout_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pack_entries (
  id INTEGER PRIMARY KEY,
  pack_id INTEGER NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
  pack_offset INTEGER NOT NULL,
  obj_type INTEGER NOT NULL,
  type_name TEXT NOT NULL,
  header_size INTEGER NOT NULL,
  compressed_size INTEGER NOT NULL,
  declared_size INTEGER NOT NULL,
  ofs_base_rel INTEGER,
  ref_base TEXT,
  crc32 INTEGER NOT NULL,
  idx_oid TEXT,
  idx_crc32 INTEGER,
  crc_ok INTEGER,
  inflate_outcome TEXT,
  error TEXT,
  UNIQUE(pack_id, pack_offset)
);
CREATE TABLE IF NOT EXISTS loose_objects (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  claimed_oid TEXT NOT NULL,
  computed_oid TEXT NOT NULL,
  type_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  oid_ok INTEGER NOT NULL,
  error TEXT
);
CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  origin_kind TEXT NOT NULL,       -- pack | loose
  entry_id INTEGER,                -- pack_entries.id
  loose_id INTEGER,                -- loose_objects.id
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  pack_id INTEGER,
  pack_offset INTEGER,
  sort_key INTEGER NOT NULL,       -- import-independent ordering key
  UNIQUE(oid, origin_kind, entry_id, loose_id)
);
CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  entry_id INTEGER,
  loose_id INTEGER,
  PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS resolved (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES pack_entries(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  type_name TEXT,
  content BLOB,
  computed_oid TEXT,
  oid_matches_idx INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0,
  bytes_used INTEGER NOT NULL DEFAULT 0,
  depth_used INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  error_message TEXT,
  chain_json TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (branch_id, entry_id)
);
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES pack_entries(id) ON DELETE CASCADE,
  step_index INTEGER NOT NULL,
  base_entry_id INTEGER,
  base_oid TEXT,
  base_source TEXT,
  op_start INTEGER,
  op_end INTEGER,
  op_count INTEGER,
  input_len INTEGER,
  output_len INTEGER,
  check_code TEXT,
  check_ok INTEGER,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS blockers (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES pack_entries(id) ON DELETE CASCADE,
  ord INTEGER NOT NULL,
  blocker_entry_id INTEGER,
  blocker_oid TEXT,
  reason TEXT NOT NULL,
  PRIMARY KEY (branch_id, entry_id, ord)
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cand_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_resolved_status ON resolved(branch_id, status);
        "#,
    )?;
    Ok(())
}
