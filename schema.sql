CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK(kind IN ('pack','idx','loose')),
  byte_size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  imported_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS source_notes (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS object_entries (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  slot INTEGER,
  pack_offset INTEGER,
  header_end INTEGER,
  zlib_start INTEGER,
  zlib_end INTEGER,
  kind INTEGER,
  delta_kind TEXT,
  declared_size INTEGER,
  compressed_len INTEGER,
  actual_len INTEGER,
  claimed_oid TEXT,
  ofs_distance INTEGER,
  ofs_base_offset INTEGER,
  ref_base_oid TEXT,
  index_crc INTEGER,
  observed_crc INTEGER,
  parse_status TEXT NOT NULL,
  parse_error TEXT,
  UNIQUE(source_id, pack_offset),
  UNIQUE(source_id, slot)
);
CREATE INDEX IF NOT EXISTS idx_entries_claimed ON object_entries(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_entries_ref ON object_entries(ref_base_oid);
CREATE TABLE IF NOT EXISTS index_fanout (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  bucket INTEGER NOT NULL,
  cumulative INTEGER NOT NULL,
  UNIQUE(source_id,bucket)
);
CREATE TABLE IF NOT EXISTS index_summary (
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  object_count INTEGER NOT NULL,
  expected_pack_sha TEXT,
  index_sha TEXT,
  observed_pack_sha TEXT,
  observed_index_sha TEXT,
  pack_sha_ok INTEGER NOT NULL,
  index_sha_ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pack_summary (
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  object_count INTEGER NOT NULL,
  header_end INTEGER NOT NULL,
  checksum_sha TEXT NOT NULL,
  observed_checksum_sha TEXT NOT NULL,
  checksum_ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO branches(id,name,created_at) VALUES (1,'default',0);
CREATE TABLE IF NOT EXISTS pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  entry_id INTEGER NOT NULL REFERENCES object_entries(id) ON DELETE CASCADE,
  PRIMARY KEY(branch_id,oid)
);
CREATE TABLE IF NOT EXISTS materializations (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES object_entries(id) ON DELETE CASCADE,
  kind INTEGER,
  output_len INTEGER,
  output BLOB,
  output_oid TEXT,
  status TEXT NOT NULL,
  error_code TEXT,
  error TEXT,
  depth INTEGER,
  block_chain TEXT NOT NULL,
  budget_max_depth INTEGER,
  budget_total_bytes INTEGER,
  budget_single_ratio REAL,
  updated_at INTEGER NOT NULL,
  UNIQUE(branch_id,entry_id)
);
CREATE INDEX IF NOT EXISTS idx_mats_oid ON materializations(output_oid);
CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY,
  materialization_id INTEGER NOT NULL REFERENCES materializations(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  base_entry_id INTEGER REFERENCES object_entries(id) ON DELETE SET NULL,
  base_oid TEXT,
  instruction_start INTEGER,
  instruction_end INTEGER,
  instruction_count INTEGER NOT NULL DEFAULT 0,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  report_json TEXT NOT NULL,
  check_status TEXT NOT NULL,
  check_detail TEXT,
  UNIQUE(materialization_id,ordinal)
);
CREATE TABLE IF NOT EXISTS edge_dirty (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES object_entries(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  PRIMARY KEY(branch_id,entry_id)
);
