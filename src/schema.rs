pub const MIGRATION: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS sources (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL,
  disk_path TEXT NOT NULL,
  import_seq INTEGER NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS source_digests (
  content_sha256 TEXT PRIMARY KEY,
  size INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  offset INTEGER,
  header_end INTEGER,
  data_end INTEGER,
  compressed_len INTEGER,
  object_type TEXT,
  type_code INTEGER,
  declared_size INTEGER,
  actual_size INTEGER,
  expected_oid TEXT,
  actual_oid TEXT,
  base_offset INTEGER,
  base_oid TEXT,
  delta_source_size INTEGER,
  delta_target_size INTEGER,
  parse_error TEXT,
  dirty INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS packs (
  source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  object_count INTEGER NOT NULL,
  data_end INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  checksum_ok INTEGER NOT NULL,
  fatal_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE INDEX IF NOT EXISTS idx_candidates_expected ON candidates(expected_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_actual ON candidates(actual_oid);
CREATE TABLE IF NOT EXISTS candidate_edges (
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  edge_kind TEXT NOT NULL,
  base_offset INTEGER,
  base_oid TEXT,
  UNIQUE(candidate_id, edge_kind, base_offset, base_oid)
);
CREATE INDEX IF NOT EXISTS idx_edges_oid ON candidate_edges(base_oid);
CREATE INDEX IF NOT EXISTS idx_edges_offset ON candidate_edges(base_offset);
CREATE TABLE IF NOT EXISTS parsed_indexes (
  source_id TEXT PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  pack_checksum TEXT NOT NULL,
  matched_pack_source TEXT REFERENCES sources(id) ON DELETE SET NULL,
  checksum_ok INTEGER NOT NULL,
  errors TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS index_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  index_source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  offset INTEGER NOT NULL,
  expected_crc INTEGER,
  crc_ok INTEGER,
  UNIQUE(index_source_id, offset)
);
CREATE INDEX IF NOT EXISTS idx_index_oid ON index_entries(oid);
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  budget_depth INTEGER NOT NULL,
  budget_bytes INTEGER NOT NULL,
  single_object_ratio INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS pins (
  analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  target_oid TEXT NOT NULL,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  PRIMARY KEY (analysis_id, target_oid)
);
CREATE TABLE IF NOT EXISTS analysis_expenses (
  analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  note TEXT NOT NULL,
  PRIMARY KEY (analysis_id, candidate_id, note)
);
CREATE TABLE IF NOT EXISTS materializations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  base_candidate_id TEXT REFERENCES candidates(id) ON DELETE CASCADE,
  object_type TEXT NOT NULL,
  actual_oid TEXT NOT NULL,
  output_len INTEGER NOT NULL,
  body BLOB NOT NULL,
  depth INTEGER NOT NULL,
  created_analysis TEXT NOT NULL,
  cache_key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS analysis_results (
  analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  object_type TEXT,
  actual_oid TEXT,
  output_len INTEGER,
  depth INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  blocked_chain TEXT,
  materialization_id INTEGER REFERENCES materializations(id) ON DELETE SET NULL,
  PRIMARY KEY (analysis_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  base_candidate_id TEXT,
  base_oid TEXT,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  instruction_start INTEGER NOT NULL,
  instruction_end INTEGER NOT NULL,
  instruction_ranges TEXT NOT NULL,
  check_status TEXT NOT NULL,
  expected_oid TEXT,
  actual_oid TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_analysis_candidate ON delta_steps(analysis_id, candidate_id);
"#;
