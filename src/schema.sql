PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('pack','idx','loose')),
  file_name TEXT NOT NULL,
  content_sha256 TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL,
  stored_path TEXT NOT NULL,
  import_seq INTEGER NOT NULL,
  parse_fatal TEXT
);

CREATE TABLE IF NOT EXISTS source_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  level TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claimed_oid TEXT,
  oid TEXT,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  origin TEXT NOT NULL CHECK (origin IN ('pack','loose')),
  ordinal INTEGER,
  header_offset INTEGER,
  data_offset INTEGER,
  end_offset INTEGER,
  declared_size INTEGER,
  inflated_size INTEGER,
  obj_type TEXT,
  crc32 INTEGER,
  idx_crc32 INTEGER,
  ref_base TEXT,
  ofs_distance INTEGER,
  base_header_offset INTEGER,
  content_sha256 TEXT,
  content_path TEXT,
  bad INTEGER NOT NULL DEFAULT 0,
  bad_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_candidates_src ON candidates(source_id);

CREATE TABLE IF NOT EXISTS graph_edges (
  candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
  base_oid TEXT,
  base_header_offset INTEGER,
  kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_seq INTEGER NOT NULL,
  depth_limit INTEGER NOT NULL,
  byte_budget INTEGER NOT NULL,
  ratio_limit INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolved (
  branch_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK (status IN ('complete','blocked','paused','bad')),
  obj_type TEXT,
  final_size INTEGER,
  content_sha256 TEXT,
  content_path TEXT,
  check_ok INTEGER,
  failure TEXT,
  resume_hint TEXT,
  run_seq INTEGER NOT NULL,
  PRIMARY KEY (branch_id, oid)
);
CREATE INDEX IF NOT EXISTS idx_resolved_branch ON resolved(branch_id, status);

CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  step INTEGER NOT NULL,
  base_oid TEXT,
  base_candidate_id INTEGER,
  candidate_id INTEGER,
  in_size INTEGER,
  out_size INTEGER,
  declared_base_size INTEGER,
  declared_target_size INTEGER,
  instr_count INTEGER,
  instr_range_start INTEGER,
  instr_range_end INTEGER,
  check_ok INTEGER,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS blockers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  level TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  candidate_id INTEGER,
  chain TEXT
);
CREATE INDEX IF NOT EXISTS idx_blockers ON blockers(branch_id, oid);

CREATE TABLE IF NOT EXISTS budget (
  branch_id INTEGER PRIMARY KEY REFERENCES branches(id) ON DELETE CASCADE,
  depth_limit INTEGER NOT NULL,
  depth_used INTEGER NOT NULL DEFAULT 0,
  byte_budget INTEGER NOT NULL,
  bytes_used INTEGER NOT NULL DEFAULT 0,
  ratio_limit INTEGER NOT NULL,
  run_seq INTEGER NOT NULL DEFAULT 0,
  paused INTEGER NOT NULL DEFAULT 0,
  last_pause TEXT
);
