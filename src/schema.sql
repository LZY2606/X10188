CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,               -- pack | idx | loose
  original_name TEXT NOT NULL,
  stored_path TEXT NOT NULL,       -- always inside the project data dir
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at TEXT NOT NULL,
  checksum_ref TEXT,               -- pack: trailer sha; idx: referenced pack sha
  UNIQUE(sha256, kind)
);

CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  otype TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  inflated_size INTEGER NOT NULL,
  is_loose INTEGER NOT NULL DEFAULT 0,
  data_start INTEGER NOT NULL,
  data_end INTEGER NOT NULL,
  base_distance INTEGER,
  base_oid TEXT,
  loose_oid TEXT,
  UNIQUE(source_id, offset)
);

CREATE TABLE IF NOT EXISTS idx_records (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  offset INTEGER NOT NULL,
  crc32 INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT,                        -- null until successfully reconstructed
  status TEXT NOT NULL,            -- pending | resolved | error | blocked | paused_budget
  length INTEGER,
  depth INTEGER,
  packed_len INTEGER,
  ratio INTEGER,                   -- out/packed, permille
  reason TEXT,                     -- error/block reason
  blocking_chain TEXT,             -- JSON chain for unresolved objects
  run_id INTEGER NOT NULL DEFAULT 0, -- run during which it was last computed
  UNIQUE(entry_id)
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);

CREATE TABLE IF NOT EXISTS contents (
  candidate_id INTEGER PRIMARY KEY
    REFERENCES candidates(id) ON DELETE CASCADE,
  data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  step INTEGER NOT NULL,
  base_desc TEXT NOT NULL,         -- "source#N@offset" or loose oid
  base_oid TEXT,
  base_type TEXT,
  ops_json TEXT NOT NULL,
  in_len INTEGER NOT NULL,
  out_len INTEGER NOT NULL,
  checks TEXT NOT NULL             -- JSON: base/result size + oid match
);
CREATE INDEX IF NOT EXISTS idx_steps_candidate ON delta_steps(candidate_id);

CREATE TABLE IF NOT EXISTS errors (
  id INTEGER PRIMARY KEY,
  source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
  oid_ref TEXT,
  kind TEXT NOT NULL,
  evidence TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
  id INTEGER PRIMARY KEY,
  branch TEXT NOT NULL,
  oid TEXT NOT NULL,
  candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  UNIQUE(branch, oid)
);

CREATE TABLE IF NOT EXISTS budgets (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS run_state (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  status TEXT NOT NULL,           -- idle | complete | paused
  expanded_bytes INTEGER NOT NULL,
  run_count INTEGER NOT NULL,
  pause_reasons TEXT NOT NULL DEFAULT '[]'
);
