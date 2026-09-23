CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  len INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS source_links (
  pack_source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  index_source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  PRIMARY KEY (pack_source_id, index_source_id)
);
CREATE TABLE IF NOT EXISTS objects (
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  location TEXT NOT NULL,
  pack_ordinal INTEGER,
  header_offset INTEGER,
  data_offset INTEGER,
  next_offset INTEGER,
  kind TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  inflated_size INTEGER NOT NULL,
  delta_type TEXT NOT NULL,
  delta_base_oid TEXT,
  delta_target_offset INTEGER,
  raw_payload BLOB,
  delta_payload BLOB,
  resolved_payload BLOB,
  resolved_type TEXT,
  actual_oid TEXT,
  id_ok INTEGER,
  status TEXT NOT NULL,
  depth INTEGER NOT NULL DEFAULT 0,
  input_len INTEGER NOT NULL DEFAULT 0,
  output_len INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0,
  budget_ticket INTEGER,
  last_attempt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(source_id, location)
);
CREATE INDEX IF NOT EXISTS idx_objects_oid ON objects(oid);
CREATE INDEX IF NOT EXISTS idx_objects_status ON objects(status);
CREATE INDEX IF NOT EXISTS idx_objects_delta_base ON objects(delta_base_oid);
CREATE TABLE IF NOT EXISTS edges (
  candidate_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  base_oid TEXT NOT NULL,
  base_kind TEXT NOT NULL,
  base_offset INTEGER,
  PRIMARY KEY (candidate_id, base_oid)
);
CREATE INDEX IF NOT EXISTS idx_edges_base ON edges(base_oid);
CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  base_candidate_id INTEGER REFERENCES objects(id) ON DELETE SET NULL,
  base_oid TEXT,
  op_index INTEGER NOT NULL,
  opcode TEXT NOT NULL,
  range_start INTEGER NOT NULL,
  range_end INTEGER NOT NULL,
  base_offset INTEGER,
  base_len INTEGER,
  insert_len INTEGER,
  input_len INTEGER NOT NULL,
  output_before INTEGER NOT NULL,
  output_after INTEGER NOT NULL,
  check_ok INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delta_steps_candidate ON delta_steps(candidate_id, ordinal);
CREATE TABLE IF NOT EXISTS errors (
  id INTEGER PRIMARY KEY,
  source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  candidate_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_errors_candidate ON errors(candidate_id);
CREATE TABLE IF NOT EXISTS budget_events (
  id INTEGER PRIMARY KEY,
  ticket INTEGER NOT NULL,
  candidate_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  charged_bytes INTEGER NOT NULL,
  total_after INTEGER NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pins (
  oid TEXT PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
