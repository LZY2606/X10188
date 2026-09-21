CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('pack','index','loose','unknown')),
  original_name TEXT NOT NULL,
  stored_path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL UNIQUE,
  byte_size INTEGER NOT NULL,
  imported_at TEXT NOT NULL DEFAULT(datetime('now')),
  parse_status TEXT NOT NULL DEFAULT('pending'),
  parse_error TEXT
);

CREATE TABLE IF NOT EXISTS packs (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  entry_count INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  expected_index_source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS indexes (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE REFERENCES sources(id) ON DELETE CASCADE,
  entry_count INTEGER NOT NULL,
  pack_checksum TEXT NOT NULL,
  matched_pack_id INTEGER REFERENCES packs(id) ON DELETE SET NULL,
  checksum_ok INTEGER NOT NULL DEFAULT(0)
);

CREATE TABLE IF NOT EXISTS index_entries (
  id INTEGER PRIMARY KEY,
  index_id INTEGER NOT NULL REFERENCES indexes(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  pack_offset INTEGER NOT NULL,
  crc32 INTEGER NOT NULL,
  UNIQUE(index_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS fanout (
  index_id INTEGER NOT NULL REFERENCES indexes(id) ON DELETE CASCADE,
  bucket INTEGER NOT NULL CHECK(bucket BETWEEN 0 AND 255),
  cumulative INTEGER NOT NULL,
  PRIMARY KEY(index_id, bucket)
);

CREATE TABLE IF NOT EXISTS objects (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE,
  pack_offset INTEGER,
  loose_path TEXT,
  object_type TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  expanded_size INTEGER NOT NULL,
  payload_offset INTEGER,
  payload_end INTEGER,
  payload_crc32 INTEGER,
  index_crc32 INTEGER,
  negative_distance INTEGER,
  base_offset INTEGER,
  base_ref_oid TEXT,
  parse_status TEXT NOT NULL,
  parse_error TEXT,
  payload_sha256 TEXT,
  stored_payload_path TEXT,
  UNIQUE(source_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  oid TEXT NOT NULL,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  source_kind TEXT NOT NULL,
  valid INTEGER NOT NULL,
  invalid_reason TEXT,
  sort_key INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT(datetime('now'))
);

CREATE TABLE IF NOT EXISTS branch_pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  PRIMARY KEY(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS reconstructions (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  object_type TEXT,
  expected_oid TEXT,
  actual_oid TEXT,
  output_size INTEGER,
  depth INTEGER,
  charged_bytes INTEGER NOT NULL DEFAULT(0),
  attempt_count INTEGER NOT NULL DEFAULT(0),
  error_kind TEXT,
  error_message TEXT,
  blocking_chain TEXT,
  output_sha256 TEXT,
  output_path TEXT,
  updated_at TEXT NOT NULL DEFAULT(datetime('now')),
  UNIQUE(branch_id, object_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  reconstruction_id INTEGER NOT NULL REFERENCES reconstructions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  base_object_id INTEGER REFERENCES objects(id) ON DELETE SET NULL,
  delta_object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  base_offset INTEGER,
  input_size INTEGER NOT NULL,
  output_size INTEGER NOT NULL,
  instruction_count INTEGER NOT NULL,
  instruction_byte_range_start INTEGER NOT NULL,
  instruction_byte_range_end INTEGER NOT NULL,
  check_ok INTEGER NOT NULL,
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE,
  source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  object_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
  candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT('{}'),
  created_at TEXT NOT NULL DEFAULT(datetime('now'))
);

INSERT OR IGNORE INTO branches(id, name) VALUES(1, 'default');
CREATE INDEX IF NOT EXISTS idx_objects_pack_offset ON objects(pack_id, pack_offset);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid, valid, sort_key);
CREATE INDEX IF NOT EXISTS idx_reconstructions_status ON reconstructions(branch_id, status);
