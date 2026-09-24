PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                 -- pack | idx | loose
    original_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    parse_status TEXT NOT NULL,        -- ok | fatal | empty
    parse_error TEXT
);

CREATE TABLE IF NOT EXISTS packs (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    version INTEGER NOT NULL,
    num_objects INTEGER NOT NULL,
    body_len INTEGER NOT NULL,
    checksum_stored TEXT NOT NULL,
    checksum_computed TEXT NOT NULL,
    checksum_ok INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    pack_id INTEGER NOT NULL REFERENCES packs(id),
    offset INTEGER NOT NULL,
    obj_type INTEGER NOT NULL,
    declared_size INTEGER NOT NULL,
    base_offset INTEGER,
    base_oid TEXT,
    z_start INTEGER NOT NULL,
    z_consumed INTEGER,
    payload_path TEXT,                  -- inflated bytes on disk
    inflate_error TEXT,
    UNIQUE(pack_id, offset)
);

CREATE TABLE IF NOT EXISTS idx_files (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    version INTEGER NOT NULL,
    n_entries INTEGER NOT NULL,
    pack_checksum TEXT NOT NULL,
    idx_checksum_ok INTEGER NOT NULL,
    paired_pack_id INTEGER REFERENCES packs(id)
);

CREATE TABLE IF NOT EXISTS idx_entries (
    id INTEGER PRIMARY KEY,
    idx_id INTEGER NOT NULL REFERENCES idx_files(id),
    oid TEXT NOT NULL,
    pack_offset INTEGER NOT NULL,
    crc INTEGER
);

CREATE TABLE IF NOT EXISTS loose_objects (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    claimed_oid TEXT,
    computed_oid TEXT NOT NULL,
    obj_type INTEGER NOT NULL,
    size INTEGER NOT NULL,
    content_path TEXT NOT NULL,
    oid_matches INTEGER NOT NULL,
    parse_error TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    oid TEXT,                            -- filled in after resolution
    origin TEXT NOT NULL,                -- loose | pack
    loose_object_id INTEGER REFERENCES loose_objects(id),
    entry_id INTEGER REFERENCES entries(id),
    chain_len INTEGER NOT NULL DEFAULT 0,
    sort_key TEXT NOT NULL,
    valid INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    subject TEXT NOT NULL,              -- source:<id> | pack:<id> | entry:<id> | candidate:<id> | loose:<id> | idx:<id>
    code TEXT NOT NULL,
    severity TEXT NOT NULL,             -- error | warning
    message TEXT NOT NULL,
    detail TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id),
    created_at INTEGER NOT NULL,
    UNIQUE(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolutions (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    oid TEXT NOT NULL,
    candidate_id INTEGER REFERENCES candidates(id),
    status TEXT NOT NULL,                -- resolved | error | missing_base | paused_budget | cycle
    obj_type INTEGER,
    content_path TEXT,
    size INTEGER,
    oid_ok INTEGER,
    depth INTEGER,
    expanded_bytes INTEGER NOT NULL DEFAULT 0,
    blocking_chain TEXT,                 -- JSON list of blocked node descriptors
    reason TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    oid TEXT NOT NULL,
    step INTEGER NOT NULL,              -- 0 is the deepest base application
    base_oid TEXT,
    base_kind TEXT,                      -- ofs | ref | loose
    base_location TEXT,                  -- offset hex or oid
    delta_entry_id INTEGER REFERENCES entries(id),
    cmd_start INTEGER,
    cmd_end INTEGER,
    cmd_count INTEGER,
    in_len INTEGER,
    out_len INTEGER,
    check_ok INTEGER,
    check_detail TEXT,
    UNIQUE(branch_id, oid, step)
);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    from_oid TEXT NOT NULL,
    to_oid TEXT NOT NULL,
    kind TEXT NOT NULL,                  -- ofs | ref
    UNIQUE(branch_id, from_oid, to_oid, kind)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_entries_pack ON entries(pack_id);
CREATE INDEX IF NOT EXISTS idx_idx_entries_idx ON idx_entries(idx_id);
CREATE INDEX IF NOT EXISTS idx_res_branch ON resolutions(branch_id);
CREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence(subject);
