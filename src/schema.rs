pub const MIGRATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                 -- pack | idx | loose
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    byte_len INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    linked_pack_source_id INTEGER,
    detail TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    locator TEXT NOT NULL,             -- "pack:<sid>:<off>" or "loose:<sid>"
    UNIQUE(source_id, locator),
    kind TEXT NOT NULL,                -- commit/tree/blob/tag/ofs_delta/ref_delta
    declared_size INTEGER NOT NULL,
    pack_offset INTEGER,
    header_start INTEGER,
    header_end INTEGER,
    zlib_start INTEGER,
    zlib_end INTEGER,
    zlib_out_len INTEGER,
    ofs_base_offset INTEGER,
    ref_base_oid BLOB,
    raw BLOB,                          -- inflated bytes (delta or final)
    content_size INTEGER,              -- inflated length
    parse_status TEXT NOT NULL,        -- ok | inflate_error
    parse_error TEXT,
    crc_expected INTEGER,
    crc_actual INTEGER,
    crc_ok INTEGER,
    computed_oid BLOB,
    UNIQUE(source_id, pack_offset)
);

CREATE TABLE IF NOT EXISTS oid_candidates (
    id INTEGER PRIMARY KEY,
    oid BLOB NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    origin TEXT NOT NULL,              -- index | computed
    idx_present INTEGER NOT NULL,
    crc_ok INTEGER,
    checksum_ok INTEGER NOT NULL,
    rank_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cand_oid ON oid_candidates(oid);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    oid BLOB NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolved (
    branch_id INTEGER NOT NULL REFERENCES branches(id),
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    status TEXT NOT NULL,              -- resolved | error | blocked | paused
    error_code TEXT,
    error_message TEXT,
    note TEXT,
    final_type TEXT,
    final_size INTEGER,
    final_oid BLOB,
    oid_ok INTEGER,
    final_content BLOB,
    depth INTEGER,
    chain_json TEXT,
    blocking_chain_json TEXT,
    last_settled_at TEXT NOT NULL DEFAULT (datetime('now')),
    recompute_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (branch_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_resolved_status ON resolved(branch_id, status);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL REFERENCES nodes(id),
    step INTEGER NOT NULL,
    base_node_id INTEGER,
    base_oid BLOB,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    instr_count INTEGER NOT NULL,
    instr_ranges_json TEXT NOT NULL,
    check_ok INTEGER NOT NULL,
    note TEXT,
    UNIQUE(branch_id, node_id, step)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_ledger (
    branch_id INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    cost INTEGER NOT NULL,
    PRIMARY KEY (branch_id, node_id)
);

CREATE TABLE IF NOT EXISTS fanout (
    source_id INTEGER NOT NULL REFERENCES sources(id),
    bucket INTEGER NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY(source_id, bucket)
);
"#;
