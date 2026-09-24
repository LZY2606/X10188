CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,                 -- pack | idx | loose | unknown
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    pack_checksum TEXT,                 -- for idx/pack: pack sha1 hex, used to pair them
    pack_source_id INTEGER REFERENCES sources(id),
    idx_source_id INTEGER REFERENCES sources(id),
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    pack_source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    oid TEXT,
    kind TEXT NOT NULL,                 -- commit/tree/blob/tag/ofs-delta/ref-delta/loose
    role TEXT NOT NULL,                 -- pack-object | loose-object | idx-record
    "offset" INTEGER,
    data_offset INTEGER,
    compressed_len INTEGER,
    declared_size INTEGER NOT NULL DEFAULT 0,
    ofs_distance INTEGER,
    ref_base TEXT,
    has_payload INTEGER NOT NULL DEFAULT 0,
    parse_error TEXT,
    idx_crc_ok INTEGER,
    content BLOB
);
CREATE INDEX IF NOT EXISTS idx_entries_oid ON entries(oid);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_entries_pack ON entries(pack_source_id, "offset");
CREATE INDEX IF NOT EXISTS idx_entries_offset ON entries(pack_source_id, "offset");

CREATE TABLE IF NOT EXISTS contents (
    oid TEXT NOT NULL,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    verified INTEGER NOT NULL,
    PRIMARY KEY (entry_id)
);
CREATE INDEX IF NOT EXISTS idx_contents_oid ON contents(oid);

CREATE TABLE IF NOT EXISTS branches (
    name TEXT PRIMARY KEY,
    note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    branch TEXT NOT NULL REFERENCES branches(name) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    PRIMARY KEY (branch, oid)
);

CREATE TABLE IF NOT EXISTS resolutions (
    branch TEXT NOT NULL REFERENCES branches(name) ON DELETE CASCADE,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    status TEXT NOT NULL,               -- resolved | blocked | error | pending
    depth INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT,
    content_len INTEGER NOT NULL DEFAULT 0,
    git_oid TEXT,
    oid_ok INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    blocking_chain TEXT,                -- JSON [{oid,sources:[...]}]
    attempted_at TEXT NOT NULL,
    PRIMARY KEY (branch, entry_id)
);
CREATE INDEX IF NOT EXISTS idx_res_status ON resolutions(branch, status);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    hop INTEGER NOT NULL,
    base_entry_id INTEGER,
    base_oid TEXT,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    opcode INTEGER NOT NULL,
    detail TEXT NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    verify TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_entry ON delta_steps(branch, entry_id, hop);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    branch TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,               -- paused | complete
    total_budget INTEGER NOT NULL,
    total_spent INTEGER NOT NULL,
    object_cap INTEGER NOT NULL,
    max_depth INTEGER NOT NULL,
    pending_entries TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
