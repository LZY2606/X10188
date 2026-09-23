//! SQLite persistence. All imported bytes and every analysis artefact stay
//! inside the per-project data directory.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const BRANCH_DEFAULT: &str = "default";

/// Resolution budgets (resource accounting).
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_delta_depth: u32,
    pub max_total_bytes: u64,
    pub max_single_bytes: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_delta_depth: 50,
            max_total_bytes: 64 * 1024 * 1024,
            max_single_bytes: 16 * 1024 * 1024,
        }
    }
}

pub struct State {
    pub db: Mutex<Connection>,
    pub data_dir: PathBuf,
    pub objects_dir: PathBuf,
    pub sources_dir: PathBuf,
}

impl State {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let objects_dir = data_dir.join("objects");
        let sources_dir = data_dir.join("sources");
        std::fs::create_dir_all(&objects_dir)?;
        std::fs::create_dir_all(&sources_dir)?;
        let db_path = data_dir.join("microscope.db");
        let mut conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        migrate(&conn)?;
        Ok(State {
            db: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
            objects_dir,
            sources_dir,
        })
    }
}

fn migrate(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS source (
    id              INTEGER PRIMARY KEY,
    filename        TEXT NOT NULL,
    kind            TEXT NOT NULL,           -- pack | idx | loose | unknown
    size_bytes      INTEGER NOT NULL,
    content_sha256  TEXT NOT NULL,
    imported_seq    INTEGER NOT NULL,
    imported_at     TEXT NOT NULL DEFAULT (datetime('now')),
    storage_path    TEXT NOT NULL,
    UNIQUE(content_sha256, filename)
);

CREATE TABLE IF NOT EXISTS pack_info (
    source_id            INTEGER PRIMARY KEY REFERENCES source(id) ON DELETE CASCADE,
    version              INTEGER NOT NULL,
    num_objects          INTEGER NOT NULL,
    trailer_expected     TEXT NOT NULL,
    trailer_actual       TEXT NOT NULL,
    trailer_ok           INTEGER NOT NULL,
    scan_completed       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pack_entry (
    id                    INTEGER PRIMARY KEY,
    pack_source_id        INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    offset                INTEGER NOT NULL,
    header_len            INTEGER NOT NULL,
    type_code             INTEGER NOT NULL,
    type_name             TEXT NOT NULL,
    declared_size         INTEGER NOT NULL,
    ofs_distance          INTEGER,
    base_offset           INTEGER,
    base_oid              TEXT,
    zlib_offset           INTEGER NOT NULL,
    compressed_len        INTEGER NOT NULL,
    inflated_len          INTEGER NOT NULL,
    adler_ok              INTEGER NOT NULL,
    crc32                 INTEGER NOT NULL,
    content_sha256        TEXT NOT NULL,
    size_matches_header   INTEGER NOT NULL,
    inflated_path         TEXT,
    parse_error           TEXT,
    delta_base_size       INTEGER,
    delta_result_size     INTEGER,
    delta_instr_start     INTEGER,
    delta_ref_oid         TEXT,
    UNIQUE(pack_source_id, ordinal)
);

CREATE TABLE IF NOT EXISTS idx_info (
    source_id            INTEGER PRIMARY KEY REFERENCES source(id) ON DELETE CASCADE,
    num_objects          INTEGER NOT NULL,
    pack_checksum        TEXT NOT NULL,
    idx_checksum_ok      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idx_entry (
    id              INTEGER PRIMARY KEY,
    idx_source_id   INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
    ordinal         INTEGER NOT NULL,
    oid             TEXT NOT NULL,
    crc32           INTEGER NOT NULL,
    offset          INTEGER NOT NULL,
    large_offset    INTEGER NOT NULL,
    UNIQUE(idx_source_id, ordinal)
);

CREATE TABLE IF NOT EXISTS loose_info (
    source_id            INTEGER PRIMARY KEY REFERENCES source(id) ON DELETE CASCADE,
    declared_type        TEXT NOT NULL,
    declared_size        INTEGER NOT NULL,
    computed_oid         TEXT NOT NULL,
    header_ok            INTEGER NOT NULL,
    adler_ok             INTEGER NOT NULL,
    content_sha256       TEXT NOT NULL,
    body_path            TEXT NOT NULL,
    issue                TEXT
);

CREATE TABLE IF NOT EXISTS candidate (
    id                  INTEGER PRIMARY KEY,
    oid                 TEXT NOT NULL,
    kind                TEXT NOT NULL,       -- loose | pack_base | pack_delta | idx_only
    source_id           INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
    pack_entry_id       INTEGER REFERENCES pack_entry(id) ON DELETE CASCADE,
    loose_source_id     INTEGER REFERENCES source(id) ON DELETE CASCADE,
    idx_source_id       INTEGER REFERENCES source(id) ON DELETE CASCADE,
    offset              INTEGER,
    type_name           TEXT,
    content_sha256      TEXT,
    -- lower is better. ranking is content-based and therefore import-order independent.
    quality_rank        INTEGER NOT NULL,
    parse_problem       INTEGER NOT NULL DEFAULT 0,
    idx_source_id       INTEGER REFERENCES source(id) ON DELETE SET NULL,
    idx_crc32           INTEGER,
    pack_crc32          INTEGER,
    crc_matches         INTEGER,
    idx_pack_mismatch   INTEGER NOT NULL DEFAULT 0,
    note                TEXT,
    UNIQUE(oid, kind, source_id, COALESCE(offset, -1))
);
CREATE INDEX IF NOT EXISTS idx_candidate_oid ON candidate(oid);
CREATE INDEX IF NOT EXISTS idx_candidate_sha ON candidate(content_sha256);

CREATE TABLE IF NOT EXISTS branch (
    name        TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO branch(name) VALUES ('default');

CREATE TABLE IF NOT EXISTS pin (
    oid         TEXT NOT NULL,
    branch      TEXT NOT NULL,
    source_id   INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
    PRIMARY KEY (oid, branch)
);

CREATE TABLE IF NOT EXISTS resolved_node (
    branch          TEXT NOT NULL,
    node_key        TEXT NOT NULL,        -- 'loose:<sid>' | 'pack:<sid>:<ordinal>'
    oid             TEXT,
    type_name       TEXT,
    candidate_id    INTEGER REFERENCES candidate(id) ON DELETE SET NULL,
    status          TEXT NOT NULL,        -- resolved | missing_base | cycle | error | paused
    depth           INTEGER NOT NULL DEFAULT 0,
    inflated_bytes  INTEGER NOT NULL DEFAULT 0,
    content_sha256  TEXT,
    body_path       TEXT,
    body_len        INTEGER,
    oid_verified    INTEGER NOT NULL DEFAULT 0,
    detail          TEXT,
    content_version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (branch, node_key)
);
CREATE INDEX IF NOT EXISTS idx_resolved_oid ON resolved_node(branch, oid);

CREATE TABLE IF NOT EXISTS delta_step (
    branch          TEXT NOT NULL,
    node_key        TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    depth           INTEGER NOT NULL,
    kind            TEXT NOT NULL,        -- ofs-delta | ref-delta
    base_node_key   TEXT,
    base_oid        TEXT,
    instr_start     INTEGER NOT NULL,
    instr_end       INTEGER NOT NULL,
    base_len        INTEGER NOT NULL,
    input_len       INTEGER NOT NULL,
    output_len      INTEGER NOT NULL,
    declared_base_size   INTEGER NOT NULL,
    declared_result_size INTEGER NOT NULL,
    base_size_match      INTEGER NOT NULL,
    result_size_match    INTEGER NOT NULL,
    status          TEXT NOT NULL,
    detail          TEXT,
    PRIMARY KEY (branch, node_key, seq)
);

CREATE TABLE IF NOT EXISTS delta_edge (
    branch      TEXT NOT NULL,
    node_key    TEXT NOT NULL,
    base_key    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    PRIMARY KEY (branch, node_key)
);

CREATE TABLE IF NOT EXISTS blocker (
    branch          TEXT NOT NULL,
    node_key        TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    blocker_oid     TEXT,
    blocker_node    TEXT,
    reason          TEXT NOT NULL,
    PRIMARY KEY (branch, node_key, seq)
);

CREATE TABLE IF NOT EXISTS run_log (
    id              INTEGER PRIMARY KEY,
    branch          TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    status          TEXT NOT NULL,        -- complete | paused | failed
    max_depth       INTEGER NOT NULL,
    max_total_bytes INTEGER NOT NULL,
    max_single_bytes INTEGER NOT NULL,
    total_inflated  INTEGER NOT NULL DEFAULT 0,
    resolved_count  INTEGER NOT NULL DEFAULT 0,
    blocked_count   INTEGER NOT NULL DEFAULT 0,
    paused_count    INTEGER NOT NULL DEFAULT 0,
    error_count     INTEGER NOT NULL DEFAULT 0,
    affected_scope  INTEGER NOT NULL DEFAULT 0
);
        "#,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}
