//! SQLite persistence: sources, candidates, blobs, delta evidence,
//! checkpoints and conflict pins.
//!
//! The whole application state lives in this database plus files copied under
//! the project data directory.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug)]
pub struct Store {
    pub conn: Mutex<Connection>,
}

/// One imported file.
#[derive(Debug, Clone)]
pub struct Source {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub size: i64,
    pub imported_at: i64,
    /// For a pack: its pack trailer sha1; for an idx: the pack checksum it names.
    pub checksum_hex: Option<String>,
}

/// One candidate occurrence of an object.
#[derive(Debug, Clone)]
pub struct CandidateRow {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    /// Declared oid hex (40 chars) for base/loose/ref-base; NULL for ofs-delta.
    pub oid_hex: Option<String>,
    pub offset: Option<i64>,
    pub declared_size: i64,
    pub actual_size: i64,
    pub crc_idx: Option<i64>,
    pub crc_actual: Option<i64>,
    pub parse_error: Option<String>,
    pub base_ref_hex: Option<String>,
    pub base_offset: Option<i64>,
    pub data_offset: Option<i64>,
    pub compressed_len: Option<i64>,
    pub resolve_status: String,
    pub resolved_oid_hex: Option<String>,
    pub resolved_kind: Option<String>,
    pub error_summary: Option<String>,
    pub needs_recompute: i64,
    pub pinned: i64,
}

/// Row in the flat object view (one oid, aggregated over candidates).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectSummary {
    pub oid_hex: String,
    pub kind: String,
    pub size: i64,
    pub status: String,
    pub candidate_count: i64,
    pub conflict: bool,
    pub pinned_source_id: Option<i64>,
}

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sources (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT NOT NULL,
            kind         TEXT NOT NULL,              -- pack | idx | loose
            path         TEXT NOT NULL,
            sha256       TEXT NOT NULL,
            size         INTEGER NOT NULL,
            imported_at  INTEGER NOT NULL,
            checksum_hex TEXT
        );

        CREATE TABLE IF NOT EXISTS candidates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id       INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            kind            TEXT NOT NULL,
            oid_hex         TEXT,
            offset          INTEGER,
            declared_size   INTEGER NOT NULL,
            actual_size     INTEGER NOT NULL DEFAULT 0,
            crc_idx         INTEGER,
            crc_actual      INTEGER,
            parse_error     TEXT,
            base_ref_hex    TEXT,
            base_offset     INTEGER,
            data_offset     INTEGER,
            compressed_len  INTEGER,
            resolve_status  TEXT NOT NULL DEFAULT 'pending',
            resolved_oid_hex TEXT,
            resolved_kind   TEXT,
            error_summary   TEXT,
            needs_recompute INTEGER NOT NULL DEFAULT 1,
            pinned          INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid_hex);
        CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
        CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(resolve_status);
        CREATE INDEX IF NOT EXISTS idx_candidates_base_ref ON candidates(base_ref_hex);
        CREATE INDEX IF NOT EXISTS idx_candidates_soff ON candidates(source_id, offset);

        CREATE TABLE IF NOT EXISTS blobs (
            candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
            role         TEXT NOT NULL,          -- raw | resolved | partial
            content      BLOB NOT NULL,
            len          INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS edges (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id    INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
            base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
            base_kind       TEXT NOT NULL,        -- ofs | ref | external
            base_offset     INTEGER,
            base_ref_hex    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_edges_cand ON edges(candidate_id);
        CREATE INDEX IF NOT EXISTS idx_edges_base ON edges(base_candidate_id);

        CREATE TABLE IF NOT EXISTS delta_steps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
            step_ord    INTEGER NOT NULL,
            kind        TEXT NOT NULL,
            instr_start INTEGER NOT NULL,
            instr_end   INTEGER NOT NULL,
            out_start   INTEGER NOT NULL,
            out_end     INTEGER NOT NULL,
            input_len   INTEGER NOT NULL,
            output_len  INTEGER NOT NULL,
            check_ok    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_steps_cand ON delta_steps(candidate_id, step_ord);

        CREATE TABLE IF NOT EXISTS checkpoints (
            candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
            delta_pos    INTEGER NOT NULL,
            instr_ord    INTEGER NOT NULL,
            output       BLOB NOT NULL,
            reason       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pins (
            oid_hex      TEXT NOT NULL,
            source_id    INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            created_at   INTEGER NOT NULL,
            PRIMARY KEY (oid_hex, source_id)
        );

        CREATE TABLE IF NOT EXISTS run_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_bytes_used INTEGER NOT NULL DEFAULT 0,
            max_depth        INTEGER NOT NULL,
            total_bytes      INTEGER NOT NULL,
            object_cap       INTEGER NOT NULL,
            paused           INTEGER NOT NULL DEFAULT 0,
            last_reason      TEXT
        );

        CREATE TABLE IF NOT EXISTS idx_meta (
            source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
            pack_checksum_hex TEXT NOT NULL,
            idx_checksum_ok   INTEGER NOT NULL,
            num_objects       INTEGER NOT NULL,
            error             TEXT
        );

        CREATE TABLE IF NOT EXISTS idx_fanout (
            source_id  INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            bucket     INTEGER NOT NULL,
            cumulative INTEGER NOT NULL,
            PRIMARY KEY (source_id, bucket)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id    INTEGER REFERENCES sources(id) ON DELETE CASCADE,
            candidate_id INTEGER REFERENCES candidates(id) ON DELETE CASCADE,
            severity     TEXT NOT NULL,
            code         TEXT NOT NULL,
            message      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_cand ON findings(candidate_id);
        "#,
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO meta(key,value) VALUES ('schema_version', ?1)",
        params![SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}
