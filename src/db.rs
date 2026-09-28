use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

pub fn init(data_dir: &Path) -> rusqlite::Result<Store> {
    std::fs::create_dir_all(data_dir.join("sources")).ok();
    std::fs::create_dir_all(data_dir.join("payload")).ok();
    std::fs::create_dir_all(data_dir.join("resolved")).ok();
    let db_path = data_dir.join("microscope.db");
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 10000)?;
    conn.execute_batch(SCHEMA)?;
    let store = Store {
        conn: Mutex::new(conn),
        data_dir: data_dir.to_path_buf(),
    };
    store.ensure_default_branch()?;
    Ok(store)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    imported_at INTEGER NOT NULL,
    data_path TEXT NOT NULL,
    version INTEGER,
    obj_count INTEGER,
    pack_checksum TEXT,
    trailer_ok INTEGER,
    parse_status TEXT NOT NULL DEFAULT 'ok',
    parse_error TEXT,
    note TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,
    pack_offset INTEGER,
    declared_type TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    inflated_size INTEGER NOT NULL,
    hdr_start INTEGER NOT NULL,
    hdr_end INTEGER NOT NULL,
    zdata_start INTEGER NOT NULL,
    zdata_end INTEGER NOT NULL,
    base_ofs INTEGER,
    base_oid TEXT,
    idx_oid TEXT,
    idx_crc INTEGER,
    crc_ok INTEGER,
    oid TEXT,
    parse_status TEXT NOT NULL,
    parse_error TEXT,
    evidence TEXT,
    UNIQUE(source_id, origin, pack_offset)
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_candidates_idxoid ON candidates(idx_oid);

CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_cid INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    to_cid INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
    to_oid TEXT,
    kind TEXT NOT NULL,
    UNIQUE(from_cid, kind, to_cid, to_oid)
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    PRIMARY KEY (branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolved (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    object_type TEXT,
    oid TEXT,
    out_size INTEGER NOT NULL DEFAULT 0,
    oid_match INTEGER,
    reason TEXT,
    blocking_chain TEXT NOT NULL DEFAULT '[]',
    budget TEXT,
    gen INTEGER NOT NULL DEFAULT 0,
    UNIQUE(branch_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS idx_resolved_status ON resolved(branch_id, status);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    step_idx INTEGER NOT NULL,
    base_candidate_id INTEGER,
    base_kind TEXT NOT NULL,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    in_len INTEGER NOT NULL,
    out_len INTEGER NOT NULL,
    declared_target_size INTEGER NOT NULL,
    size_match INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    note TEXT,
    UNIQUE(branch_id, candidate_id, step_idx)
);


CREATE TABLE IF NOT EXISTS idx_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    crc INTEGER NOT NULL,
    pack_offset INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idx_entries ON idx_entries(source_id);

CREATE TABLE IF NOT EXISTS idx_fanout (
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY(source_id, bucket)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Store {
    fn ensure_default_branch(&self) -> rusqlite::Result<()> {
        let db = self.conn.lock().unwrap();
        let exists: Option<i64> = db
            .query_row("SELECT id FROM branches WHERE name='main'", [], |r| r.get(0))
            .optional()?;
        if exists.is_none() {
            db.execute(
                "INSERT INTO branches(name, created_at) VALUES('main', ?)",
                params![now_secs()],
            )?;
        }
        Ok(())
    }

    pub fn source_path(&self, source_id: i64) -> PathBuf {
        self.data_dir.join("sources").join(format!("{}", source_id))
    }

    pub fn payload_path(&self, candidate_id: i64) -> PathBuf {
        self.data_dir
            .join("payload")
            .join(format!("cand_{}.bin", candidate_id))
    }

    pub fn resolved_path(&self, branch_id: i64, candidate_id: i64) -> PathBuf {
        self.data_dir
            .join("resolved")
            .join(format!("b{}_c{}.bin", branch_id, candidate_id))
    }

    pub fn write_payload(&self, candidate_id: i64, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.payload_path(candidate_id), data)
    }

    pub fn read_payload(&self, candidate_id: i64) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.payload_path(candidate_id))
    }

    pub fn write_resolved(&self, branch_id: i64, candidate_id: i64, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.resolved_path(branch_id, candidate_id), data)
    }

    pub fn read_resolved(&self, branch_id: i64, candidate_id: i64) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.resolved_path(branch_id, candidate_id))
    }

    pub fn remove_resolved(&self, branch_id: i64, candidate_id: i64) {
        std::fs::remove_file(self.resolved_path(branch_id, candidate_id)).ok();
    }
}

pub fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
