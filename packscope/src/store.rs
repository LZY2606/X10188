use crate::gitobj::ObjType;
use crate::oid::Oid;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceRow {
    pub id: String,
    pub kind: String, // pack | idx | loose
    pub filename: String,
    pub imported_order: i64,
    pub size: i64,
    pub sha256: String,
    pub pack_source_id: Option<String>,
}

/// A candidate: one place an object id could originate from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub cid: i64,
    pub source_id: String,
    pub source_kind: String,
    pub filename: String,
    pub entry_index: Option<i64>,
    pub offset: Option<i64>,
    pub kind: String,
    pub declared_oid: Option<String>,
    pub actual_oid: Option<String>,
    pub payload_key: Option<String>,
    pub declared_size: i64,
    pub payload_len: i64,
    pub parse_error: Option<String>,
    pub quality: i64,
}

/// A dependency edge from one candidate to a named base.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub from_cid: i64,
    pub base_kind: String, // ofs | ref
    pub base_cid: Option<i64>,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchRow {
    pub id: i64,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepRow {
    pub cid: i64,
    pub depth: i64,
    pub base_cid: Option<i64>,
    pub base_kind: Option<String>,
    pub input_len: i64,
    pub output_len: i64,
    pub instr_start: i64,
    pub instr_end: i64,
    pub op_count: i64,
    pub check: String,
    pub expected_oid: Option<String>,
    pub actual_oid: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub id: i64,
    pub branch_id: Option<i64>,
    pub cid: Option<i64>,
    pub oid: Option<String>,
    pub level: String,
    pub code: String,
    pub message: String,
    pub context: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedRow {
    pub branch_id: i64,
    pub cid: i64,
    pub oid: String,
    pub kind: String,
    pub depth: i64,
    pub input_bytes: i64,
    pub output_bytes: i64,
    pub preview: String,
    pub steps_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeState {
    pub branch_id: i64,
    pub cid: i64,
    pub state: String, // resolved | error | blocked | paused
    pub oid: Option<String>,
    pub reason: Option<String>,
    pub blocking_chain: Option<String>,
}

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: std::path::PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: i64,
    pub total_bytes: i64,
    pub single_ratio_pct: i64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets { max_depth: 50, total_bytes: 64 * 1024 * 1024, single_ratio_pct: 500 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub branch_id: i64,
    pub root_cid: i64,
    pub depth: i64,
    pub total_used: i64,
    pub chain_json: String,
    pub reason: String,
}

impl Store {
    pub fn open(dir: &std::path::Path) -> std::io::Result<Store> {
        std::fs::create_dir_all(dir)?;
        let blob_dir = dir.join("blobs");
        std::fs::create_dir_all(&blob_dir)?;
        let conn = Connection::open(dir.join("packscope.db"))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;",
        )
        .unwrap();
        let mut s = Store { conn: Mutex::new(conn), data_dir: dir.to_path_buf() };
        s.init_schema();
        s.seed();
        Ok(s)
    }

    fn init_schema(&self) {
        let c = self.conn.lock().unwrap();
        c.execute_batch(SCHEMA).unwrap();
    }

    fn seed(&self) {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction().unwrap();
        let exists: i64 = tx
            .query_row("SELECT COUNT(*) FROM branches", [], |r| r.get(0))
            .unwrap();
        if exists == 0 {
            tx.execute("INSERT INTO branches(id, name) VALUES(1, 'default')", [])
                .unwrap();
        }
        let b = Budgets::default();
        tx.execute(
            "INSERT OR IGNORE INTO kv(key, value) VALUES
              ('max_depth', ?1), ('total_bytes', ?2), ('single_ratio_pct', ?3)",
            params![b.max_depth, b.total_bytes, b.single_ratio_pct],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    pub fn budgets(&self) -> Budgets {
        let c = self.conn.lock().unwrap();
        let get = |k: &str| -> i64 {
            c.query_row("SELECT value FROM kv WHERE key=?1", params![k], |r| r.get(0))
                .unwrap()
        };
        Budgets {
            max_depth: get("max_depth"),
            total_bytes: get("total_bytes"),
            single_ratio_pct: get("single_ratio_pct"),
        }
    }

    pub fn set_budgets(&self, b: &Budgets) {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction().unwrap();
        tx.execute("UPDATE kv SET value=?1 WHERE key='max_depth'", params![b.max_depth])
            .unwrap();
        tx.execute("UPDATE kv SET value=?1 WHERE key='total_bytes'", params![b.total_bytes])
            .unwrap();
        tx.execute(
            "UPDATE kv SET value=?1 WHERE key='single_ratio_pct'",
            params![b.single_ratio_pct],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    pub fn reset_budget_meter(&self, branch_id: i64) {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO kv(key, value) VALUES('used_bytes_' || ?1, 0)
             ON CONFLICT(key) DO UPDATE SET value=0",
            params![branch_id],
        )
        .unwrap();
    }

    pub fn used_bytes(&self, branch_id: i64) -> i64 {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT COALESCE(value,0) FROM kv WHERE key='used_bytes_' || ?1",
            params![branch_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    pub fn add_used(&self, branch_id: i64, n: i64) {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO kv(key, value) VALUES('used_bytes_' || ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=value+?2",
            params![branch_id, n],
        )
        .unwrap();
    }

    pub fn blob_path(&self, key: &str) -> std::path::PathBuf {
        self.data_dir.join("blobs").join(key)
    }

    pub fn write_blob(&self, key: &str, data: &[u8]) -> std::io::Result<()> {
        let p = self.blob_path(key);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, data)
    }

    pub fn read_blob(&self, key: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.blob_path(key))
    }

    pub fn source_path(&self, id: &str) -> std::path::PathBuf {
        self.data_dir.join("sources").join(id)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS sources(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  filename TEXT NOT NULL,
  imported_order INTEGER NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  pack_source_id TEXT
);

CREATE TABLE IF NOT EXISTS candidates(
  cid INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  source_kind TEXT NOT NULL,
  entry_index INTEGER,
  offset INTEGER,
  kind TEXT NOT NULL,
  declared_oid TEXT,
  actual_oid TEXT,
  payload_key TEXT,
  declared_size INTEGER NOT NULL DEFAULT 0,
  payload_len INTEGER NOT NULL DEFAULT 0,
  parse_error TEXT,
  quality INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cand_oid ON candidates(actual_oid);
CREATE INDEX IF NOT EXISTS idx_cand_decl ON candidates(declared_oid);
CREATE INDEX IF NOT EXISTS idx_cand_src ON candidates(source_id);

CREATE TABLE IF NOT EXISTS edges(
  from_cid INTEGER NOT NULL REFERENCES candidates(cid) ON DELETE CASCADE,
  base_kind TEXT NOT NULL,
  base_cid INTEGER REFERENCES candidates(cid) ON DELETE CASCADE,
  base_offset INTEGER,
  base_oid TEXT
);
CREATE INDEX IF NOT EXISTS idx_edge_from ON edges(from_cid);
CREATE INDEX IF NOT EXISTS idx_edge_base ON edges(base_cid);

CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS pins(
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  cid INTEGER NOT NULL REFERENCES candidates(cid) ON DELETE CASCADE,
  PRIMARY KEY(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS resolved(
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  cid INTEGER NOT NULL REFERENCES candidates(cid) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  kind TEXT NOT NULL,
  depth INTEGER NOT NULL,
  input_bytes INTEGER NOT NULL,
  output_bytes INTEGER NOT NULL,
  preview TEXT NOT NULL,
  steps_json TEXT NOT NULL,
  PRIMARY KEY(branch_id, cid)
);
CREATE TABLE IF NOT EXISTS node_state(
  branch_id INTEGER NOT NULL,
  cid INTEGER NOT NULL,
  state TEXT NOT NULL,
  oid TEXT,
  reason TEXT,
  blocking_chain TEXT,
  PRIMARY KEY(branch_id, cid)
);
CREATE INDEX IF NOT EXISTS idx_node_state ON node_state(branch_id, state);

CREATE TABLE IF NOT EXISTS steps(
  branch_id INTEGER NOT NULL,
  cid INTEGER NOT NULL,
  depth INTEGER NOT NULL,
  base_cid INTEGER,
  base_kind TEXT,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  instr_start INTEGER NOT NULL,
  instr_end INTEGER NOT NULL,
  op_count INTEGER NOT NULL,
  check TEXT NOT NULL,
  expected_oid TEXT,
  actual_oid TEXT,
  note TEXT,
  PRIMARY KEY(branch_id, cid, depth)
);

CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER,
  cid INTEGER,
  oid TEXT,
  level TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  context TEXT NOT NULL DEFAULT '',
  created_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints(
  branch_id INTEGER NOT NULL,
  root_cid INTEGER NOT NULL,
  depth INTEGER NOT NULL,
  total_used INTEGER NOT NULL,
  chain_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY(branch_id, root_cid)
);
"#;
