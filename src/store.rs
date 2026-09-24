//! SQLite-backed persistence: sources, pack objects, candidates, loose objects,
//! index entries, crc findings, branches. All inputs stay inside the data dir.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  filename TEXT NOT NULL,
  kind TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT
);
CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  pack_offset INTEGER NOT NULL,
  kind TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  data_offset INTEGER NOT NULL,
  comp_size INTEGER NOT NULL,
  ofs_distance INTEGER,
  base_oid TEXT,
  payload BLOB,
  parse_error TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  compute_gen INTEGER NOT NULL DEFAULT 0,
  attempt_stamp TEXT NOT NULL DEFAULT '',
  resume_json TEXT,
  UNIQUE(source_id, pack_offset)
);
CREATE TABLE IF NOT EXISTS candidates(
  id INTEGER PRIMARY KEY,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  size INTEGER NOT NULL,
  content BLOB,
  delta_json TEXT,
  sort_key TEXT NOT NULL,
  UNIQUE(object_id, oid)
);
CREATE TABLE IF NOT EXISTS loose(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  content BLOB NOT NULL,
  status TEXT NOT NULL,
  error TEXT
);
CREATE TABLE IF NOT EXISTS idx_entries(
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  pack_source_id INTEGER
);
CREATE TABLE IF NOT EXISTS idx_fanout(
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  bucket INTEGER NOT NULL,
  cumulative INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS crc_findings(
  id INTEGER PRIMARY KEY,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  idx_source_id INTEGER NOT NULL,
  expected_crc INTEGER NOT NULL,
  actual_crc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS branch_pins(
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  object_id INTEGER NOT NULL,
  PRIMARY KEY(branch_id, oid)
);
"#;

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub sha256: String,
    pub size: i64,
    pub imported_at: String,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub source_id: i64,
    pub pack_offset: i64,
    pub kind: String,
    pub declared_size: i64,
    pub data_offset: i64,
    pub comp_size: i64,
    pub ofs_distance: Option<i64>,
    pub base_oid: Option<String>,
    pub parse_error: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub depth: i64,
    pub compute_gen: i64,
    pub has_resume: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CandidateRow {
    pub id: i64,
    pub object_id: i64,
    pub oid: String,
    pub size: i64,
    pub delta_json: Option<String>,
    pub sort_key: String,
}

pub fn now_iso() -> String {
    // Avoid extra deps: seconds since epoch formatted raw is fine for ordering.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(data_dir.join("uploads"))?;
        let db_path = data_dir.join("packscope.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("open db {}", db_path.display()))?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Store {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn next_gen(&self) -> Result<i64> {
        let conn = self.conn.lock();
        let cur: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='gen'", [], |r| r.get(0))
            .ok();
        let next: i64 = cur.and_then(|v| v.parse().ok()).unwrap_or(0) + 1;
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('gen',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![next.to_string()],
        )?;
        Ok(next)
    }

    pub fn add_source(
        &self,
        filename: &str,
        kind: &str,
        sha256: &str,
        size: i64,
        status: &str,
        message: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO sources(filename,kind,sha256,size,imported_at,status,message) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![filename, kind, sha256, size, now_iso(), status, message],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_sources(&self) -> Result<Vec<SourceRow>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT id,filename,kind,sha256,size,imported_at,status,message FROM sources ORDER BY id",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(SourceRow {
                    id: r.get(0)?,
                    filename: r.get(1)?,
                    kind: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get(4)?,
                    imported_at: r.get(5)?,
                    status: r.get(6)?,
                    message: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_source_sha(&self, source_id: i64) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let r = conn
            .query_row(
                "SELECT sha256 FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )
            .ok();
        Ok(r)
    }

    pub fn list_objects(&self, source_id: Option<i64>) -> Result<Vec<ObjectRow>> {
        let conn = self.conn.lock();
        let sql = "SELECT id,source_id,pack_offset,kind,declared_size,data_offset,comp_size,\
                   ofs_distance,base_oid,parse_error,status,error,depth,compute_gen,\
                   (resume_json IS NOT NULL) FROM objects \
                   ORDER BY source_id, pack_offset";
        let mut st = conn.prepare(sql)?;
        let map = |r: &rusqlite::Row| {
            Ok(ObjectRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                pack_offset: r.get(2)?,
                kind: r.get(3)?,
                declared_size: r.get(4)?,
                data_offset: r.get(5)?,
                comp_size: r.get(6)?,
                ofs_distance: r.get(7)?,
                base_oid: r.get(8)?,
                parse_error: r.get(9)?,
                status: r.get(10)?,
                error: r.get(11)?,
                depth: r.get(12)?,
                compute_gen: r.get(13)?,
                has_resume: r.get::<_, i64>(14)? != 0,
            })
        };
        let rows: Vec<ObjectRow> = match source_id {
            Some(sid) => {
                let mut st2 = conn.prepare(&format!("{} ", sql.replace("ORDER BY", "WHERE source_id=?1 ORDER BY")))?;
                st2.query_map(params![sid], map)?.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => st.query_map([], map)?.collect::<rusqlite::Result<Vec<_>>>()?,
        };
        Ok(rows)
    }

    /// Objects from other sources that (transitively) depend on any object or
    /// loose entry owned by `source_id`. Used before deleting a source.
    pub fn dependents_of_source(&self, source_id: i64) -> Result<Vec<serde_json::Value>> {
        let objs = crate::resolve::load_objects(&self.conn.lock())?;
        let loose_oids: std::collections::HashSet<String> = {
            let conn = self.conn.lock();
            let mut st = conn.prepare("SELECT oid FROM loose WHERE source_id=?1")?;
            let s = st
                .query_map(params![source_id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?;
            s
        };
        let mut deps = Vec::new();
        for o in &objs {
            if o.source_id == source_id {
                continue;
            }
            let chain = crate::resolve::raw_chain(o.id, &objs);
            for node in &chain {
                match node {
                    crate::resolve::ChainRef::Object(oid_) => {
                        if objs.iter().find(|x| &x.id == oid_).map(|x| x.source_id)
                            == Some(source_id)
                        {
                            deps.push(serde_json::json!({
                                "object_id": o.id, "via": format!("object #{}", oid_),
                            }));
                            break;
                        }
                    }
                    crate::resolve::ChainRef::MissingOid(hex) => {
                        if loose_oids.contains(hex) {
                            deps.push(serde_json::json!({
                                "object_id": o.id, "via": format!("loose {}", hex),
                            }));
                            break;
                        }
                    }
                }
            }
        }
        Ok(deps)
    }

    pub fn delete_source(&self, source_id: i64) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
        // Objects that lost their base go back to pending for re-resolution.
        conn.execute(
            "UPDATE objects SET status='pending', error=NULL, resume_json=NULL WHERE status NOT IN ('pending')",
            [],
        )?;
        Ok(())
    }
}
