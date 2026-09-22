//! SQLite persistence: sources, entries, edges, branches, meta.

use crate::git::ObjType;
use rusqlite::{params, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Status {
    Pending,
    Done,
    Failed,
    Blocked,
    Paused,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Done => "done",
            Status::Failed => "failed",
            Status::Blocked => "blocked",
            Status::Paused => "paused",
        }
    }
    pub fn parse(s: &str) -> Status {
        match s {
            "done" => Status::Done,
            "failed" => Status::Failed,
            "blocked" => Status::Blocked,
            "paused" => Status::Paused,
            _ => Status::Pending,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Source {
    pub id: i64,
    pub path: String,
    pub kind: String,
    pub sha256: String,
    pub size: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Entry {
    pub id: i64,
    pub source_id: i64,
    pub offset: u64,
    pub obj_type: ObjType,
    pub size_hdr: u64,
    pub data_start: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub comp_len: u64,
    pub crc32: u32,
    pub status: Status,
    pub oid: Option<String>,
    /// Resolved (final) type for delta chains.
    pub rtype: Option<String>,
    pub depth: u32,
    pub expanded: u64,
    pub error: Option<String>,
    pub blocked_on: Option<String>,
    pub crc_ok: bool,
    pub delta_steps: String,
    pub version: i64,
    #[serde(skip)]
    pub content: Option<Vec<u8>>,
}

pub struct Store {
    pub conn: Connection,
}

impl Store {
    pub fn open(path: &std::path::Path) -> Result<Store, String> {
        let conn = Connection::open(path).map_err(|e| format!("打开数据库失败: {e}"))?;
        let s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    pub fn open_memory() -> Result<Store, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sources(
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS entries(
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                offset INTEGER NOT NULL,
                obj_type TEXT NOT NULL,
                size_hdr INTEGER NOT NULL,
                data_start INTEGER NOT NULL,
                base_offset INTEGER,
                base_oid TEXT,
                comp_len INTEGER NOT NULL,
                crc32 INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                oid TEXT,
                rtype TEXT,
                depth INTEGER NOT NULL DEFAULT 0,
                expanded INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                blocked_on TEXT,
                crc_ok INTEGER NOT NULL DEFAULT 1,
                delta_steps TEXT NOT NULL DEFAULT '[]',
                version INTEGER NOT NULL DEFAULT 0,
                content BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
            CREATE INDEX IF NOT EXISTS idx_entries_oid ON entries(oid);
            CREATE INDEX IF NOT EXISTS idx_entries_status ON entries(status);
            CREATE TABLE IF NOT EXISTS edges(
                child_id INTEGER NOT NULL,
                base_id INTEGER NOT NULL,
                PRIMARY KEY(child_id, base_id)
            );
            CREATE TABLE IF NOT EXISTS branches(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                pins TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
            )
            .map_err(|e| format!("建表失败: {e}"))?;
        Ok(())
    }

    pub fn add_source(&self, path: &str, kind: &str, sha256: &str, size: u64) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO sources(path, kind, sha256, size) VALUES(?1,?2,?3,?4)",
                params![path, kind, sha256, size as i64],
            )
            .map_err(|e| format!("写入 source 失败: {e}"))?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_sources(&self) -> Result<Vec<Source>, String> {
        let mut st = self
            .conn
            .prepare("SELECT id, path, kind, sha256, size, created_at FROM sources ORDER BY path, id")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok(Source {
                    id: r.get(0)?,
                    path: r.get(1)?,
                    kind: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get::<_, i64>(4)? as u64,
                    created_at: r.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn get_source(&self, id: i64) -> Result<Option<Source>, String> {
        Ok(self
            .list_sources()?
            .into_iter()
            .find(|s| s.id == id))
    }

    pub fn delete_source(&self, id: i64) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM edges WHERE child_id IN (SELECT id FROM entries WHERE source_id=?1) OR base_id IN (SELECT id FROM entries WHERE source_id=?1)", params![id])
            .map_err(|e| e.to_string())?;
        self.conn
            .execute("DELETE FROM entries WHERE source_id=?1", params![id])
            .map_err(|e| e.to_string())?;
        self.conn
            .execute("DELETE FROM sources WHERE id=?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_entry(&self, e: &Entry) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO entries(source_id, offset, obj_type, size_hdr, data_start,
                    base_offset, base_oid, comp_len, crc32, status, crc_ok)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    e.source_id,
                    e.offset as i64,
                    e.obj_type.as_str(),
                    e.size_hdr as i64,
                    e.data_start as i64,
                    e.base_offset.map(|v| v as i64),
                    e.base_oid,
                    e.comp_len as i64,
                    e.crc32 as i64,
                    e.status.as_str(),
                    e.crc_ok as i64,
                ],
            )
            .map_err(|e| format!("写入 entry 失败: {e}"))?;
        Ok(self.conn.last_insert_rowid())
    }

    fn row_to_entry(r: &rusqlite::Row) -> rusqlite::Result<Entry> {
        let content: Option<Vec<u8>> = r.get(19)?;
        Ok(Entry {
            id: r.get(0)?,
            source_id: r.get(1)?,
            offset: r.get::<_, i64>(2)? as u64,
            obj_type: ObjType::parse(&r.get::<_, String>(3)?).unwrap_or(ObjType::Blob),
            size_hdr: r.get::<_, i64>(4)? as u64,
            data_start: r.get::<_, i64>(5)? as u64,
            base_offset: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            base_oid: r.get(7)?,
            comp_len: r.get::<_, i64>(8)? as u64,
            crc32: r.get::<_, i64>(9)? as u32,
            status: Status::parse(&r.get::<_, String>(10)?),
            oid: r.get(11)?,
            rtype: r.get(12)?,
            depth: r.get::<_, i64>(13)? as u32,
            expanded: r.get::<_, i64>(14)? as u64,
            error: r.get(15)?,
            blocked_on: r.get(16)?,
            crc_ok: r.get::<_, i64>(17)? != 0,
            delta_steps: r.get(18)?,
            version: r.get(20)?,
            content,
        })
    }

    const ENTRY_COLS: &'static str =
        "id, source_id, offset, obj_type, size_hdr, data_start, base_offset, base_oid,
         comp_len, crc32, status, oid, rtype, depth, expanded, error, blocked_on, crc_ok,
         delta_steps, content, version";

    pub fn load_entries(&self, with_content: bool) -> Result<Vec<Entry>, String> {
        let cols = if with_content {
            Self::ENTRY_COLS.to_string()
        } else {
            Self::ENTRY_COLS.replace("content", "NULL AS content")
        };
        let sql = format!(
            "SELECT {cols} FROM entries ORDER BY source_id, offset, id"
        );
        let mut st = self.conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Self::row_to_entry(r))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn load_entries_for_source(&self, source_id: i64) -> Result<Vec<Entry>, String> {
        Ok(self
            .load_entries(false)?
            .into_iter()
            .filter(|e| e.source_id == source_id)
            .collect())
    }

    pub fn get_entry(&self, id: i64, with_content: bool) -> Result<Option<Entry>, String> {
        let cols = if with_content {
            Self::ENTRY_COLS.to_string()
        } else {
            Self::ENTRY_COLS.replace("content", "NULL AS content")
        };
        let sql = format!("SELECT {cols} FROM entries WHERE id=?1");
        let mut st = self.conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mut rows = st.query(params![id]).map_err(|e| e.to_string())?;
        match rows.next().map_err(|e| e.to_string())? {
            Some(r) => Ok(Some(Self::row_to_entry(r).map_err(|e| e.to_string())?)),
            None => Ok(None),
        }
    }

    /// Persist a resolution outcome and bump the entry version.
    pub fn save_resolution(&self, e: &Entry) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE entries SET status=?1, oid=?2, rtype=?3, depth=?4, expanded=?5,
                    error=?6, blocked_on=?7, delta_steps=?8, content=?9, version=version+1
                 WHERE id=?10",
                params![
                    e.status.as_str(),
                    e.oid,
                    e.rtype,
                    e.depth as i64,
                    e.expanded as i64,
                    e.error,
                    e.blocked_on,
                    e.delta_steps,
                    e.content,
                    e.id,
                ],
            )
            .map_err(|e| format!("保存解析结果失败: {e}"))?;
        Ok(())
    }

    pub fn save_crc_ok(&self, id: i64, ok: bool) -> Result<(), String> {
        self.conn
            .execute("UPDATE entries SET crc_ok=?1 WHERE id=?2", params![ok as i64, id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn replace_edges(&self, child_id: i64, base_ids: &[i64]) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM edges WHERE child_id=?1", params![child_id])
            .map_err(|e| e.to_string())?;
        for b in base_ids {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO edges(child_id, base_id) VALUES(?1,?2)",
                    params![child_id, b],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// (child_id, base_id) pairs.
    pub fn load_edges(&self) -> Result<Vec<(i64, i64)>, String> {
        let mut st = self
            .conn
            .prepare("SELECT child_id, base_id FROM edges")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    /// Reset entries blocked on any of `oids` (and their transitive dependents)
    /// so a follow-up run recomputes only the affected subgraph.
    pub fn reset_affected(&self, oids: &[String]) -> Result<usize, String> {
        if oids.is_empty() {
            return Ok(0);
        }
        let entries = self.load_entries(false)?;
        let edges = self.load_edges()?;
        // dependents: child -> [bases]
        let mut children_of: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::new();
        for (c, b) in &edges {
            children_of.entry(*b).or_default().push(*c);
        }
        let mut queue: Vec<i64> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        for e in &entries {
            let hit = e
                .blocked_on
                .as_ref()
                .map(|b| oids.iter().any(|o| b.contains(o)))
                .unwrap_or(false);
            if hit && matches!(e.status, Status::Blocked | Status::Failed) {
                queue.push(e.id);
            }
        }
        let mut reset = 0usize;
        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            self.conn
                .execute(
                    "UPDATE entries SET status='pending', error=NULL, blocked_on=NULL WHERE id=?1",
                    params![id],
                )
                .map_err(|e| e.to_string())?;
            reset += 1;
            if let Some(children) = children_of.get(&id) {
                for c in children {
                    // Only reset dependents that are not already resolved.
                    if let Some(ce) = entries.iter().find(|x| x.id == *c) {
                        if !matches!(ce.status, Status::Done) {
                            queue.push(*c);
                        }
                    }
                }
            }
        }
        Ok(reset)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO meta(key, value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>, String> {
        let mut st = self
            .conn
            .prepare("SELECT value FROM meta WHERE key=?1")
            .map_err(|e| e.to_string())?;
        let mut rows = st.query(params![key]).map_err(|e| e.to_string())?;
        Ok(match rows.next().map_err(|e| e.to_string())? {
            Some(r) => Some(r.get(0).map_err(|e| e.to_string())?),
            None => None,
        })
    }

    pub fn add_branch(&self, name: &str, pins: &str) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO branches(name, pins) VALUES(?1,?2)",
                params![name, pins],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_branches(&self) -> Result<Vec<serde_json::Value>, String> {
        let mut st = self
            .conn
            .prepare("SELECT id, name, pins, created_at FROM branches ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "pins": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(2)?)
                        .unwrap_or(serde_json::json!({})),
                    "created_at": r.get::<_, String>(3)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}
