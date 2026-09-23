use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: i64,
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub size: i64,
    pub imported_at: String,
}

#[derive(Debug, Clone)]
pub struct EntryRow {
    pub id: i64,
    pub source_id: i64,
    pub seq: i64,
    pub offset: i64,
    pub type_code: i64,
    pub size_declared: i64,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub data_start: i64,
    pub data_end: i64,
    pub crc32: i64,
    pub payload: Vec<u8>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LooseRow {
    pub id: i64,
    pub source_id: i64,
    pub oid: Option<String>,
    pub type_name: Option<String>,
    pub content: Option<Vec<u8>>,
    pub expected_oid: Option<String>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionRow {
    pub entry_id: i64,
    pub status: String,
    pub oid: Option<String>,
    pub type_name: Option<String>,
    pub content: Option<Vec<u8>>,
    pub steps: String,
    pub blocking: String,
    pub error: Option<String>,
    pub depth: i64,
    pub expanded: i64,
    pub updated_at: String,
}

pub struct Store {
    pub conn: Connection,
}

fn now() -> String {
    // seconds since epoch; good enough for ordering evidence
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(
            "
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pack_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  type_code INTEGER NOT NULL,
  size_declared INTEGER NOT NULL,
  base_offset INTEGER,
  base_oid TEXT,
  data_start INTEGER NOT NULL,
  data_end INTEGER NOT NULL,
  crc32 INTEGER NOT NULL,
  payload BLOB NOT NULL,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS pack_meta(
  source_id INTEGER PRIMARY KEY,
  version INTEGER NOT NULL,
  declared_count INTEGER NOT NULL,
  errors TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idx_data(
  source_id INTEGER PRIMARY KEY,
  version INTEGER NOT NULL,
  fanout TEXT NOT NULL,
  entries TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS loose_objects(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL,
  oid TEXT,
  type_name TEXT,
  content BLOB,
  expected_oid TEXT,
  ok INTEGER NOT NULL,
  error TEXT
);
CREATE TABLE IF NOT EXISTS resolutions(
  entry_id INTEGER PRIMARY KEY,
  status TEXT NOT NULL,
  oid TEXT,
  type_name TEXT,
  content BLOB,
  steps TEXT NOT NULL DEFAULT '[]',
  blocking TEXT NOT NULL DEFAULT '[]',
  error TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  expanded INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pins(
  oid TEXT PRIMARY KEY,
  choice TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
",
        )?;
        Ok(Store { conn })
    }

    pub fn add_source(&self, kind: &str, path: &str, sha256: &str, size: i64) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sources(kind,path,sha256,size,imported_at) VALUES(?1,?2,?3,?4,?5)",
            params![kind, path, sha256, size, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_sources(&self) -> rusqlite::Result<Vec<SourceRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,kind,path,sha256,size,imported_at FROM sources ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                path: r.get(2)?,
                sha256: r.get(3)?,
                size: r.get(4)?,
                imported_at: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_source(&self, id: i64) -> rusqlite::Result<Option<SourceRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,kind,path,sha256,size,imported_at FROM sources WHERE id=?1")?;
        let mut rows = st.query_map(params![id], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                path: r.get(2)?,
                sha256: r.get(3)?,
                size: r.get(4)?,
                imported_at: r.get(5)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn delete_source_rows(&self, id: i64) -> rusqlite::Result<()> {
        // resolutions for entries of this source are removed by caller first
        self.conn.execute(
            "DELETE FROM resolutions WHERE entry_id IN (SELECT id FROM pack_entries WHERE source_id=?1)",
            params![id],
        )?;
        self.conn.execute("DELETE FROM pack_entries WHERE source_id=?1", params![id])?;
        self.conn.execute("DELETE FROM pack_meta WHERE source_id=?1", params![id])?;
        self.conn.execute("DELETE FROM idx_data WHERE source_id=?1", params![id])?;
        self.conn.execute("DELETE FROM loose_objects WHERE source_id=?1", params![id])?;
        self.conn.execute("DELETE FROM sources WHERE id=?1", params![id])?;
        Ok(())
    }

    pub fn insert_entry(&self, source_id: i64, e: &crate::packfile::PackEntry) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO pack_entries(source_id,seq,offset,type_code,size_declared,base_offset,base_oid,data_start,data_end,crc32,payload,parse_error)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                source_id,
                e.seq as i64,
                e.offset as i64,
                e.type_code as i64,
                e.size_declared as i64,
                e.base_offset.map(|v| v as i64),
                e.base_oid.map(|o| hex::encode(o)),
                e.data_start as i64,
                e.data_end as i64,
                e.crc32 as i64,
                e.payload,
                e.parse_error,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn set_pack_meta(&self, source_id: i64, version: u32, count: u32, errors: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pack_meta(source_id,version,declared_count,errors) VALUES(?1,?2,?3,?4)",
            params![source_id, version, count, errors],
        )
        .map(|_| ())
    }

    pub fn get_pack_meta(&self, source_id: i64) -> rusqlite::Result<Option<(u32, u32, String)>> {
        let mut st = self.conn.prepare(
            "SELECT version,declared_count,errors FROM pack_meta WHERE source_id=?1")?;
        let mut rows = st.query_map(params![source_id], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?))
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn set_idx_data(&self, source_id: i64, version: u32, fanout: &str, entries: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO idx_data(source_id,version,fanout,entries) VALUES(?1,?2,?3,?4)",
            params![source_id, version, fanout, entries],
        )
        .map(|_| ())
    }

    pub fn all_idx(&self) -> rusqlite::Result<Vec<(i64, u32, String, String)>> {
        let mut st = self.conn.prepare("SELECT source_id,version,fanout,entries FROM idx_data")?;
        let rows = st.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        rows.collect()
    }

    pub fn insert_loose(&self, source_id: i64, l: &LooseRow) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO loose_objects(source_id,oid,type_name,content,expected_oid,ok,error)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                source_id,
                l.oid,
                l.type_name,
                l.content,
                l.expected_oid,
                l.ok as i64,
                l.error,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn all_loose(&self) -> rusqlite::Result<Vec<LooseRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,source_id,oid,type_name,content,expected_oid,ok,error FROM loose_objects ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(LooseRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                oid: r.get(2)?,
                type_name: r.get(3)?,
                content: r.get(4)?,
                expected_oid: r.get(5)?,
                ok: r.get::<_, i64>(6)? != 0,
                error: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn entries_of_source(&self, source_id: i64) -> rusqlite::Result<Vec<EntryRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,source_id,seq,offset,type_code,size_declared,base_offset,base_oid,data_start,data_end,crc32,payload,parse_error
             FROM pack_entries WHERE source_id=?1 ORDER BY seq")?;
        let rows = st.query_map(params![source_id], entry_map)?;
        rows.collect()
    }

    pub fn all_entries(&self) -> rusqlite::Result<Vec<EntryRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,source_id,seq,offset,type_code,size_declared,base_offset,base_oid,data_start,data_end,crc32,payload,parse_error
             FROM pack_entries ORDER BY id")?;
        let rows = st.query_map([], entry_map)?;
        rows.collect()
    }

    pub fn get_entry(&self, id: i64) -> rusqlite::Result<Option<EntryRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,source_id,seq,offset,type_code,size_declared,base_offset,base_oid,data_start,data_end,crc32,payload,parse_error
             FROM pack_entries WHERE id=?1")?;
        let mut rows = st.query_map(params![id], entry_map)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn save_resolution(&self, r: &ResolutionRow) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO resolutions(entry_id,status,oid,type_name,content,steps,blocking,error,depth,expanded,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                r.entry_id, r.status, r.oid, r.type_name, r.content, r.steps, r.blocking,
                r.error, r.depth, r.expanded, now(),
            ],
        )
        .map(|_| ())
    }

    pub fn get_resolution(&self, entry_id: i64) -> rusqlite::Result<Option<ResolutionRow>> {
        let mut st = self.conn.prepare(
            "SELECT entry_id,status,oid,type_name,content,steps,blocking,error,depth,expanded,updated_at
             FROM resolutions WHERE entry_id=?1")?;
        let mut rows = st.query_map(params![entry_id], resolution_map)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn all_resolutions(&self) -> rusqlite::Result<Vec<ResolutionRow>> {
        let mut st = self.conn.prepare(
            "SELECT entry_id,status,oid,type_name,content,steps,blocking,error,depth,expanded,updated_at
             FROM resolutions ORDER BY entry_id")?;
        let rows = st.query_map([], resolution_map)?;
        rows.collect()
    }

    pub fn delete_resolution(&self, entry_id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM resolutions WHERE entry_id=?1", params![entry_id])
            .map(|_| ())
    }

    pub fn set_pin(&self, oid: &str, choice: &str) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO pins(oid,choice) VALUES(?1,?2)",
                params![oid, choice],
            )
            .map(|_| ())
    }

    pub fn clear_pin(&self, oid: &str) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM pins WHERE oid=?1", params![oid])
            .map(|_| ())
    }

    pub fn all_pins(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare("SELECT oid,choice FROM pins ORDER BY oid")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn get_meta(&self, key: &str) -> rusqlite::Result<Option<String>> {
        let mut st = self.conn.prepare("SELECT value FROM meta WHERE key=?1")?;
        let mut rows = st.query_map(params![key], |r| r.get(0))?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn set_meta(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)",
                params![key, value],
            )
            .map(|_| ())
    }
}

fn entry_map(r: &rusqlite::Row) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        id: r.get(0)?,
        source_id: r.get(1)?,
        seq: r.get(2)?,
        offset: r.get(3)?,
        type_code: r.get(4)?,
        size_declared: r.get(5)?,
        base_offset: r.get(6)?,
        base_oid: r.get(7)?,
        data_start: r.get(8)?,
        data_end: r.get(9)?,
        crc32: r.get(10)?,
        payload: r.get(11)?,
        parse_error: r.get(12)?,
    })
}

fn resolution_map(r: &rusqlite::Row) -> rusqlite::Result<ResolutionRow> {
    Ok(ResolutionRow {
        entry_id: r.get(0)?,
        status: r.get(1)?,
        oid: r.get(2)?,
        type_name: r.get(3)?,
        content: r.get(4)?,
        steps: r.get(5)?,
        blocking: r.get(6)?,
        error: r.get(7)?,
        depth: r.get(8)?,
        expanded: r.get(9)?,
        updated_at: r.get(10)?,
    })
}
