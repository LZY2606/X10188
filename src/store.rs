use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub fingerprint: String,
    pub size: i64,
    pub seq: i64,
}

#[derive(Debug, Clone)]
pub struct CandidateRow {
    pub id: i64,
    pub source_id: i64,
    pub source_fingerprint: String,
    pub offset: i64,
    pub obj_type: String,
    pub declared_size: Option<i64>,
    pub data_offset: Option<i64>,
    pub compressed_len: Option<i64>,
    pub raw_len: Option<i64>,
    pub base_kind: String, // none | ofs | ref
    pub base_ofs: Option<i64>,
    pub base_ref: Option<String>,
    pub status: String, // pending | resolved | blocked | error
    pub oid: Option<String>,
    pub content_len: Option<i64>,
    pub error: Option<String>,
    pub crc32: Option<i64>,
    pub idx_crc32: Option<i64>,
    pub depth: i64,
    pub resolved_run: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DeltaStepRow {
    pub id: i64,
    pub candidate_id: i64,
    pub step: i64,
    pub base_candidate_id: Option<i64>,
    pub base_desc: String,
    pub range_start: i64,
    pub range_end: i64,
    pub ops_json: String,
    pub input_len: i64,
    pub output_len: i64,
    pub check_ok: bool,
    pub run: i64,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    size INTEGER NOT NULL,
    seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    "offset" INTEGER NOT NULL,
    obj_type TEXT NOT NULL,
    declared_size INTEGER,
    data_offset INTEGER,
    compressed_len INTEGER,
    raw_len INTEGER,
    base_kind TEXT NOT NULL DEFAULT 'none',
    base_ofs INTEGER,
    base_ref TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    oid TEXT,
    content_len INTEGER,
    error TEXT,
    crc32 INTEGER,
    idx_crc32 INTEGER,
    depth INTEGER NOT NULL DEFAULT 0,
    resolved_run INTEGER
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_candidates_source_off ON candidates(source_id, "offset");

CREATE TABLE IF NOT EXISTS contents (
    candidate_id INTEGER PRIMARY KEY REFERENCES candidates(id) ON DELETE CASCADE,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    step INTEGER NOT NULL,
    base_candidate_id INTEGER,
    base_desc TEXT NOT NULL,
    range_start INTEGER NOT NULL,
    range_end INTEGER NOT NULL,
    ops_json TEXT NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    run INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_steps_candidate ON delta_steps(candidate_id);

CREATE TABLE IF NOT EXISTS idx_entries (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    crc32 INTEGER NOT NULL,
    "offset" INTEGER NOT NULL,
    fanout_bucket INTEGER NOT NULL,
    fanout_cumulative INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    oid TEXT PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_memory() -> rusqlite::Result<Db> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn next_seq(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM sources", [], |r| r.get(0))
            .unwrap_or(1)
    }

    pub fn next_run(&self) -> i64 {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let n: i64 = tx
            .query_row("SELECT COALESCE(value, '0') FROM meta WHERE key='run'", [], |r| {
                r.get::<_, String>(0).and_then(|s| s.parse::<i64>().map_err(|e| e.into()))
            })
            .unwrap_or(0);
        tx.execute("INSERT INTO meta(key,value) VALUES('run', ?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![n + 1])
            .unwrap();
        tx.commit().unwrap();
        n + 1
    }

    pub fn add_bytes_expanded(&self, n: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('expanded', ?1)
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?1",
            params![n],
        )
        .unwrap();
    }

    pub fn total_bytes_expanded(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(CAST(value AS INTEGER), 0) FROM meta WHERE key='expanded'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    pub fn insert_source(&self, name: &str, kind: &str, fingerprint: &str, size: i64) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sources(name, kind, fingerprint, size, seq) VALUES(?1,?2,?3,?4,?5)",
            params![name, kind, fingerprint, size, self_seq_placeholder(&conn)],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn list_sources(&self) -> Vec<SourceRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, kind, fingerprint, size, seq FROM sources ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(SourceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    kind: r.get(2)?,
                    fingerprint: r.get(3)?,
                    size: r.get(4)?,
                    seq: r.get(5)?,
                })
            })
            .unwrap();
        rows.flatten().collect()
    }

    pub fn get_source(&self, id: i64) -> Option<SourceRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, name, kind, fingerprint, size, seq FROM sources WHERE id=?1",
            params![id],
            |r| {
                Ok(SourceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    kind: r.get(2)?,
                    fingerprint: r.get(3)?,
                    size: r.get(4)?,
                    seq: r.get(5)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    pub fn delete_source(&self, id: i64) {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        // cascade through candidates / contents / steps manually for clarity
        tx.execute(
            "DELETE FROM contents WHERE candidate_id IN (SELECT id FROM candidates WHERE source_id=?1)",
            params![id],
        )
        .unwrap();
        tx.execute(
            "DELETE FROM delta_steps WHERE candidate_id IN (SELECT id FROM candidates WHERE source_id=?1)",
            params![id],
        )
        .unwrap();
        tx.execute(
            "DELETE FROM delta_steps WHERE base_candidate_id IN (SELECT id FROM candidates WHERE source_id=?1)",
            params![id],
        )
        .unwrap();
        tx.execute("DELETE FROM pins WHERE candidate_id IN (SELECT id FROM candidates WHERE source_id=?1)", params![id])
            .unwrap();
        tx.execute("DELETE FROM candidates WHERE source_id=?1", params![id]).unwrap();
        tx.execute("DELETE FROM idx_entries WHERE source_id=?1", params![id]).unwrap();
        tx.execute("DELETE FROM sources WHERE id=?1", params![id]).unwrap();
        tx.commit().unwrap();
    }

    pub fn list_candidates(&self) -> Vec<CandidateRow> {
        let conn = self.conn.lock().unwrap();
        list_candidates_conn(&conn)
    }

    pub fn get_candidate(&self, id: i64) -> Option<CandidateRow> {
        let conn = self.conn.lock().unwrap();
        get_candidate_conn(&conn, id)
    }

    pub fn get_content(&self, candidate_id: i64) -> Option<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT payload FROM contents WHERE candidate_id=?1",
            params![candidate_id],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
        .flatten()
    }

    pub fn steps_for(&self, candidate_id: i64) -> Vec<DeltaStepRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, candidate_id, step, base_candidate_id, base_desc,
                        range_start, range_end, ops_json, input_len, output_len, check_ok, run
                 FROM delta_steps WHERE candidate_id=?1 ORDER BY step",
            )
            .unwrap();
        let rows = stmt.query_map(params![candidate_id], |r| {
            Ok(DeltaStepRow {
                id: r.get(0)?,
                candidate_id: r.get(1)?,
                step: r.get(2)?,
                base_candidate_id: r.get(3)?,
                base_desc: r.get(4)?,
                range_start: r.get(5)?,
                range_end: r.get(6)?,
                ops_json: r.get(7)?,
                input_len: r.get(8)?,
                output_len: r.get(9)?,
                check_ok: r.get::<_, i64>(10)? != 0,
                run: r.get(11)?,
            })
        }).unwrap();
        rows.flatten().collect()
    }

    pub fn pins(&self) -> Vec<(String, i64)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT oid, candidate_id FROM pins").unwrap();
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap();
        rows.flatten().collect()
    }

    pub fn set_pin(&self, oid: &str, candidate_id: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pins(oid, candidate_id) VALUES(?1,?2)
             ON CONFLICT(oid) DO UPDATE SET candidate_id=?2",
            params![oid, candidate_id],
        )
        .unwrap();
    }

    pub fn clear_pin(&self, oid: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pins WHERE oid=?1", params![oid]).unwrap();
    }

    pub fn idx_entries_for(&self, source_id: i64) -> Vec<(String, i64, i64, i64, i64)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT oid, crc32, \"offset\", fanout_bucket, fanout_cumulative FROM idx_entries WHERE source_id=?1 ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map(params![source_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))
            })
            .unwrap();
        rows.flatten().collect()
    }
}

/// insert sequence computed inside the same lock
fn self_seq_placeholder(conn: &Connection) -> i64 {
    conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM sources", [], |r| r.get(0))
        .unwrap_or(1)
}

pub fn list_candidates_conn(conn: &Connection) -> Vec<CandidateRow> {
    let sql = r#"
        SELECT c.id, c.source_id, s.fingerprint, c."offset", c.obj_type,
               c.declared_size, c.data_offset, c.compressed_len, c.raw_len,
               c.base_kind, c.base_ofs, c.base_ref,
               c.status, c.oid, c.content_len, c.error, c.crc32, c.idx_crc32,
               c.depth, c.resolved_run
        FROM candidates c JOIN sources s ON s.id = c.source_id
        ORDER BY s.fingerprint, c."offset", c.id
    "#;
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(CandidateRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                source_fingerprint: r.get(2)?,
                offset: r.get(3)?,
                obj_type: r.get(4)?,
                declared_size: r.get(5)?,
                data_offset: r.get(6)?,
                compressed_len: r.get(7)?,
                raw_len: r.get(8)?,
                base_kind: r.get(9)?,
                base_ofs: r.get(10)?,
                base_ref: r.get(11)?,
                status: r.get(12)?,
                oid: r.get(13)?,
                content_len: r.get(14)?,
                error: r.get(15)?,
                crc32: r.get(16)?,
                idx_crc32: r.get(17)?,
                depth: r.get(18)?,
                resolved_run: r.get(19)?,
            })
        })
        .unwrap();
    rows.flatten().collect()
}

pub fn get_candidate_conn(conn: &Connection, id: i64) -> Option<CandidateRow> {
    let rows = list_candidates_conn(conn);
    rows.into_iter().find(|c| c.id == id)
}
