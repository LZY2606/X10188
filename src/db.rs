use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub total_bytes: usize,
    pub single_ratio_num: u64,
    pub single_ratio_den: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_depth: 50,
            total_bytes: 32 * 1024 * 1024,
            single_ratio_num: 1,
            single_ratio_den: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub id: i64,
    pub oid: String,
    pub source_id: i64,
    pub source_name: String,
    pub source_kind: String,
    pub offset: Option<i64>,
    pub type_name: Option<String>,
    pub status: String,
    pub depth: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub actual_oid: Option<String>,
    pub id_ok: Option<bool>,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedChain {
    pub candidate_id: i64,
    pub oid: String,
    pub chain: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyItem {
    pub oid: String,
    pub candidate_id: i64,
    pub source_name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceDependency {
    pub source_id: i64,
    pub source_name: String,
    pub dependents: Vec<DependencyItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolveSummary {
    pub resolved: usize,
    pub blocked: usize,
    pub bad: usize,
    pub paused: usize,
    pub touched_oids: Vec<String>,
}

pub struct Store {
    pub conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|err| err.to_string())?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|err| err.to_string())?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(include_str!("schema.sql"))
            .map_err(|err| err.to_string())
    }

    pub fn upsert_source(
        &self,
        name: &str,
        kind: &str,
        path: &str,
        len: i64,
        sha256: &str,
    ) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO sources(name, kind, path, len, sha256) VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,path=excluded.path,len=excluded.len,sha256=excluded.sha256,imported_at=CURRENT_TIMESTAMP",
                params![name, kind, path, len, sha256],
            )
            .map_err(|err| err.to_string())?;
        self.conn
            .query_row("SELECT id FROM sources WHERE name=?1", params![name], |row| {
                row.get(0)
            })
            .map_err(|err| err.to_string())
    }

    pub fn link_pack_index(&self, pack_source_id: i64, index_source_id: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO source_links(pack_source_id,index_source_id) VALUES (?1,?2)",
                params![pack_source_id, index_source_id],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn clear_candidate_steps(&self, candidate_id: i64) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM delta_steps WHERE candidate_id=?1", params![candidate_id])
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn insert_edge(
        &self,
        child_id: i64,
        base_oid: &str,
        base_kind: &str,
        base_offset: Option<i64>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO edges(candidate_id,base_oid,base_kind,base_offset)
                 VALUES (?1,?2,?3,?4)",
                params![child_id, base_oid, base_kind, base_offset],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn insert_delta_step(
        &self,
        candidate_id: i64,
        ordinal: i64,
        base_candidate_id: Option<i64>,
        base_oid: Option<&str>,
        op_index: i64,
        opcode: &str,
        range_start: i64,
        range_end: i64,
        base_offset: Option<i64>,
        base_len: Option<i64>,
        insert_len: Option<i64>,
        input_len: i64,
        output_before: i64,
        output_after: i64,
        check_ok: bool,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO delta_steps(candidate_id,ordinal,base_candidate_id,base_oid,op_index,opcode,range_start,range_end,base_offset,base_len,insert_len,input_len,output_before,output_after,check_ok)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    candidate_id,
                    ordinal,
                    base_candidate_id,
                    base_oid,
                    op_index,
                    opcode,
                    range_start,
                    range_end,
                    base_offset,
                    base_len,
                    insert_len,
                    input_len,
                    output_before,
                    output_after,
                    check_ok
                ],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn add_error(&self, candidate_id: i64, code: &str, message: &str, evidence: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO errors(candidate_id,code,message,evidence) VALUES (?1,?2,?3,?4)",
                params![candidate_id, code, message, evidence],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn add_pack_error(&self, source_id: i64, code: &str, message: &str, evidence: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO errors(source_id,candidate_id,code,message,evidence) VALUES (?1,NULL,?2,?3,?4)",
                params![source_id, code, message, evidence],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_object(
        &self,
        oid: &str,
        source_id: i64,
        location: &str,
        pack_ordinal: Option<i64>,
        header_offset: Option<i64>,
        data_offset: Option<i64>,
        next_offset: Option<i64>,
        kind: &str,
        declared_size: i64,
        inflated_size: i64,
        delta_type: &str,
        delta_base_oid: Option<&str>,
        delta_target_offset: Option<i64>,
        raw_payload: &[u8],
        delta_payload: Option<&[u8]>,
        status: &str,
    ) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO objects(
                    oid,source_id,location,pack_ordinal,header_offset,data_offset,next_offset,
                    kind,declared_size,inflated_size,delta_type,delta_base_oid,delta_target_offset,
                    raw_payload,delta_payload,status,input_len,output_len
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)
                 ON CONFLICT(source_id,location) DO UPDATE SET
                    oid=excluded.oid, pack_ordinal=excluded.pack_ordinal,
                    header_offset=excluded.header_offset,data_offset=excluded.data_offset,
                    next_offset=excluded.next_offset,kind=excluded.kind,
                    declared_size=excluded.declared_size,inflated_size=excluded.inflated_size,
                    delta_type=excluded.delta_type,delta_base_oid=excluded.delta_base_oid,
                    delta_target_offset=excluded.delta_target_offset,raw_payload=excluded.raw_payload,
                    delta_payload=excluded.delta_payload,status=excluded.status,
                    resolved_payload=NULL,resolved_type=NULL,actual_oid=NULL,id_ok=NULL,
                    depth=0,input_len=0,output_len=0,budget_ticket=NULL,last_attempt=CURRENT_TIMESTAMP",
                params![
                    oid,
                    source_id,
                    location,
                    pack_ordinal,
                    header_offset,
                    data_offset,
                    next_offset,
                    kind,
                    declared_size,
                    inflated_size,
                    delta_type,
                    delta_base_oid,
                    delta_target_offset,
                    raw_payload,
                    delta_payload,
                    status,
                    inflated_size,
                    0
                ],
            )
            .map_err(|err| err.to_string())?;
        self.conn
            .query_row(
                "SELECT id FROM objects WHERE source_id=?1 AND location=?2",
                params![source_id, location],
                |row| row.get(0),
            )
            .map_err(|err| err.to_string())
    }

    pub fn prepare_resolution(&self, ids: &[i64]) -> Result<(), String> {
        if ids.is_empty() {
            return Ok(());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "UPDATE objects SET status='queued',resolved_payload=NULL,resolved_type=NULL,actual_oid=NULL,id_ok=NULL,depth=0,output_len=0,budget_ticket=NULL,last_attempt=CURRENT_TIMESTAMP WHERE id IN ({placeholders})"
        );
        self.conn
            .execute(&sql, rusqlite::params_from_iter(ids.iter()))
            .map(|_| ())
            .map_err(|err| err.to_string())?;
        let sql = format!("DELETE FROM delta_steps WHERE candidate_id IN ({placeholders})");
        self.conn
            .execute(&sql, rusqlite::params_from_iter(ids.iter()))
            .map(|_| ())
            .map_err(|err| err.to_string())?;
        let sql = format!("DELETE FROM errors WHERE candidate_id IN ({placeholders})");
        self.conn
            .execute(&sql, rusqlite::params_from_iter(ids.iter()))
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn reset_all_unresolved(&self) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE objects SET status='queued' WHERE status IN ('blocked','paused','bad','resolved','queued')",
                [],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn set_success(
        &self,
        id: i64,
        kind: &str,
        payload: &[u8],
        actual_oid: &str,
        id_ok: bool,
        depth: i64,
        input_len: i64,
        output_len: i64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE objects SET status='resolved',resolved_type=?1,resolved_payload=?2,actual_oid=?3,id_ok=?4,depth=?5,input_len=?6,output_len=?7,budget_ticket=NULL,last_attempt=CURRENT_TIMESTAMP WHERE id=?8",
                params![kind, payload, actual_oid, id_ok, depth, input_len, output_len, id],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn set_failure(&self, id: i64, status: &str, budget_ticket: Option<i64>) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE objects SET status=?1,resolved_payload=NULL,resolved_type=NULL,actual_oid=NULL,id_ok=NULL,budget_ticket=?2,last_attempt=CURRENT_TIMESTAMP WHERE id=?3",
                params![status, budget_ticket, id],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn pin(&self, oid: &str, source_id: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO pins(oid,source_id) VALUES (?1,?2)
                 ON CONFLICT(oid) DO UPDATE SET source_id=excluded.source_id,created_at=CURRENT_TIMESTAMP",
                params![oid, source_id],
            )
            .map_err(|err| err.to_string())?;
        self.conn
            .execute(
                "UPDATE objects SET pinned=CASE WHEN oid=?1 AND source_id=?2 THEN 1 ELSE 0 END WHERE oid=?1",
                params![oid, source_id],
            )
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn unpin(&self, oid: &str) -> Result<(), String> {
        self.conn.execute("DELETE FROM pins WHERE oid=?1", params![oid]).map(|_| ()).map_err(|err| err.to_string())?;
        self.conn.execute("UPDATE objects SET pinned=0 WHERE oid=?1", params![oid]).map(|_| ()).map_err(|err| err.to_string())
    }

    pub fn object(&self, id: i64) -> Result<Candidate, String> {
        self.conn
            .query_row(&candidate_select("WHERE o.id=?1"), params![id], candidate_row)
            .map_err(|err| err.to_string())
    }

    pub fn object_payloads(&self, id: i64) -> Result<(Vec<u8>, Vec<u8>, Option<String>, Option<String>), String> {
        self.conn
            .query_row(
                "SELECT COALESCE(raw_payload,X''),COALESCE(delta_payload,X''),status,COALESCE(delta_base_oid,'') FROM objects WHERE id=?1",
                params![id],
                |row| {
                    let raw: Vec<u8> = row.get(0)?;
                    let delta: Vec<u8> = row.get(1)?;
                    let status: String = row.get(2)?;
                    let base: Option<String> = row.get::<_, String>(3).ok().filter(|value| !value.is_empty());
                    Ok((raw, delta, Some(status), base))
                },
            )
            .map_err(|err| err.to_string())
    }

    pub fn active_base(&self, base_oid: &str) -> Result<Option<Candidate>, String> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "{candidate_select} WHERE o.oid=?1 ORDER BY o.pinned DESC,
                 CASE o.status WHEN 'resolved' THEN 0 WHEN 'paused' THEN 1 WHEN 'queued' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
                 s.name, o.header_offset, o.id LIMIT 1",
                candidate_select = candidate_select("")
            ))
            .map_err(|err| err.to_string())?;
        stmt.query_row(params![base_oid], candidate_row).optional().map_err(|err| err.to_string())
    }

    pub fn candidates(&self) -> Result<Vec<Candidate>, String> {
        let mut stmt = self
            .conn
            .prepare(&candidate_select("ORDER BY o.oid, o.pinned DESC,
                 CASE o.status WHEN 'resolved' THEN 0 WHEN 'paused' THEN 1 WHEN 'queued' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
                 s.name, o.header_offset, o.id"))
            .map_err(|err| err.to_string())?;
        let rows = stmt.query_map([], candidate_row).map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn queued(&self) -> Result<Vec<i64>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM objects WHERE status='queued' ORDER BY id")
            .map_err(|err| err.to_string())?;
        let rows = stmt.query_map([], |row| row.get(0)).map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn reverse_dependents(&self, root_ids: &[i64]) -> Result<Vec<i64>, String> {
        if root_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut oids = Vec::new();
        for id in root_ids {
            let candidate = self.object(*id)?;
            oids.push(candidate.oid);
        }
        let placeholders = oids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "WITH RECURSIVE reach(oid) AS (
                SELECT value FROM (VALUES {values})
                UNION
                SELECT o.oid FROM objects o JOIN edges e ON e.candidate_id=o.id JOIN reach r ON e.base_oid=r.oid
             )
             SELECT o.id FROM objects o JOIN reach r ON o.oid=r.oid ORDER BY o.id",
            values = oids
                .iter()
                .map(|_| "(?)".to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut stmt = self.conn.prepare(&sql).map_err(|err| err.to_string())?;
        let rows = stmt.query_map(rusqlite::params_from_iter(oids), |row| row.get(0)).map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

fn candidate_select(where_or_order: &str) -> String {
    format!(
        "SELECT o.id,o.oid,o.source_id,s.name,s.kind,o.header_offset,COALESCE(o.resolved_type,o.kind),
                o.status,o.depth,o.input_len,o.output_len,COALESCE(o.actual_oid,''),o.id_ok,o.pinned
         FROM objects o JOIN sources s ON s.id=o.source_id {where_or_order}"
    )
}

fn candidate_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Candidate> {
    let actual: String = row.get(11)?;
    Ok(Candidate {
        id: row.get(0)?,
        oid: row.get(1)?,
        source_id: row.get(2)?,
        source_name: row.get(3)?,
        source_kind: row.get(4)?,
        offset: row.get(5)?,
        type_name: row.get(6)?,
        status: row.get(7)?,
        depth: row.get(8)?,
        input_len: row.get(9)?,
        output_len: row.get(10)?,
        actual_oid: if actual.is_empty() { None } else { Some(actual) },
        id_ok: row.get(12)?,
        pinned: row.get::<_, i64>(13)? != 0,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorRecord {
    pub id: i64,
    pub source_id: Option<i64>,
    pub candidate_id: Option<i64>,
    pub code: String,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaStepRecord {
    pub ordinal: i64,
    pub base_candidate_id: Option<i64>,
    pub base_oid: Option<String>,
    pub op_index: i64,
    pub opcode: String,
    pub range_start: i64,
    pub range_end: i64,
    pub base_offset: Option<i64>,
    pub base_len: Option<i64>,
    pub insert_len: Option<i64>,
    pub input_len: i64,
    pub output_before: i64,
    pub output_after: i64,
    pub check_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRecord {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub path: String,
    pub len: i64,
    pub sha256: String,
}

impl Store {
    pub fn sources(&self) -> Result<Vec<SourceRecord>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,name,kind,path,len,sha256 FROM sources ORDER BY name")
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SourceRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    path: row.get(3)?,
                    len: row.get(4)?,
                    sha256: row.get(5)?,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn source(&self, source_id: i64) -> Result<SourceRecord, String> {
        self.conn
            .query_row(
                "SELECT id,name,kind,path,len,sha256 FROM sources WHERE id=?1",
                params![source_id],
                |row| {
                    Ok(SourceRecord {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        kind: row.get(2)?,
                        path: row.get(3)?,
                        len: row.get(4)?,
                        sha256: row.get(5)?,
                    })
                },
            )
            .map_err(|err| err.to_string())
    }

    pub fn errors_for(&self, candidate_id: Option<i64>) -> Result<Vec<ErrorRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,source_id,candidate_id,code,message,evidence FROM errors
                 WHERE (?1 IS NULL AND candidate_id IS NULL) OR candidate_id=?1 ORDER BY id",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![candidate_id], |row| {
                Ok(ErrorRecord {
                    id: row.get(0)?,
                    source_id: row.get(1)?,
                    candidate_id: row.get(2)?,
                    code: row.get(3)?,
                    message: row.get(4)?,
                    evidence: row.get(5)?,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn steps_for(&self, candidate_id: i64) -> Result<Vec<DeltaStepRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ordinal,base_candidate_id,base_oid,op_index,opcode,range_start,range_end,
                        base_offset,base_len,insert_len,input_len,output_before,output_after,check_ok
                 FROM delta_steps WHERE candidate_id=?1 ORDER BY ordinal,id",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![candidate_id], |row| {
                Ok(DeltaStepRecord {
                    ordinal: row.get(0)?,
                    base_candidate_id: row.get(1)?,
                    base_oid: row.get(2)?,
                    op_index: row.get(3)?,
                    opcode: row.get(4)?,
                    range_start: row.get(5)?,
                    range_end: row.get(6)?,
                    base_offset: row.get(7)?,
                    base_len: row.get(8)?,
                    insert_len: row.get(9)?,
                    input_len: row.get(10)?,
                    output_before: row.get(11)?,
                    output_after: row.get(12)?,
                    check_ok: row.get::<_, i64>(13)? != 0,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn resolved_payload(&self, id: i64) -> Result<(String, Vec<u8>), String> {
        self.conn
            .query_row(
                "SELECT COALESCE(resolved_type,''),COALESCE(resolved_payload,X'') FROM objects WHERE id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|err| err.to_string())
    }

    pub fn update_oid(&self, id: i64, oid: &str) -> Result<(), String> {
        self.conn
            .execute("UPDATE objects SET oid=?1 WHERE id=?2", params![oid, id])
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub fn base_edges(&self, id: i64) -> Result<Vec<(String, String, Option<i64>)>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT base_oid,base_kind,base_offset FROM edges WHERE candidate_id=?1")
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())
    }

    pub fn blocked_chains(&self) -> Result<Vec<BlockedChain>, String> {
        let candidates = self.candidates()?;
        let mut edges = std::collections::HashMap::new();
        for candidate in &candidates {
            edges.insert(candidate.id, self.base_edges(candidate.id)?);
        }
        let by_oid = |oid: &str| {
            candidates
                .iter()
                .filter(|item| item.oid == oid)
                .min_by_key(|item| match item.status.as_str() {
                    "resolved" => 0,
                    "paused" => 1,
                    "queued" => 2,
                    "blocked" => 3,
                    _ => 4,
                })
        };
        let mut result = Vec::new();
        for candidate in candidates.iter().filter(|item| item.status != "resolved") {
            let mut chain = vec![format!("{}#{} ({})", candidate.oid, candidate.id, candidate.status)];
            let mut current_id = candidate.id;
            let mut seen = vec![current_id];
            let mut reason = candidate.status.clone();
            for _ in 0..128 {
                let edge = edges.get(&current_id).and_then(|items| items.first().cloned());
                let Some((base_oid, base_kind, base_offset)) = edge else { break };
                let base = by_oid(&base_oid);
                let offset_note = base_offset
                    .map(|offset| format!("@{offset}"))
                    .unwrap_or_default();
                chain.push(format!("{base_kind}:{base_oid}{offset_note}"));
                let Some(base) = base else {
                    reason = "missing_external_base".into();
                    break;
                };
                if seen.contains(&base.id) {
                    reason = "delta_cycle".into();
                    chain.push(format!("cycle→{}#{}", base.oid, base.id));
                    break;
                }
                seen.push(base.id);
                if base.status == "resolved" {
                    reason = format!("blocked_but_base_resolved:{}", candidate.status);
                    break;
                }
                if base.status == "bad" {
                    reason = "bad_base".into();
                }
                if base.status == "paused" {
                    reason = "budget_paused_base".into();
                }
                current_id = base.id;
            }
            result.push(BlockedChain {
                candidate_id: candidate.id,
                oid: candidate.oid.clone(),
                chain,
                reason,
            });
        }
        Ok(result)
    }

    pub fn source_dependencies(&self, source_id: i64) -> Result<SourceDependency, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT o.oid,o.id,s.name,o.status FROM objects o JOIN sources s ON s.id=o.source_id
                 WHERE o.source_id=?1 OR o.id IN (
                     SELECT e.candidate_id FROM edges e JOIN objects base ON base.oid=e.base_oid
                     WHERE base.source_id=?1
                 ) ORDER BY o.oid,s.name,o.id",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![source_id], |row| {
                Ok(DependencyItem {
                    oid: row.get(0)?,
                    candidate_id: row.get(1)?,
                    source_name: row.get(2)?,
                    status: row.get(3)?,
                })
            })
            .map_err(|err| err.to_string())?;
        let dependents = rows.collect::<Result<Vec<_>, _>>().map_err(|err| err.to_string())?;
        let source = self.source(source_id)?;
        Ok(SourceDependency {
            source_id,
            source_name: source.name,
            dependents,
        })
    }

    pub fn delete_source(&self, source_id: i64) -> Result<(), String> {
        let path = self
            .conn
            .query_row("SELECT path FROM sources WHERE id=?1", params![source_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|err| err.to_string())?;
        self.conn
            .execute("DELETE FROM sources WHERE id=?1", params![source_id])
            .map(|_| ())
            .map_err(|err| err.to_string())?;
        if let Some(path) = path {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}
