use sha2::Digest;
use std::error::Error;
use crate::git::{self, ObjectId, ObjectType};
use crate::schema::open_conn;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub max_delta_depth: usize,
    pub max_total_expanded: u64,
    pub max_object_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Self { max_delta_depth: 64, max_total_expanded: 256 * 1024 * 1024, max_object_ratio: 32.0 }
    }
}

#[derive(Serialize)]
pub struct ImportResult {
    pub source_id: i64,
    pub kind: String,
    pub candidate_count: usize,
    pub run: RunSummary,
}

#[derive(Serialize, Clone)]
pub struct RunSummary {
    pub branch_id: i64,
    pub state: String,
    pub used_bytes: u64,
    pub queue_len: usize,
    pub active_chain: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceView {
    pub id: i64,
    pub kind: String,
    pub original_name: String,
    pub path: String,
    pub sha256: String,
    pub size: i64,
    pub summary: serde_json::Value,
    pub errors: serde_json::Value,
    pub dependent_objects: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidateView {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    pub claimed_oid: Option<String>,
    pub actual_oid: Option<String>,
    pub object_type: Option<String>,
    pub pack_offset: Option<i64>,
    pub payload_offset: Option<i64>,
    pub end_offset: Option<i64>,
    pub inflated_size: Option<i64>,
    pub compressed_size: Option<i64>,
    pub base_claim: Option<String>,
    pub base_offset: Option<i64>,
    pub integrity: String,
    pub status: String,
    pub error: Option<String>,
    pub evidence: serde_json::Value,
    pub resolution: Option<ResolutionView>,
    pub blockers: Vec<BlockerView>,
    pub steps: Vec<StepView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolutionView {
    pub state: String,
    pub actual_oid: Option<String>,
    pub object_type: Option<String>,
    pub output_size: Option<i64>,
    pub delta_depth: i64,
    pub charged_bytes: i64,
    pub error: Option<String>,
    pub preview: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockerView {
    pub kind: String,
    pub base_candidate_id: Option<i64>,
    pub base_oid: Option<String>,
    pub reason: String,
    pub chain: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepView {
    pub position: i64,
    pub base_candidate_id: Option<i64>,
    pub base_oid: Option<String>,
    pub instruction_start: i64,
    pub instruction_end: i64,
    pub base_size: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub check_ok: bool,
    pub details: serde_json::Value,
}

#[derive(Serialize)]
pub struct Dashboard {
    pub sources: Vec<SourceView>,
    pub candidates: Vec<CandidateView>,
    pub run: RunSummary,
    pub budget: Budget,
}

#[derive(Clone, Debug)]
struct CandidateRow {
    id: i64,
    source_id: i64,
    kind: String,
    claimed_oid: Option<String>,
    actual_oid: Option<String>,
    object_type: Option<String>,
    pack_offset: Option<i64>,
    payload_offset: Option<i64>,
    end_offset: Option<i64>,
    inflated_size: Option<i64>,
    compressed_size: Option<i64>,
    base_claim: Option<String>,
    base_offset: Option<i64>,
    integrity: String,
    status: String,
    error: Option<String>,
}

#[derive(Clone)]
struct ChainItem {
    candidate: CandidateRow,
    instruction_start: usize,
    instruction_end: usize,
}

#[derive(Clone)]
struct RunState {
    state: String,
    used_bytes: u64,
    queue: Vec<i64>,
    active_chain: Vec<i64>,
}

pub struct Service {
    pub conn: Mutex<Connection>,
    data_dir: PathBuf,
}

impl Service {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join("imports")).map_err(|e| e.to_string())?;
        fs::create_dir_all(dir.join("objects")).map_err(|e| e.to_string())?;
        let conn = open_conn(&dir.join("microscope.db")).map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn), data_dir: dir })
    }

    pub fn import_bytes(&self, original_name: &str, bytes: &[u8]) -> Result<ImportResult, String> {
        let digest = sha2::Sha256::digest(bytes);
        let sha256 = hex::encode(digest);
        if let Some(existing) = self.conn.lock().unwrap()
            .query_row("SELECT id,kind FROM sources WHERE sha256=?1", params![sha256], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,String>(1)?)))
            .optional().map_err(|e| e.to_string())?
        {
            return self.after_import(existing.0, existing.1, 0);
        }
        let kind = detect_kind(original_name, bytes);
        let safe = sanitize_name(original_name);
        let path = self.data_dir.join("imports").join(format!("{}-{}", &sha256[..16], safe));
        fs::write(&path, bytes).map_err(|e| e.to_string())?;
        let summary = serde_json::json!({"detected_kind": kind});
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sources(kind,original_name,path,sha256,size,imported_at,summary,errors) VALUES(?1,?2,?3,?4,?5,strftime('%s','now'),?6,'[]')",
            params![kind, original_name, path.to_string_lossy(), sha256, bytes.len() as i64, serde_json::to_string(&summary).unwrap()],
        ).map_err(|e| e.to_string())?;
        let source_id = conn.last_insert_rowid();
        drop(conn);

        let count = match kind.as_str() {
            "pack" => self.import_pack(source_id, bytes)?,
            "idx" => self.import_idx(source_id, bytes)?,
            "loose" => self.import_loose(source_id, bytes)?,
            _ => 0,
        };
        self.after_import(source_id, kind, count)
    }

    fn after_import(&self, source_id: i64, kind: String, candidate_count: usize) -> Result<ImportResult, String> {
        self.resolve(1, Budget::default())?;
        Ok(ImportResult { source_id, kind, candidate_count, run: self.run_summary(1)? })
    }

    fn import_pack(&self, source_id: i64, bytes: &[u8]) -> Result<usize, String> {
        let idx = self.find_matching_idx(bytes);
        let claims = idx.as_ref().map(|(_, parse)| {
            parse.entries.iter().map(|e| (e.offset, (e.oid, e.crc32))).collect::<HashMap<_,_>>()
        });
        let pack = git::pack::parse_pack(bytes, claims.as_ref());
        let mut summary = serde_json::json!({
            "version": pack.version,
            "object_count": pack.object_count,
            "checksum_ok": pack.checksum_ok,
            "stored_checksum": pack.stored_checksum.hex(),
            "actual_checksum": pack.actual_checksum.hex(),
        });
        if let Some((idx_source_id, idx_parse)) = &idx {
            summary["paired_idx_source_id"] = (*idx_source_id).into();
            summary["index_fanout"] = serde_json::to_value(idx_parse.fanout.to_vec()).unwrap_or(serde_json::Value::Null);
            let mut conn = self.conn.lock().unwrap();
            conn.execute("UPDATE sources SET paired_source_id=?1 WHERE id=?2 OR id=?3", params![idx_source_id, source_id, idx_source_id]).map_err(|e| e.to_string())?;
        }
        let errors = serde_json::to_value(pack.errors.iter().map(|e| serde_json::json!({"offset":e.offset,"code":e.code,"message":e.message})).collect::<Vec<_>>()).unwrap();
        {
            let conn = self.conn.lock().unwrap();
            conn.execute("UPDATE sources SET summary=?1,errors=?2 WHERE id=?3", params![serde_json::to_string(&summary).unwrap(), serde_json::to_string(&errors).unwrap(), source_id]).map_err(|e| e.to_string())?;
        }
        let mut count = 0;
        for entry in pack.entries {
            let claimed = claims.as_ref().and_then(|map| map.get(&entry.offset)).map(|(oid,_)| oid.hex());
            let error = entry.error.clone();
            let evidence = serde_json::json!({
                "type": entry.kind.git_name(),
                "declared_size": entry.declared_size,
                "compressed_len": entry.compressed_len,
                "payload_offset": entry.payload_offset,
                "negative_offset": entry.negative_offset,
            });
            let integrity = if error.is_some() { "bad" } else if pack.checksum_ok { "verified" } else { "pack_checksum_bad" };
            let status = if error.is_some() { "corrupt" } else { "discovered" };
            let inflated_size = entry.inflated.len() as i64;
            let base_claim = entry.ref_base.map(|oid| oid.hex());
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO candidates(source_id,kind,claimed_oid,object_type,pack_offset,payload_offset,end_offset,header_size,inflated_size,compressed_size,base_claim,base_offset,integrity,status,error,evidence)
                 VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![source_id, claimed, entry.kind.git_name(), entry.offset as i64, entry.payload_offset as i64, entry.end_offset as i64, entry.header_size as i64, inflated_size, entry.compressed_len as i64, base_claim, entry.base_offset.map(|v| v as i64), integrity, status, error, evidence],
            ).map_err(|e| e.to_string())?;
            let candidate_id = conn.last_insert_rowid();
            drop(conn);
            fs::create_dir_all(self.data_dir.join("objects/raw")).map_err(|e| e.to_string())?;
            fs::write(self.raw_path(candidate_id), entry.inflated).map_err(|e| e.to_string())?;
            count += 1;
        }
        Ok(count)
    }

    fn import_idx(&self, source_id: i64, bytes: &[u8]) -> Result<usize, String> {
        let pack_bytes = self.find_matching_pack_bytes(bytes);
        let parse = git::idx::parse_idx(bytes, pack_bytes.as_deref()).map_err(|e| e)?;
        let summary = serde_json::json!({
            "version": parse.version,
            "object_count": parse.object_count,
            "fanout": parse.fanout.to_vec(),
            "checksum_ok": parse.checksum_ok,
            "pack_checksum_ok": parse.pack_checksum_ok,
        });
        let errors = serde_json::to_value(&parse.errors).unwrap();
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE sources SET summary=?1,errors=?2 WHERE id=?3", params![serde_json::to_string(&summary).unwrap(), serde_json::to_string(&errors).unwrap(), source_id]).map_err(|e| e.to_string())?;
        Ok(0)
    }

    fn import_loose(&self, source_id: i64, bytes: &[u8]) -> Result<usize, String> {
        let parsed = git::loose::parse_loose(bytes)?;
        let actual = parsed.actual_oid.hex();
        let evidence = serde_json::json!({"declared_size": parsed.declared_size, "payload_offset": parsed.payload_offset});
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO candidates(source_id,kind,claimed_oid,actual_oid,object_type,pack_offset,payload_offset,end_offset,header_size,inflated_size,compressed_size,integrity,status,evidence)
             VALUES(?1,'loose',?2,?2,?3,NULL,?4,NULL,NULL,?5,NULL,'verified','discovered',?6)",
            params![source_id, actual, parsed.kind.git_name(), parsed.payload_offset as i64, parsed.data.len() as i64, serde_json::to_string(&evidence).unwrap()],
        ).map_err(|e| e.to_string())?;
        let candidate_id = conn.last_insert_rowid();
        let raw_path = self.raw_path(candidate_id);
        drop(conn);
        fs::write(raw_path, parsed.data).map_err(|e| e.to_string())?;
        Ok(1)
    }

    fn find_matching_idx(&self, pack: &[u8]) -> Option<(i64, git::idx::IdxParse)> {
        if pack.len() < 20 { return None; }
        let expected = ObjectId::new(pack[pack.len()-20..].try_into().ok()?).hex();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id,path FROM sources WHERE kind='idx'").ok()?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,String>(1)?))).ok()?;
        for row in rows.flatten() {
            if let Ok(bytes) = fs::read(&row.1) {
                if let Ok(parse) = git::idx::parse_idx(&bytes, Some(pack)) {
                    let stored = ObjectId::new(bytes[bytes.len()-40..bytes.len()-20].try_into().ok()?).hex();
                    if stored == expected && parse.pack_checksum_ok {
                        return Some((row.0, parse));
                    }
                }
            }
        }
        None
    }

    fn find_matching_pack_bytes(&self, idx: &[u8]) -> Option<Vec<u8>> {
        if idx.len() < 40 { return None; }
        let expected = hex::encode(&idx[idx.len()-40..idx.len()-20]);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT path FROM sources WHERE kind='pack'").ok()?;
        let rows = stmt.query_map([], |row| row.get::<_,String>(0)).ok()?;
        for path in rows.flatten() {
            if let Ok(bytes) = fs::read(path) {
                if bytes.len() >= 20 && hex::encode(&bytes[bytes.len()-20..]) == expected { return Some(bytes); }
            }
        }
        None
    }

    pub fn resolve(&self, branch_id: i64, budget: Budget) -> Result<RunSummary, String> {
        self.mark_corrupt(branch_id)?;
        self.ensure_run(branch_id)?;
        let initial_pending = self.pending_candidates(branch_id)?;
        {
            let conn = self.conn.lock().unwrap();
            let mut run = self.load_run(&conn, branch_id)?;
            let known: HashSet<i64> = initial_pending.iter().map(|c| c.id).collect();
            if run.queue.is_empty() && !initial_pending.is_empty() {
                run.queue = initial_pending.iter().map(|c| c.id).collect();
                self.save_run(&conn, branch_id, &run)?;
            } else {
                run.queue.retain(|id| known.contains(id));
                self.save_run(&conn, branch_id, &run)?;
            }
        }

        loop {
            let candidate_id = {
                let conn = self.conn.lock().unwrap();
                let mut run = self.load_run(&conn, branch_id)?;
                if run.state == "paused" && run.used_bytes >= budget.max_total_expanded {
                    break;
                }
                if run.state == "paused" { run.state = "running"; }
                match run.queue.first().copied() {
                    Some(id) => id,
                    None => {
                        run.state = if self.has_blockers(branch_id)? { "blocked" } else { "complete" };
                        self.save_run(&conn, branch_id, &run)?;
                        break;
                    }
                }
            };

            let result = self.resolve_candidate(branch_id, candidate_id, &budget);
            let mut progress = false;
            match result {
                Ok(ResolveOutcome::Ready) => {
                    let mut conn = self.conn.lock().unwrap();
                    let mut run = self.load_run(&conn, branch_id)?;
                    run.queue.retain(|id| *id != candidate_id);
                    run.active_chain.clear();
                    run.state = "running";
                    self.save_run(&conn, branch_id, &run)?;
                    self.enqueue_dependents(&mut conn, branch_id, candidate_id)?;
                    progress = true;
                }
                Ok(ResolveOutcome::NeedsBase(base_id)) => {
                    let mut conn = self.conn.lock().unwrap();
                    let mut run = self.load_run(&conn, branch_id)?;
                    if let Some(position) = run.queue.iter().position(|id| *id == base_id) {
                        let id = run.queue.remove(position);
                        run.queue.insert(0, id);
                    } else if self.is_pending(branch_id, base_id)? {
                        run.queue.insert(0, base_id);
                    }
                    if let Some(position) = run.queue.iter().position(|id| *id == candidate_id) {
                        let id = run.queue.remove(position);
                        run.queue.insert(1, id);
                    }
                    self.save_run(&conn, branch_id, &run)?;
                }
                Ok(ResolveOutcome::Paused(chain)) => {
                    let mut conn = self.conn.lock().unwrap();
                    let mut run = self.load_run(&conn, branch_id)?;
                    run.state = "paused".into();
                    run.active_chain = chain;
                    self.save_run(&conn, branch_id, &run)?;
                    break;
                }
                Err(FailedPermanent { reason, kind, base_id, base_oid, chain }) => {
                    self.fail_candidate(branch_id, candidate_id, kind, base_id, base_oid, reason, chain)?;
                    let mut conn = self.conn.lock().unwrap();
                    let mut run = self.load_run(&conn, branch_id)?;
                    run.queue.retain(|id| *id != candidate_id);
                    run.active_chain.clear();
                    self.save_run(&conn, branch_id, &run)?;
                    progress = true;
                }
            }
            if !progress {
                let conn = self.conn.lock().unwrap();
                let run = self.load_run(&conn, branch_id)?;
                if run.queue.len() <= 1 {
                    drop(conn);
                    self.mark_unresolved_blocked(branch_id)?;
                    break;
                }
            }
        }
        self.mark_unresolved_blocked(branch_id)?;
        self.run_summary(branch_id)
    }

    fn mark_corrupt(&self, branch_id: i64) -> Result<(), String> {
        let corrupt = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT id,error FROM candidates WHERE status='corrupt' AND id NOT IN (SELECT candidate_id FROM resolutions WHERE state='failed')").map_err(|e| e.to_string())?;
            stmt.query_map([], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,Option<String>>(1)?))).map_err(|e| e.to_string())?.flatten().collect::<Vec<_>>()
        };
        for (id, error) in corrupt {
            self.fail_candidate(branch_id, id, "corrupt_object".into(), None, None, error.unwrap_or_else(||"corrupt object".into()), vec![id])?;
        }
        Ok(())
    }

    fn ensure_run(&self, branch_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO branches(id,name,created_at) VALUES(?1,?2,strftime('%s','now')) ON CONFLICT(id) DO NOTHING",
            params![branch_id, if branch_id == 1 {"默认"} else {"分析分支"}],
        ).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO runs(branch_id,run_id,state,used_bytes,queue,active_chain,updated_at) VALUES(?1,0,'running',0,'[]','[]',strftime('%s','now')) ON CONFLICT(branch_id) DO NOTHING",
            params![branch_id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn pending_candidates(&self, branch_id: i64) -> Result<Vec<CandidateRow>, String> {
        let conn = self.conn.lock().unwrap();
        self.query_candidates(&conn, "WHERE c.status!='corrupt' AND c.id NOT IN (SELECT candidate_id FROM resolutions WHERE branch_id=?1 AND state IN ('ready','failed')) ORDER BY COALESCE(c.actual_oid,c.claimed_oid), c.pack_offset, c.source_id, c.id", params![branch_id])
    }

    fn query_candidates(&self, conn: &Connection, where_order: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<CandidateRow>, String> {
        let sql = format!("SELECT c.id,c.source_id,c.kind,c.claimed_oid,c.actual_oid,c.object_type,c.pack_offset,c.payload_offset,c.end_offset,c.header_size,c.inflated_size,c.compressed_size,c.base_claim,c.base_offset,c.integrity,c.status,c.error FROM candidates c {where_order}");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params, |row| Ok(CandidateRow {
            id: row.get(0)?, source_id: row.get(1)?, kind: row.get(2)?, claimed_oid: row.get(3)?, actual_oid: row.get(4)?, object_type: row.get(5)?,
            pack_offset: row.get(6)?, payload_offset: row.get(7)?, end_offset: row.get(8)?, header_size: row.get(9)?, inflated_size: row.get(10)?, compressed_size: row.get(11)?,
            base_claim: row.get(12)?, base_offset: row.get(13)?, integrity: row.get(14)?, status: row.get(15)?, error: row.get(16)?,
        })).map_err(|e| e.to_string())?;
        rows.map(|r| r.map_err(|e| e.to_string())).collect()
    }

    fn load_run(&self, conn: &Connection, branch_id: i64) -> Result<RunState, String> {
        let (state, used, queue_json, chain_json): (String,i64,String,String) = conn.query_row(
            "SELECT state,used_bytes,queue,active_chain FROM runs WHERE branch_id=?1", params![branch_id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|e| e.to_string())?;
        Ok(RunState { state, used_bytes: used as u64, queue: serde_json::from_str(&queue_json).unwrap_or_default(), active_chain: serde_json::from_str(&chain_json).unwrap_or_default() })
    }

    fn save_run(&self, conn: &Connection, branch_id: i64, run: &RunState) -> Result<(), String> {
        conn.execute("UPDATE runs SET state=?1,used_bytes=?2,queue=?3,active_chain=?4,updated_at=strftime('%s','now') WHERE branch_id=?5",
            params![run.state, run.used_bytes as i64, serde_json::to_string(&run.queue).unwrap(), serde_json::to_string(&run.active_chain).unwrap(), branch_id]).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn has_blockers(&self, branch_id: i64) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM blockers WHERE branch_id=?1)", params![branch_id], |r| r.get::<_,i64>(0)).map_err(|e| e.to_string())? != 0)
    }

    fn is_pending(&self, branch_id: i64, id: i64) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM candidates WHERE id=?1 AND status!='corrupt' AND id NOT IN (SELECT candidate_id FROM resolutions WHERE branch_id=?2 AND state IN ('ready','failed')))", params![id,branch_id], |r| r.get::<_,i64>(0)).map_err(|e| e.to_string())? != 0)
    }

    fn enqueue_dependents(&self, conn: &mut Connection, branch_id: i64, ready_id: i64) -> Result<(), String> {
        let mut run = self.load_run(conn, branch_id)?;
        let children: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT candidate_id FROM edges WHERE branch_id=?1 AND base_candidate_id=?2").map_err(|e| e.to_string())?;
            stmt.query_map(params![branch_id, ready_id], |r| r.get::<_,i64>(0)).map_err(|e| e.to_string())?.flatten().collect()
        };
        for child in children {
            conn.execute("DELETE FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id, child]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2", params![branch_id, child]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM blockers WHERE branch_id=?1 AND candidate_id=?2", params![branch_id, child]).map_err(|e| e.to_string())?;
            if !run.queue.contains(&child) { run.queue.push(child); }
        }
        self.save_run(conn, branch_id, &run)
    }

    fn resolve_candidate(&self, branch_id: i64, candidate_id: i64, budget: &Budget) -> Result<ResolveOutcome, FailedPermanent> {
        let candidate = self.get_candidate(candidate_id).map_err(permanent("query_failed"))?;
        if !candidate.object_type.as_deref().is_some_and(|t| t != "delta") {
            let chain = self.build_chain(branch_id, &candidate)?;
            return self.apply_chain(branch_id, candidate_id, chain, budget);
        }
        let raw = self.read_raw(candidate_id).map_err(permanent("raw_read_failed"))?;
        let kind = parse_type(candidate.object_type.as_deref())?;
        let actual = git::object_id(kind, &raw);
        self.verify_claim(&candidate, actual)?;
        self.commit_ready(branch_id, &candidate, kind, raw, 0, Vec::new(), budget)?;
        Ok(ResolveOutcome::Ready)
    }

    fn build_chain(&self, branch_id: i64, target: &CandidateRow) -> Result<Vec<ChainItem>, FailedPermanent> {
        let mut chain = vec![ChainItem { candidate: target.clone(), instruction_start: 0, instruction_end: 0 }];
        let mut seen = HashSet::from([target.id]);
        loop {
            let current = chain.last().unwrap().candidate.clone();
            if current.object_type.as_deref() != Some("delta") { break; }
            let delta = self.read_raw(current.id).map_err(permanent("raw_read_failed"))?;
            let (_, base_header) = git::read_delta_size(&delta).ok_or_else(|| permanent("bad_delta_header")("truncated base size"))?;
            let (_, result_header) = git::read_delta_size(&delta[base_header..]).ok_or_else(|| permanent("bad_delta_header")("truncated result size"))?;
            chain.last_mut().unwrap().instruction_start = base_header + result_header;
            chain.last_mut().unwrap().instruction_end = delta.len();

            let base = self.select_base(branch_id, &current)?;
            self.record_edge(branch_id, current.id, base.id, base.actual_oid.clone().or(base.claimed_oid.clone())).map_err(permanent("edge_failed"))?;
            if !seen.insert(base.id) {
                let mut ids: Vec<i64> = chain.iter().map(|i| i.candidate.id).collect();
                ids.push(base.id);
                return Err(FailedPermanent { kind: "cycle".into(), base_id: Some(base.id), base_oid: base.actual_oid.or(base.claimed_oid), reason: "delta dependency forms a cycle".into(), chain: ids });
            }
            match self.resolution_state(branch_id, base.id)? {
                Some(state) if state == "ready" => {
                    chain.push(ChainItem { candidate: base, instruction_start: 0, instruction_end: 0 });
                    break;
                }
                Some("failed") => return Err(FailedPermanent { kind: "bad_base".into(), base_id: Some(base.id), base_oid: base.actual_oid.or(base.claimed_oid), reason: "selected base candidate failed verification".into(), chain: chain.iter().map(|i| i.candidate.id).collect() }),
                Some("paused") => return Ok(chain),
                _ => return Ok(chain),
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn apply_chain(&self, branch_id: i64, target_id: i64, chain: Vec<ChainItem>, budget: &Budget) -> Result<ResolveOutcome, FailedPermanent> {
        if chain.is_empty() { return Err(permanent("empty_chain")("empty delta chain")); }
        let root = &chain[0].candidate;
        let root_state = self.resolution_state(branch_id, root.id)?;
        if root_state.as_deref() != Some("ready") {
            if root.status == "corrupt" {
                return Err(FailedPermanent { kind: "bad_base".into(), base_id: Some(root.id), base_oid: root.actual_oid.clone().or(root.claimed_oid.clone()), reason: root.error.clone().unwrap_or_else(||"corrupt base".into()), chain: chain.iter().map(|i| i.candidate.id).collect() });
            }
            return Ok(ResolveOutcome::NeedsBase(root.id));
        }

        let mut content = self.read_content(branch_id, root.id).map_err(permanent("content_read_failed"))?;
        let root_type = self.content_type(branch_id, root.id)?.ok_or_else(|| permanent("missing_content_type")("ready root has no object type"))?;
        let total_budget = budget.max_total_expanded;
        let object_cap = ((total_budget as f64 * budget.max_object_ratio).ceil() as u64).max(1024);
        let chain_ids: Vec<i64> = chain.iter().map(|item| item.candidate.id).collect();

        {
            let conn = self.conn.lock().unwrap();
            conn.execute("DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,target_id]).map_err(|e| permanent("step_delete_failed")(e.to_string()))?;
            let used = self.load_run(&conn, branch_id)?.used_bytes;
            let prospective = used.saturating_add(content.len() as u64);
            if prospective > total_budget {
                return Ok(ResolveOutcome::Paused(chain_ids.clone()));
            }
        }

        let mut charged = content.len() as u64;
        let mut steps = Vec::new();
        for (position, item) in chain.iter().enumerate().skip(1) {
            if position > budget.max_delta_depth {
                return Err(FailedPermanent { kind: "depth_limit".into(), base_id: Some(item.candidate.id), base_oid: item.candidate.actual_oid.clone().or(item.candidate.claimed_oid.clone()), reason: format!("delta depth exceeds {}", budget.max_delta_depth), chain: chain_ids.clone() });
            }
            let delta = self.read_raw(item.candidate.id).map_err(permanent("raw_read_failed"))?;
            let (base_declared, base_header) = git::read_delta_size(&delta).ok_or_else(|| permanent("bad_delta_header")("truncated base size"))?;
            let (result_declared, result_header) = git::read_delta_size(&delta[base_header..]).ok_or_else(|| permanent("bad_delta_header")("truncated result size"))?;
            let result_header = base_header + result_header;
            if base_declared as usize != content.len() {
                return Err(FailedPermanent { kind: "size_spoof".into(), base_id: Some(item.candidate.id), base_oid: item.candidate.actual_oid.clone().or(item.candidate.claimed_oid.clone()), reason: format!("delta base size declares {base_declared}, actual {}", content.len()), chain: chain_ids.clone() });
            }
            if result_declared > object_cap {
                return Err(FailedPermanent { kind: "object_ratio".into(), base_id: Some(item.candidate.id), base_oid: item.candidate.actual_oid.clone().or(item.candidate.claimed_oid.clone()), reason: format!("declared object {result_declared} exceeds single-object cap {object_cap}"), chain: chain_ids.clone() });
            }
            if charged.saturating_add(result_declared) > total_budget {
                return Ok(ResolveOutcome::Paused(chain_ids.clone()));
            }
            let remaining_cap = total_budget.saturating_sub(charged);
            let (next, ranges) = git::delta::parse_delta(&delta, &content, remaining_cap, None).map_err(|e| FailedPermanent {
                kind: if format!("{e}").contains("budget") { "budget" } else { "bad_delta" }.into(),
                base_id: Some(item.candidate.id),
                base_oid: item.candidate.actual_oid.clone().or(item.candidate.claimed_oid.clone()),
                reason: e.to_string(),
                chain: chain_ids.clone(),
            })?;
            charged = charged.saturating_add(next.len() as u64);
            if charged > total_budget { return Ok(ResolveOutcome::Paused(chain_ids.clone())); }
            steps.push((position, item.candidate.clone(), result_header, delta.len(), content.len(), next.len(), ranges));
            content = next;
        }

        let actual = git::object_id(root_type, &content);
        let target = chain.last().unwrap().candidate.clone();
        self.verify_claim(&target, actual)?;
        let mut previous_base: Option<i64> = Some(root.id);
        for (position, candidate, instruction_start, input_len, base_size, output_len, ranges) in &steps {
            let base_oid = self.candidate_oid(previous_base.unwrap()).unwrap_or_default();
            let details = serde_json::to_value(ranges.iter().map(|r| serde_json::json!({"start":r.start,"end":r.end,"kind":r.kind})).collect::<Vec<_>>()).unwrap();
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO delta_steps(branch_id,candidate_id,position,base_candidate_id,base_oid,instruction_start,instruction_end,base_size,input_len,output_len,check_ok,details) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11)",
                params![branch_id,target_id,*position as i64,previous_base,base_oid,*instruction_start as i64,*input_len as i64,*base_size as i64,*input_len as i64,*output_len as i64,details],
            ).map_err(|e| permanent("step_insert_failed")(e.to_string()))?;
            previous_base = Some(candidate.id);
        }
        self.commit_ready(branch_id, &target, root_type, content, chain.len() - 1, steps.iter().map(|s| s.1.id).collect(), budget)?;
        Ok(ResolveOutcome::Ready)
    }

    fn select_base(&self, branch_id: i64, delta: &CandidateRow) -> Result<CandidateRow, FailedPermanent> {
        if delta.object_type.as_deref() == Some("ofs-delta-name") {}
        if delta.object_type.as_deref() == Some("delta") && delta.kind == "pack" && delta.base_offset.is_some() {
            if let Some(base) = self.get_by_offset(delta.source_id, delta.base_offset.unwrap())? {
                if base.status != "corrupt" { return Ok(base); }
            }
            return Err(FailedPermanent { kind: "missing_ofs_base".into(), base_id: None, base_oid: None, reason: format!("ofs-delta base offset {} is absent or corrupt", delta.base_offset.unwrap()), chain: vec![delta.id] });
        }
        let oid_text = delta.base_claim.clone().ok_or_else(|| FailedPermanent { kind: "missing_ref_base".into(), base_id: None, base_oid: None, reason: "ref-delta has no base oid".into(), chain: vec![delta.id] })?;
        let oid = ObjectId::from_hex(&oid_text).ok_or_else(|| permanent("bad_ref_oid")("invalid base oid"))?;
        if let Some(pinned) = self.pinned_candidate(branch_id, &oid)? {
            return Ok(pinned);
        }
        let candidates = self.candidates_for_oid(&oid)?;
        let mut usable: Vec<CandidateRow> = candidates.into_iter().filter(|c| c.status != "corrupt").collect();
        if usable.is_empty() {
            return Err(FailedPermanent { kind: "missing_ref_base".into(), base_id: None, base_oid: Some(oid_text), reason: "external base object is not imported".into(), chain: vec![delta.id] });
        }
        usable.sort_by(|a,b| self.candidate_rank(a).cmp(&self.candidate_rank(b)).then_with(|| a.source_id.cmp(&b.source_id)).then_with(|| a.id.cmp(&b.id)));
        Ok(usable.remove(0))
    }

    fn candidate_rank(&self, candidate: &CandidateRow) -> u8 {
        let ready = self.resolution_state(1, candidate.id).ok().flatten().as_deref() == Some("ready");
        let kind_score = if candidate.kind == "loose" { 0 } else { 1 };
        let status_score = if ready { 0 } else if candidate.status == "discovered" { 1 } else { 2 };
        let integrity_score = if candidate.integrity == "verified" { 0 } else { 1 };
        (kind_score * 16 + status_score * 4 + integrity_score) as u8
    }

    fn pinned_candidate(&self, branch_id: i64, oid: &ObjectId) -> Result<Option<CandidateRow>, String> {
        let conn = self.conn.lock().unwrap();
        let id = conn.query_row("SELECT candidate_id FROM pins WHERE branch_id=?1 AND oid=?2", params![branch_id,oid.hex()], |r| r.get::<_,i64>(0)).optional().map_err(|e| e.to_string())?;
        if let Some(id) = id { Ok(Some(self.get_candidate(id)?)) } else { Ok(None) }
    }

    fn candidates_for_oid(&self, oid: &ObjectId) -> Result<Vec<CandidateRow>, String> {
        let hex = oid.hex();
        let conn = self.conn.lock().unwrap();
        self.query_candidates(&conn, "WHERE c.claimed_oid=?1 OR c.actual_oid=?1 ORDER BY c.kind DESC,c.source_id,c.id", params![hex])
    }

    fn get_by_offset(&self, source_id: i64, offset: i64) -> Result<Option<CandidateRow>, String> {
        let conn = self.conn.lock().unwrap();
        let rows = self.query_candidates(&conn, "WHERE c.source_id=?1 AND c.pack_offset=?2", params![source_id,offset])?;
        Ok(rows.into_iter().next())
    }

    fn get_candidate(&self, id: i64) -> Result<CandidateRow, String> {
        let conn = self.conn.lock().unwrap();
        self.query_candidates(&conn, "WHERE c.id=?1", params![id])?.into_iter().next().ok_or_else(|| format!("candidate {id} not found"))
    }

    fn candidate_oid(&self, id: i64) -> Result<Option<String>, String> {
        let c = self.get_candidate(id)?;
        Ok(c.actual_oid.or(c.claimed_oid))
    }

    fn resolution_state(&self, branch_id: i64, candidate_id: i64) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT state FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate_id], |r| r.get::<_,String>(0)).optional().map_err(|e| e.to_string())
    }

    fn content_type(&self, branch_id: i64, candidate_id: i64) -> Result<Option<ObjectType>, String> {
        let conn = self.conn.lock().unwrap();
        let value: Option<String> = conn.query_row("SELECT object_type FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate_id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        Ok(value.and_then(|v| parse_type(Some(&v)).ok()))
    }

    fn verify_claim(&self, candidate: &CandidateRow, actual: ObjectId) -> Result<(), FailedPermanent> {
        if let Some(claimed) = candidate.claimed_oid.as_ref() {
            if claimed != &actual.hex() {
                return Err(FailedPermanent { kind: "oid_mismatch".into(), base_id: Some(candidate.id), base_oid: Some(actual.hex()), reason: format!("recomputed object id {actual} does not match claimed {claimed}"), chain: vec![candidate.id] });
            }
        }
        Ok(())
    }

    fn commit_ready(
        &self,
        branch_id: i64,
        candidate: &CandidateRow,
        kind: ObjectType,
        data: Vec<u8>,
        delta_depth: usize,
        _step_ids: Vec<i64>,
        budget: &Budget,
    ) -> Result<(), FailedPermanent> {
        let actual = git::object_id(kind, &data);
        let path = self.content_path(branch_id, candidate.id);
        fs::create_dir_all(path.parent().unwrap()).map_err(|e| permanent("content_write_failed")(e.to_string()))?;
        fs::write(&path, &data).map_err(|e| permanent("content_write_failed")(e.to_string()))?;
        let charged = self.charged_for(candidate.id, data.len() as u64, delta_depth);
        let mut conn = self.conn.lock().unwrap();
        let used = self.load_run(&conn, branch_id).map_err(permanent("run_failed"))?.used_bytes;
        if used.saturating_add(charged) > budget.max_total_expanded {
            return Err(FailedPermanent { kind: "budget".into(), base_id: Some(candidate.id), base_oid: Some(actual.hex()), reason: format!("budget requires {} but {} remains", charged, budget.max_total_expanded.saturating_sub(used)), chain: vec![candidate.id] });
        }
        let tx_used = used + charged;
        conn.execute(
            "INSERT INTO resolutions(branch_id,candidate_id,run_id,state,actual_oid,object_type,content_path,output_size,delta_depth,charged_bytes,error)
             VALUES(?1,?2,0,'ready',?3,?4,?5,?6,?7,?8,NULL)
             ON CONFLICT(branch_id,candidate_id) DO UPDATE SET run_id=0,state='ready',actual_oid=excluded.actual_oid,object_type=excluded.object_type,content_path=excluded.content_path,output_size=excluded.output_size,delta_depth=excluded.delta_depth,charged_bytes=excluded.charged_bytes,error=NULL",
            params![branch_id,candidate.id,actual.hex(),kind.git_name(),path.to_string_lossy(),data.len() as i64,delta_depth as i64,charged as i64],
        ).map_err(|e| permanent("resolution_insert_failed")(e.to_string()))?;
        conn.execute("UPDATE candidates SET actual_oid=COALESCE(actual_oid,?1), status='ready' WHERE id=?2", params![actual.hex(),candidate.id]).map_err(|e| permanent("candidate_update_failed")(e.to_string()))?;
        conn.execute("DELETE FROM blockers WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate.id]).map_err(|e| permanent("blocker_delete_failed")(e.to_string()))?;
        let mut run = self.load_run(&conn, branch_id).map_err(permanent("run_failed"))?;
        run.used_bytes = tx_used;
        if run.used_bytes >= budget.max_total_expanded { run.state = "paused".into(); }
        self.save_run(&conn, branch_id, &run).map_err(permanent("run_failed"))?;
        Ok(())
    }

    fn charged_for(&self, candidate_id: i64, final_len: u64, depth: usize) -> u64 {
        if depth == 0 {
            self.read_raw_len(candidate_id).unwrap_or(final_len).max(final_len)
        } else {
            final_len
        }
    }

    fn fail_candidate(&self, branch_id: i64, candidate_id: i64, kind: String, base_id: Option<i64>, base_oid: Option<String>, reason: String, chain: Vec<i64>) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO resolutions(branch_id,candidate_id,run_id,state,error) VALUES(?1,?2,0,'failed',?3)
             ON CONFLICT(branch_id,candidate_id) DO UPDATE SET state='failed',error=excluded.error,content_path=NULL,output_size=NULL",
            params![branch_id,candidate_id,reason],
        )?;
        conn.execute("UPDATE candidates SET status='failed' WHERE id=?1 AND status!='corrupt'", params![candidate_id])?;
        conn.execute("DELETE FROM blockers WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate_id])?;
        conn.execute("INSERT INTO blockers(branch_id,candidate_id,kind,base_candidate_id,base_oid,reason,chain) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![branch_id,candidate_id,kind,base_id,base_oid,reason,serde_json::to_string(&chain).unwrap()])?;
        if let Some(path) = conn.query_row::<Option<String>,_,_>("SELECT content_path FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate_id], |r| r.get(0)).optional()? {
            if let Some(path) = path { let _ = fs::remove_file(path); }
        }
        Ok(())
    }

    fn mark_unresolved_blocked(&self, branch_id: i64) -> Result<(), String> {
        let pending = self.pending_candidates(branch_id)?;
        let mut conn = self.conn.lock().unwrap();
        for candidate in pending {
            let base = if candidate.object_type.as_deref() == Some("delta") {
                if candidate.base_offset.is_some() && candidate.kind == "pack" {
                    let row = self.get_by_offset_locked(&conn, candidate.source_id, candidate.base_offset.unwrap())?;
                    row.map(|c| (c.id, c.actual_oid.or(c.claimed_oid), "missing_ofs_base".to_string(), format!("base offset {} is not ready", candidate.base_offset.unwrap())))
                } else if let Some(oid) = candidate.base_claim.clone() {
                    let selected = self.select_base_locked(&conn, branch_id, &oid)?;
                    selected.map(|c| (c.id, Some(oid), "blocked_base".into(), "base exists but is not ready".into()))
                } else { None }
            } else { None };
            if let Some((base_id, base_oid, kind, reason)) = base {
                let chain = self.blocking_chain_locked(&conn, branch_id, candidate.id, base_id)?;
                conn.execute("DELETE FROM blockers WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,candidate.id])?;
                conn.execute("INSERT INTO blockers(branch_id,candidate_id,kind,base_candidate_id,base_oid,reason,chain) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![branch_id,candidate.id,kind,base_id,base_oid,reason,serde_json::to_string(&chain).unwrap()])?;
            }
        }
        let unresolved: i64 = conn.query_row("SELECT COUNT(*) FROM candidates WHERE status!='corrupt' AND id NOT IN (SELECT candidate_id FROM resolutions WHERE branch_id=?1 AND state IN ('ready','failed'))", params![branch_id], |r| r.get(0))?;
        let mut run = self.load_run(&conn, branch_id)?;
        if unresolved == 0 { run.state = if conn.query_row("SELECT COUNT(*) FROM blockers WHERE branch_id=?1", params![branch_id], |r| r.get::<_,i64>(0)).unwrap_or(0) > 0 { "blocked" } else { "complete" }.to_string(); }
        else if run.state != "paused" { run.state = if run.queue.is_empty() { "blocked" } else { "running" }.to_string(); }
        self.save_run(&conn, branch_id, &run)?;
        Ok(())
    }

    fn get_by_offset_locked(&self, conn: &Connection, source_id: i64, offset: i64) -> Result<Option<CandidateRow>, String> {
        Ok(self.query_candidates(conn, "WHERE c.source_id=?1 AND c.pack_offset=?2", params![source_id,offset])?.into_iter().next())
    }

    fn select_base_locked(&self, conn: &Connection, branch_id: i64, oid_hex: &str) -> Result<Option<CandidateRow>, String> {
        if let Some(id) = conn.query_row("SELECT candidate_id FROM pins WHERE branch_id=?1 AND oid=?2", params![branch_id,oid_hex], |r| r.get::<_,i64>(0)).optional()? {
            return Ok(self.query_candidates(conn, "WHERE c.id=?1", params![id])?.into_iter().next());
        }
        let mut rows = self.query_candidates(conn, "WHERE c.claimed_oid=?1 OR c.actual_oid=?1 ORDER BY c.kind DESC,c.source_id,c.id", params![oid_hex])?;
        rows.retain(|c| c.status != "corrupt");
        Ok(rows.into_iter().next())
    }

    fn blocking_chain_locked(&self, conn: &Connection, branch_id: i64, start: i64, first_base: i64) -> Result<Vec<i64>, String> {
        let mut chain = vec![start];
        let mut current = first_base;
        for _ in 0..128 {
            if chain.contains(&current) { chain.push(current); break; }
            chain.push(current);
            let state = conn.query_row::<String,_,_>("SELECT state FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,current], |r| r.get(0)).optional()?;
            if state.as_deref() == Some("ready") { break; }
            let next = conn.query_row::<i64,_,_>("SELECT base_candidate_id FROM edges WHERE branch_id=?1 AND candidate_id=?2 ORDER BY id LIMIT 1", params![branch_id,current], |r| r.get(0)).optional()?;
            match next { Some(next) => current = next, None => break }
        }
        Ok(chain)
    }

    fn record_edge(&self, branch_id: i64, candidate_id: i64, base_id: i64, base_oid: Option<String>) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT OR IGNORE INTO edges(branch_id,candidate_id,base_candidate_id,base_oid) VALUES(?1,?2,?3,?4)", params![branch_id,candidate_id,base_id,base_oid])?;
        Ok(())
    }

    pub fn invalidate_for_imported_source(&self, source_id: i64) -> Result<(), String> {
        let ids: Vec<i64> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT id FROM candidates WHERE source_id=?1")?;
            stmt.query_map(params![source_id], |r| r.get::<_,i64>(0))?.flatten().collect()
        };
        for id in ids { self.invalidate_dependents(1, id)?; }
        Ok(())
    }

    fn invalidate_dependents(&self, branch_id: i64, seed: i64) -> Result<(), String> {
        let mut affected = HashSet::from([seed]);
        let mut frontier = vec![seed];
        while let Some(id) = frontier.pop() {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT candidate_id FROM edges WHERE branch_id=?1 AND base_candidate_id=?2")?;
            let children: Vec<i64> = stmt.query_map(params![branch_id,id], |r| r.get::<_,i64>(0))?.flatten().collect();
            for child in children { if affected.insert(child) { frontier.push(child); } }
        }
        let mut conn = self.conn.lock().unwrap();
        for id in affected {
            conn.execute("DELETE FROM resolutions WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,id])?;
            conn.execute("DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,id])?;
            conn.execute("DELETE FROM blockers WHERE branch_id=?1 AND candidate_id=?2", params![branch_id,id])?;
            conn.execute("UPDATE candidates SET status='discovered', error=NULL WHERE id=?1 AND status NOT IN ('corrupt')", params![id])?;
            let _ = fs::remove_file(self.content_path(branch_id, id));
        }
        let mut run = self.load_run(&conn, branch_id)?;
        run.state = "running".into();
        run.used_bytes = 0;
        run.queue.clear();
        self.save_run(&conn, branch_id, &run)?;
        Ok(())
    }

    pub fn pin_candidate(&self, branch_id: i64, candidate_id: i64, budget: Budget) -> Result<RunSummary, String> {
        self.ensure_run(branch_id)?;
        let candidate = self.get_candidate(candidate_id)?;
        let oid = candidate.actual_oid.clone().or(candidate.claimed_oid).ok_or("candidate has no oid")?;
        {
            let conn = self.conn.lock().unwrap();
            conn.execute("INSERT OR REPLACE INTO pins(branch_id,oid,candidate_id) VALUES(?1,?2,?3)", params![branch_id,oid,candidate_id])?;
        }
        self.invalidate_dependents(branch_id, candidate_id)?;
        self.resolve(branch_id, budget)
    }

    pub fn unpin_oid(&self, branch_id: i64, oid: &str, budget: Budget) -> Result<RunSummary, String> {
        {
            let conn = self.conn.lock().unwrap();
            conn.execute("DELETE FROM pins WHERE branch_id=?1 AND oid=?2", params![branch_id,oid])?;
        }
        self.invalidate_dependents(branch_id, -1)?;
        self.resolve(branch_id, budget)
    }

    fn raw_path(&self, candidate_id: i64) -> PathBuf { self.data_dir.join("objects/raw").join(format!("{candidate_id}.bin")) }
    fn content_path(&self, branch_id: i64, candidate_id: i64) -> PathBuf { self.data_dir.join("objects").join(branch_id.to_string()).join(format!("{candidate_id}.bin")) }

    fn read_raw(&self, candidate_id: i64) -> Result<Vec<u8>, String> { fs::read(self.raw_path(candidate_id)).map_err(|e| e.to_string()) }
    fn read_raw_len(&self, candidate_id: i64) -> Result<u64, String> { Ok(fs::metadata(self.raw_path(candidate_id)).map_err(|e| e.to_string())?.len()) }
    fn read_content(&self, branch_id: i64, candidate_id: i64) -> Result<Vec<u8>, String> { fs::read(self.content_path(branch_id, candidate_id)).map_err(|e| e.to_string()) }

    pub fn source_dependents(&self, source_id: i64) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT DISTINCT COALESCE(r.actual_oid,c.claimed_oid,c.object_type||'@'||COALESCE(CAST(c.pack_offset AS TEXT),'loose')) FROM candidates c LEFT JOIN resolutions r ON r.branch_id=1 AND r.candidate_id=c.id WHERE c.source_id=?1")?;
        let ids: Vec<String> = stmt.query_map(params![source_id], |r| r.get::<_,String>(0))?.flatten().collect();
        Ok(ids)
    }

    pub fn delete_source(&self, source_id: i64, force: bool) -> Result<DeleteResult, String> {
        let dependents = self.source_dependents(source_id)?;
        if !force && !dependents.is_empty() {
            return Ok(DeleteResult { deleted: false, dependents });
        }
        let candidate_ids: Vec<i64> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT id FROM candidates WHERE source_id=?1")?;
            stmt.query_map(params![source_id], |r| r.get::<_,i64>(0))?.flatten().collect()
        };
        for branch in 1..=1 {
            for id in &candidate_ids { self.invalidate_dependents(branch, *id)?; }
        }
        let mut conn = self.conn.lock().unwrap();
        let path: Option<String> = conn.query_row("SELECT path FROM sources WHERE id=?1", params![source_id], |r| r.get(0)).optional()?;
        for id in &candidate_ids {
            conn.execute("DELETE FROM pins WHERE candidate_id=?1", params![id])?;
            conn.execute("DELETE FROM edges WHERE candidate_id=?1 OR base_candidate_id=?1", params![id,id])?;
            conn.execute("DELETE FROM resolutions WHERE candidate_id=?1", params![id])?;
            conn.execute("DELETE FROM delta_steps WHERE candidate_id=?1 OR base_candidate_id=?1", params![id,id])?;
            conn.execute("DELETE FROM blockers WHERE candidate_id=?1 OR base_candidate_id=?1", params![id,id])?;
            conn.execute("DELETE FROM candidates WHERE id=?1", params![id])?;
            let _ = fs::remove_file(self.raw_path(*id));
            for branch in 1..=1 { let _ = fs::remove_file(self.content_path(branch, *id)); }
        }
        conn.execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
        drop(conn);
        if let Some(path) = path { let _ = fs::remove_file(path); }
        self.resolve(1, Budget::default())?;
        Ok(DeleteResult { deleted: true, dependents: Vec::new() })
    }

    pub fn dashboard(&self) -> Result<Dashboard, String> {
        let conn = self.conn.lock().unwrap();
        let mut sources = Vec::new();
        let mut stmt = conn.prepare("SELECT id,kind,original_name,path,sha256,size,summary,errors FROM sources ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?)))?;
        for (id,kind,original_name,path,sha256,size,summary,errors) in rows.flatten() {
            sources.push(SourceView {
                id,kind,original_name,path,sha256,size,
                summary: serde_json::from_str(&summary).unwrap_or(serde_json::json!({})),
                errors: serde_json::from_str(&errors).unwrap_or(serde_json::json!([])),
                dependent_objects: self.source_dependents(id).unwrap_or_default(),
            });
        }
        let candidates = self.query_candidates(&conn, "ORDER BY COALESCE(c.actual_oid,c.claimed_oid), c.kind, c.pack_offset, c.source_id,c.id", &[])?;
        let run = self.run_summary_locked(&conn, 1)?;
        drop(conn);
        let candidates = candidates.into_iter().map(|c| self.candidate_view(1,c)).collect::<Result<Vec<_>,_>>()?;
        Ok(Dashboard { sources, candidates, run, budget: Budget::default() })
    }

    fn candidate_view(&self, branch_id: i64, c: CandidateRow) -> Result<CandidateView, String> {
        let conn = self.conn.lock().unwrap();
        let resolution = conn.query_row(
            "SELECT state,actual_oid,object_type,output_size,delta_depth,charged_bytes,error,content_path FROM resolutions WHERE branch_id=?1 AND candidate_id=?2",
            params![branch_id,c.id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<i64>>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<String>>(7)?))
        ).optional()?;
        let resolution = resolution.map(|(state,actual_oid,object_type,output_size,delta_depth,charged_bytes,error,path)| {
            let preview = path.as_ref().and_then(|p| fs::read(p).ok()).map(|bytes| preview_bytes(&bytes));
            ResolutionView { state, actual_oid, object_type, output_size, delta_depth, charged_bytes, error, preview }
        });
        let mut stmt = conn.prepare("SELECT kind,base_candidate_id,base_oid,reason,chain FROM blockers WHERE branch_id=?1 AND candidate_id=?2 ORDER BY id")?;
        let blockers = stmt.query_map(params![branch_id,c.id], |r| Ok(BlockerView {
            kind:r.get(0)?, base_candidate_id:r.get(1)?, base_oid:r.get(2)?, reason:r.get(3)?, chain: serde_json::from_str(&r.get::<_,String>(4)?).unwrap_or_default()
        }))?.flatten().collect();
        let mut stmt = conn.prepare("SELECT position,base_candidate_id,base_oid,instruction_start,instruction_end,base_size,input_len,output_len,check_ok,details FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2 ORDER BY position")?;
        let steps = stmt.query_map(params![branch_id,c.id], |r| Ok(StepView {
            position:r.get(0)?, base_candidate_id:r.get(1)?, base_oid:r.get(2)?, instruction_start:r.get(3)?, instruction_end:r.get(4)?, base_size:r.get(5)?, input_len:r.get(6)?, output_len:r.get(7)?, check_ok:r.get::<_,i64>(8)? != 0, details: serde_json::from_str(&r.get::<_,String>(9)?).unwrap_or(serde_json::json!({}))
        }))?.flatten().collect();
        let evidence = conn.query_row("SELECT evidence FROM candidates WHERE id=?1", params![c.id], |r| r.get::<_,String>(0)).unwrap_or_else(|_| "{}".into());
        Ok(CandidateView {
            id:c.id,source_id:c.source_id,kind:c.kind,claimed_oid:c.claimed_oid,actual_oid:c.actual_oid,object_type:c.object_type,
            pack_offset:c.pack_offset,payload_offset:c.payload_offset,end_offset:c.end_offset,inflated_size:c.inflated_size,compressed_size:c.compressed_size,
            base_claim:c.base_claim,base_offset:c.base_offset,integrity:c.integrity,status:c.status,error:c.error,
            evidence: serde_json::from_str(&evidence).unwrap_or(serde_json::json!({})), resolution, blockers, steps,
        })
    }

    pub fn run_summary(&self, branch_id: i64) -> Result<RunSummary, String> {
        let conn = self.conn.lock().unwrap();
        self.run_summary_locked(&conn, branch_id)
    }

    fn run_summary_locked(&self, conn: &Connection, branch_id: i64) -> Result<RunSummary, String> {
        let run = self.load_run(conn, branch_id)?;
        Ok(RunSummary { branch_id, state: run.state, used_bytes: run.used_bytes, queue_len: run.queue.len(), active_chain: run.active_chain })
    }
}

#[derive(Serialize)]
pub struct DeleteResult { pub deleted: bool, pub dependents: Vec<String> }

enum ResolveOutcome { Ready, NeedsBase(i64), Paused(Vec<i64>) }
struct FailedPermanent { kind: String, base_id: Option<i64>, base_oid: Option<String>, reason: String, chain: Vec<i64> }

fn permanent(kind: &str) -> impl Fn(String) -> FailedPermanent + '_ {
    move |reason: String| FailedPermanent { kind: kind.to_string(), base_id: None, base_oid: None, reason, chain: Vec::new() }
}

fn parse_type(value: Option<&str>) -> Result<ObjectType, FailedPermanent> {
    match value {
        Some("commit") => Ok(ObjectType::Commit),
        Some("tree") => Ok(ObjectType::Tree),
        Some("blob") => Ok(ObjectType::Blob),
        Some("tag") => Ok(ObjectType::Tag),
        other => Err(FailedPermanent { kind: "unknown_object_type".into(), base_id: None, base_oid: None, reason: format!("unknown object type {other:?}"), chain: Vec::new() }),
    }
}

fn detect_kind(name: &str, bytes: &[u8]) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pack") || bytes.starts_with(b"PACK") { "pack".into() }
    else if lower.ends_with(".idx") || bytes.starts_with(b"\xfftOc") { "idx".into() }
    else { "loose".into() }
}

fn sanitize_name(name: &str) -> String {
    name.replace(['/', '\\', '\0'], "_").chars().take(80).collect()
}

fn preview_bytes(bytes: &[u8]) -> String {
    let limit = bytes.iter().take(512).copied().collect::<Vec<u8>>();
    match std::str::from_utf8(&limit) {
        Ok(text) if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') => text.to_string(),
        _ => format!("{} bytes; hex={}", bytes.len(), hex::encode(&bytes[..bytes.len().min(64)])),
    }
}
