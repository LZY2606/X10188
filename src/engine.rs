use crate::db::Database;
use crate::git::{
    apply_delta, entry_crc32, git_object_id, oid_hex, parse_idx, parse_loose_object, parse_pack,
    GitType,
};
use rusqlite::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub total_bytes: usize,
    pub single_ratio_percent: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget { max_depth: 16, total_bytes: 64 * 1024 * 1024, single_ratio_percent: 80 }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolveState {
    Resolved,
    MissingBase,
    Cycle,
    Invalid,
    Paused,
    Conflict,
}

#[derive(Debug, Clone)]
pub struct StepRecord {
    pub base_raw_id: Option<i64>,
    pub base_oid: Option<String>,
    pub op_start: Option<i64>,
    pub op_end: Option<i64>,
    pub op_kind: Option<String>,
    pub input_len: i64,
    pub output_len: i64,
    pub check_kind: String,
    pub check_ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ResolveOutcome {
    pub state: ResolveState,
    pub oid: Option<[u8; 20]>,
    pub kind: Option<GitType>,
    pub content: Vec<u8>,
    pub depth: usize,
    pub expanded_bytes: usize,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub blocked_chain: Vec<i64>,
    pub steps: Vec<StepRecord>,
}

#[derive(Debug, Clone)]
struct RawRecord {
    id: i64,
    source_id: i64,
    source_kind: String,
    source_name: String,
    source_sha: String,
    origin_rank: i64,
    offset: Option<i64>,
    type_name: String,
    declared_size: i64,
    inflated_size: i64,
    content: Vec<u8>,
    content_sha: String,
    parse_error: Option<String>,
    crc32: Option<i64>,
    base_ref_oid: Option<String>,
    base_offset: Option<i64>,
}

#[derive(Debug, Clone)]
struct CandidateRecord {
    oid: String,
    raw_id: i64,
    source_id: i64,
    origin_rank: i64,
    valid: bool,
    source_name: String,
    source_sha: String,
    content_sha: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewObject {
    pub raw_id: i64,
    pub source: String,
    pub offset: Option<i64>,
    pub declared_type: String,
    pub declared_size: i64,
    pub inflated_size: i64,
    pub state: String,
    pub oid: Option<String>,
    pub resolved_type: Option<String>,
    pub preview: String,
    pub error: Option<String>,
    pub blocked_chain: Vec<String>,
    pub depth: i64,
    pub expanded_bytes: i64,
}

pub struct AnalysisReport {
    pub states: HashMap<i64, ResolveOutcome>,
    pub used_bytes: usize,
    pub paused: bool,
    pub raws: HashMap<i64, RawRecord>,
    pub edges: HashMap<i64, (String, Option<String>, Option<i64>, Option<i64>)>,
}

pub struct Analyzer {
    pub root: PathBuf,
    pub db: Database,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn git_type(name: &str) -> Option<GitType> {
    match name {
        "commit" => Some(GitType::Commit),
        "tree" => Some(GitType::Tree),
        "blob" => Some(GitType::Blob),
        "tag" => Some(GitType::Tag),
        "ofs-delta" => Some(GitType::OfsDelta),
        "ref-delta" => Some(GitType::RefDelta),
        _ => None,
    }
}

impl Analyzer {
    pub fn open(root: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("uploads")).ok();
        Ok(Analyzer { db: Database::open(&root)?, root })
    }

    pub fn import(&self, filename: &str, bytes: Vec<u8>) -> Result<i64, String> {
        let stem = filename.rsplit('/').last().unwrap_or(filename);
        let unique = format!("{}-{}", &sha256_hex(&bytes)[..16], stem.replace(['/', '\\'], "_"));
        let path = self.root.join("uploads").join(unique);
        std::fs::write(&path, &bytes).map_err(|err| err.to_string())?;
        self.import_path(filename, path)
    }

    pub fn import_path(&self, original: &str, path: PathBuf) -> Result<i64, String> {
        if let Some(existing) = self.db.source_by_path(&path).map_err(|e| e.to_string())? {
            return Ok(existing.id);
        }
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let hash = sha256_hex(&bytes);
        let kind = classify(original, &bytes);
        match kind {
            "pack" => self.import_pack(original, &path, &hash, &bytes),
            "idx" => self.import_idx(original, &path, &hash, &bytes),
            _ => self.import_loose(original, &path, &hash, &bytes),
        }
    }

    fn import_pack(&self, original: &str, path: &Path, hash: &str, bytes: &[u8]) -> Result<i64, String> {
        let pack = parse_pack(bytes).map_err(|e| e.to_string())?;
        let checksum_ok = pack.checksum == pack.stored_checksum;
        let status = if checksum_ok { "parsed" } else { "checksum-mismatch" };
        let error = (!checksum_ok).then(|| "pack SHA-1 trailer mismatch".to_string());
        let tx = self.db.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let source_id = {
            tx.execute(
                "INSERT INTO sources(kind, original_name, stored_path, sha256, parse_status, parse_error, imported_at)
                 VALUES ('pack',?1,?2,?3,?4,?5,strftime('%s','now'))",
                params![original, path.to_string_lossy(), hash, status, error],
            ).map_err(|e| e.to_string())?;
            tx.last_insert_rowid()
        };
        let offset_to_raw: HashMap<i64, i64> = HashMap::new();
        let mut mapping = HashMap::new();
        for entry in &pack.entries {
            let parse_error = if entry.expected_size != entry.payload.data.len() {
                Some(format!("declared size {} but inflated size {}", entry.expected_size, entry.payload.data.len()))
            } else {
                pack.entry_errors.iter().find(|(offset, _)| *offset == entry.offset).map(|(_, error)| error.clone())
            };
            let row_id = insert_raw(
                &tx,
                source_id,
                "pack",
                Some(entry.offset as i64),
                entry.object_type.name(),
                entry.expected_size as i64,
                entry.payload.data.len() as i64,
                (entry.entry_end - entry.offset) as i64,
                &entry.payload.data,
                Some((entry.offset as usize + entry.header_len) as i64),
                Some(entry.entry_end as i64),
                entry.base_oid.map(|oid| oid_hex(&oid)),
                entry.negative_offset.map(|distance| entry.offset as i64 - distance as i64),
                parse_error,
                Some(entry_crc32(bytes, entry) as i64),
            )
            .map_err(|e| e.to_string())?;
            mapping.insert(entry.offset, row_id);
        }
        let _ = offset_to_raw;
        for entry in &pack.entries {
            let child = mapping[&entry.offset];
            if entry.object_type == GitType::OfsDelta {
                let target = entry.offset as i64 - entry.negative_offset.unwrap_or(0) as i64;
                let base_raw = mapping.get(&(target as u64)).copied();
                tx.execute(
                    "INSERT OR REPLACE INTO edges(child_raw_id,ref_kind,base_oid,base_offset,base_raw_id)
                     VALUES (?1,'ofs',NULL,?2,?3)",
                    params![child, target, base_raw],
                ).map_err(|e| e.to_string())?;
            } else if entry.object_type == GitType::RefDelta {
                tx.execute(
                    "INSERT OR REPLACE INTO edges(child_raw_id,ref_kind,base_oid,base_offset,base_raw_id)
                     VALUES (?1,'ref',?2,NULL,NULL)",
                    params![child, entry.base_oid.map(|oid| oid_hex(&oid))],
                ).map_err(|e| e.to_string())?;
            }
        }
        tx.execute(
            "UPDATE sources SET paired_source_id=NULL WHERE id=?1",
            params![source_id],
        ).ok();
        tx.commit().map_err(|e| e.to_string())?;
        self.try_pair_idx(source_id, pack.checksum)?;
        self.refresh_candidates()?;
        Ok(source_id)
    }

    fn import_idx(&self, original: &str, path: &Path, hash: &str, bytes: &[u8]) -> Result<i64, String> {
        match parse_idx(bytes) {
            Ok(idx) => {
                let source_id = self.db.insert_source("idx", original, path, hash, "parsed", None).map_err(|e| e.to_string())?;
                self.try_pair_pack(source_id, idx.pack_checksum)?;
                self.refresh_candidates()?;
                Ok(source_id)
            }
            Err(err) => {
                let source_id = self.db.insert_source("idx", original, path, hash, "invalid", Some(&err.to_string())).map_err(|e| e.to_string())?;
                Ok(source_id)
            }
        }
    }

    fn import_loose(&self, original: &str, path: &Path, hash: &str, bytes: &[u8]) -> Result<i64, String> {
        match parse_loose_object(bytes) {
            Ok((kind, content, input_len)) => {
                let source_id = self.db.insert_source("loose", original, path, hash, "parsed", None).map_err(|e| e.to_string())?;
                let tx = self.db.conn.unchecked_transaction().map_err(|e| e.to_string())?;
                insert_raw(&tx, source_id, "loose", None, kind.name(), content.len() as i64, content.len() as i64, input_len as i64, &content, Some(0), Some(input_len as i64), None, None, None, None).map_err(|e| e.to_string())?;
                tx.commit().map_err(|e| e.to_string())?;
                self.refresh_candidates()?;
                Ok(source_id)
            }
            Err(err) => {
                let source_id = self.db.insert_source("loose", original, path, hash, "invalid", Some(&err.to_string())).map_err(|e| e.to_string())?;
                Ok(source_id)
            }
        }
    }

    fn try_pair_idx(&self, pack_source_id: i64, pack_checksum: [u8; 20]) -> Result<(), String> {
        let mut found = None;
        let mut stmt = self.db.conn.prepare("SELECT id, stored_path FROM sources WHERE kind='idx' AND paired_source_id IS NULL").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
        for row in rows {
            let (id, stored) = row.map_err(|e| e.to_string())?;
            if let Ok(bytes) = std::fs::read(&stored) {
                if let Ok(idx) = parse_idx(&bytes) {
                    if idx.pack_checksum == pack_checksum {
                        found = Some(id);
                        break;
                    }
                }
            }
        }
        if let Some(idx_id) = found {
            self.db.conn.execute("UPDATE sources SET paired_source_id=?1 WHERE id=?2 OR id=?1", params![idx_id, pack_source_id]).map_err(|e| e.to_string())?;
            self.verify_idx(pack_source_id, idx_id)?;
        }
        Ok(())
    }

    fn try_pair_pack(&self, idx_source_id: i64, idx_checksum: [u8; 20]) -> Result<(), String> {
        let mut found = None;
        let mut stmt = self.db.conn.prepare("SELECT id, stored_path FROM sources WHERE kind='pack' AND paired_source_id IS NULL").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
        for row in rows {
            let (id, stored) = row.map_err(|e| e.to_string())?;
            if let Ok(bytes) = std::fs::read(&stored) {
                if let Ok(pack) = parse_pack(&bytes) {
                    if pack.checksum == idx_checksum {
                        found = Some(id);
                        break;
                    }
                }
            }
        }
        if let Some(pack_id) = found {
            self.db.conn.execute("UPDATE sources SET paired_source_id=?1 WHERE id=?2 OR id=?1", params![idx_source_id, pack_id]).map_err(|e| e.to_string())?;
            self.verify_idx(pack_id, idx_source_id)?;
        }
        Ok(())
    }

    fn verify_idx(&self, pack_source_id: i64, idx_source_id: i64) -> Result<(), String> {
        let pack_path: String = self.db.conn.query_row("SELECT stored_path FROM sources WHERE id=?1", params![pack_source_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        let idx_path: String = self.db.conn.query_row("SELECT stored_path FROM sources WHERE id=?1", params![idx_source_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        let pack_bytes = std::fs::read(pack_path).map_err(|e| e.to_string())?;
        let idx_bytes = std::fs::read(idx_path).map_err(|e| e.to_string())?;
        let pack = parse_pack(&pack_bytes).map_err(|e| e.to_string())?;
        let idx = parse_idx(&idx_bytes).map_err(|e| e.to_string())?;
        let by_offset: HashMap<i64, &crate::git::PackEntry> = pack.entries.iter().map(|e| (e.offset as i64, e)).collect();
        for item in &idx.entries {
            let evidence = match by_offset.get(&(item.offset as i64)) {
                None => "index points outside pack".to_string(),
                Some(entry) => {
                    let actual_crc = entry_crc32(&pack_bytes, entry) as i64;
                    if actual_crc != item.crc32 as i64 {
                        format!("CRC mismatch at offset {}: index {:08x} actual {:08x}", item.offset, item.crc32, actual_crc)
                    } else if !entry.object_type.name().contains("delta") {
                        let actual_oid = git_object_id(entry.object_type, &entry.payload.data);
                        if actual_oid != item.oid {
                            "index object id does not match recomputed object id".to_string()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                }
            };
            if !evidence.is_empty() {
                self.db.conn.execute(
                    "INSERT INTO resolution_steps(raw_id,seq,check_kind,check_ok,detail)
                     SELECT COALESCE((SELECT id FROM raw_objects WHERE source_id=?1 AND pack_offset=?2),-1),0,'index',0,?3",
                    params![pack_source_id, item.offset as i64, evidence],
                ).map_err(|e| e.to_string())?;
            }
        }
        if pack.count as usize != idx.entries.len() {
            self.db.conn.execute("UPDATE sources SET parse_status='mismatch', parse_error='index and pack object counts differ' WHERE id IN (?1,?2)", params![pack_source_id, idx_source_id]).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn refresh_candidates(&self) -> Result<(), String> {
        let mut stmt = self.db.conn.prepare(
            "SELECT r.id,r.source_id,s.kind,s.original_name,s.sha256,
                    CASE s.kind WHEN 'loose' THEN 0 WHEN 'pack' THEN 1 ELSE 2 END,
                    r.pack_offset,r.type_name,r.declared_size,r.inflated_size,r.content,r.content_sha256,r.parse_error,r.crc32,r.base_ref_oid,r.base_offset
             FROM raw_objects r JOIN sources s ON s.id=r.source_id",
        ).map_err(|e| e.to_string())?;
        let raws = stmt.query_map([], map_raw).map_err(|e| e.to_string())?;
        let mut candidates: Vec<(String, i64, i64, i64, bool, Option<String>)> = Vec::new();
        for raw in raws {
            let raw = raw.map_err(|e| e.to_string())?;
            if raw.parse_error.is_some() || !matches!(raw.type_name.as_str(), "commit" | "tree" | "blob" | "tag") {
                continue;
            }
            if let Some(kind) = git_type(&raw.type_name) {
                let oid = git_object_id(kind, &raw.content);
                let valid = raw.declared_size == raw.inflated_size;
                let reason = (!valid).then(|| "declared size differs from inflated length".to_string());
                candidates.push((oid_hex(&oid), raw.id, raw.source_id, raw.origin_rank, valid, reason));
            }
        }
        let tx = self.db.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM candidates", []).map_err(|e| e.to_string())?;
        for (oid, raw_id, source_id, rank, valid, reason) in candidates {
            tx.execute(
                "INSERT INTO candidates(oid,raw_id,source_id,origin_rank,valid,mismatch_reason) VALUES (?1,?2,?3,?4,?5,?6)",
                params![oid, raw_id, source_id, rank, valid, reason],
            ).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn load_raws(&self) -> Result<HashMap<i64, RawRecord>, String> {
        let mut stmt = self.db.conn.prepare(
            "SELECT r.id,r.source_id,s.kind,s.original_name,s.sha256,
                    CASE s.kind WHEN 'loose' THEN 0 WHEN 'pack' THEN 1 ELSE 2 END,
                    r.pack_offset,r.type_name,r.declared_size,r.inflated_size,r.content,r.content_sha256,r.parse_error,r.crc32,r.base_ref_oid,r.base_offset
             FROM raw_objects r JOIN sources s ON s.id=r.source_id",
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], map_raw).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        for row in rows {
            let raw = row.map_err(|e| e.to_string())?;
            map.insert(raw.id, raw);
        }
        Ok(map)
    }

    fn load_candidates(&self, branch: &str) -> Result<HashMap<String, Vec<CandidateRecord>>, String> {
        let mut stmt = self.db.conn.prepare(
            "SELECT c.oid,c.raw_id,c.source_id,c.origin_rank,c.valid,s.original_name,s.sha256,r.content_sha256
             FROM candidates c
             JOIN sources s ON s.id=c.source_id
             JOIN raw_objects r ON r.id=c.raw_id
             WHERE NOT EXISTS (
               SELECT 1 FROM branch_pins p WHERE p.oid=c.oid AND p.branch=?1 AND p.source_id<>c.source_id
             )
             ORDER BY c.valid DESC, c.origin_rank ASC, c.source_id ASC, c.raw_id ASC",
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![branch], |row| {
            Ok(CandidateRecord {
                oid: row.get(0)?,
                raw_id: row.get(1)?,
                source_id: row.get(2)?,
                origin_rank: row.get(3)?,
                valid: row.get::<_, i64>(4)? != 0,
                source_name: row.get(5)?,
                source_sha: row.get(6)?,
                content_sha: row.get(7)?,
            })
        }).map_err(|e| e.to_string())?;
        let mut map: HashMap<String, Vec<CandidateRecord>> = HashMap::new();
        for row in rows {
            let candidate = row.map_err(|e| e.to_string())?;
            map.entry(candidate.oid.clone()).or_default().push(candidate);
        }
        Ok(map)
    }

    fn load_edges(&self) -> Result<HashMap<i64, (String, Option<String>, Option<i64>, Option<i64>)>, String> {
        let mut stmt = self.db.conn.prepare("SELECT child_raw_id,ref_kind,base_oid,base_offset,base_raw_id FROM edges").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, (r.get::<_, String>(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))).map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        for row in rows {
            let (id, edge) = row.map_err(|e| e.to_string())?;
            map.insert(id, edge);
        }
        Ok(map)
    }


    pub fn analyze(&self, budget: Budget, branch: &str) -> Result<AnalysisReport, String> {
        self.refresh_candidates()?;
        let raws = self.load_raws()?;
        let candidates = self.load_candidates(branch)?;
        let edges = self.load_edges()?;
        let run_id = self.db.conn.execute(
            "INSERT INTO analysis_runs(state,max_depth,total_budget,single_ratio,used_bytes,started_at)
             VALUES ('running',?1,?2,?3,0,strftime('%s','now'))",
            params![budget.max_depth as i64, budget.total_bytes as i64, budget.single_ratio_percent as i64],
        ).map_err(|e| e.to_string())?;
        let mut solver = Solver {
            budget, raws: &raws, candidates: &candidates, edges: &edges,
            states: HashMap::new(), active: HashSet::new(), used_bytes: 0, paused: false,
        };
        for id in raws.keys().copied().collect::<Vec<_>>() {
            solver.resolve(id, 0, 0);
        }
        self.persist(&solver.states, run_id as i64, solver.used_bytes, solver.paused)?;
        Ok(AnalysisReport { states: solver.states, used_bytes: solver.used_bytes, paused: solver.paused, raws, edges })
    }

    pub fn recompute_affected(&self, affected: &[i64], budget: Budget, branch: &str) -> Result<AnalysisReport, String> {
        self.refresh_candidates()?;
        let raws = self.load_raws()?;
        let candidates = self.load_candidates(branch)?;
        let edges = self.load_edges()?;
        let mut states = self.load_resolved(&raws)?;
        let reverse = reverse_edges(&edges);
        let mut affected_set: HashSet<i64> = affected.iter().copied().filter(|id| raws.contains_key(id)).collect();
        for new_raw_id in affected {
            if let Some(outcome) = states.get(new_raw_id).cloned() {
                if let Some(new_oid) = outcome.oid {
                    let new_oid = oid_hex(&new_oid);
                    for (child, edge) in edges.iter() {
                        if edge.1.as_deref() == Some(new_oid.as_str()) && !affected_set.contains(child) {
                            affected_set.insert(*child);
                        }
                    }
                }
            }
        }
        let mut work: Vec<i64> = affected_set.iter().copied().collect();
        let mut seen: HashSet<i64> = affected_set.clone();
        while let Some(id) = work.pop() {
            if let Some(next) = reverse.get(&id) {
                for child in next {
                    if seen.insert(*child) { work.push(*child); }
                }
            }
        }
        for id in &seen {
            states.remove(id);
            self.db.conn.execute("DELETE FROM resolved WHERE raw_id=?1", params![id]).ok();
            self.db.conn.execute("DELETE FROM resolution_steps WHERE raw_id=?1", params![id]).ok();
        }
        let run_id = self.db.conn.execute(
            "INSERT INTO analysis_runs(state,max_depth,total_budget,single_ratio,used_bytes,started_at)
             VALUES ('incremental',?1,?2,?3,0,strftime('%s','now'))",
            params![budget.max_depth as i64, budget.total_bytes as i64, budget.single_ratio_percent as i64],
        ).map_err(|e| e.to_string())?;
        let used_bytes = self.total_used_bytes()?;
        let mut solver = Solver {
            budget, raws: &raws, candidates: &candidates, edges: &edges,
            states, active: HashSet::new(), used_bytes, paused: false,
        };
        for id in seen {
            solver.resolve(id, 0, 0);
        }
        self.persist(&solver.states, run_id as i64, solver.used_bytes, solver.paused)?;
        Ok(AnalysisReport { states: solver.states, used_bytes: solver.used_bytes, paused: solver.paused, raws, edges })
    }
}

struct Solver<'a> {
    budget: Budget,
    raws: &'a HashMap<i64, RawRecord>,
    candidates: &'a HashMap<String, Vec<CandidateRecord>>,
    edges: &'a HashMap<i64, (String, Option<String>, Option<i64>, Option<i64>)>,
    states: HashMap<i64, ResolveOutcome>,
    active: HashSet<i64>,
    used_bytes: usize,
    paused: bool,
}

impl<'a> Solver<'a> {
    fn resolve(&mut self, raw_id: i64, depth: usize, chain_bytes: usize) {
        if self.states.contains_key(&raw_id) {
            return;
        }
        if self.active.contains(&raw_id) {
            self.states.insert(raw_id, failed_outcome(ResolveState::Cycle, "delta chain forms a cycle", vec![raw_id]));
            return;
        }
        let Some(raw) = self.raws.get(&raw_id).cloned() else {
            self.states.insert(raw_id, failed_outcome(ResolveState::MissingBase, "raw object vanished", vec![raw_id]));
            return;
        };
        if let Some(error) = raw.parse_error.clone() {
            self.states.insert(raw_id, failed_outcome(ResolveState::Invalid, &error, vec![raw_id]));
            return;
        }
        if matches!(raw.type_name.as_str(), "commit" | "tree" | "blob" | "tag") {
            self.resolve_plain(&raw);
            return;
        }
        if depth > self.budget.max_depth {
            self.paused = true;
            self.states.insert(raw_id, paused_outcome(vec![raw_id], "delta depth budget reached; retry is safe"));
            return;
        }
        let Some(edge) = self.edges.get(&raw_id).cloned() else {
            self.states.insert(raw_id, failed_outcome(ResolveState::Invalid, "delta object has no base reference", vec![raw_id]));
            return;
        };
        let Some(base_id) = self.find_base(&raw, &edge) else {
            let reason = if edge.0 == "ofs" { "ofs-delta target is outside parsed pack" } else { "external ref-delta base is absent" };
            self.states.insert(raw_id, failed_outcome(ResolveState::MissingBase, reason, vec![raw_id]));
            return;
        };
        let path_before = self.active.iter().copied().collect::<HashSet<_>>();
        self.active.insert(raw_id);
        self.resolve(base_id, depth + 1, chain_bytes + raw.content.len());
        self.active.remove(&raw_id);
        let base_became_cycle = self
            .states
            .get(&base_id)
            .map(|state| state.state == ResolveState::Cycle && state.blocked_chain.iter().any(|id| path_before.contains(id) || *id == raw_id))
            .unwrap_or(false);
        if self.active.contains(&base_id) || base_became_cycle {
            let mut chain = vec![raw_id];
            chain.extend(self.states.get(&base_id).map(|s| s.blocked_chain.clone()).unwrap_or_default());
            self.states.insert(raw_id, failed_outcome(ResolveState::Cycle, "delta chain forms a cycle", chain));
            return;
        }
        let base = match self.states.get(&base_id).cloned() {
            Some(base) => base,
            None => return,
        };
        if base.state != ResolveState::Resolved {
            let state = if base.state == ResolveState::Paused { ResolveState::Paused } else { base.state.clone() };
            if state == ResolveState::Paused { self.paused = true; }
            let message = base.error_message.clone().unwrap_or_else(|| "base unavailable".to_string());
            let mut chain = vec![raw_id];
            chain.extend(base.blocked_chain);
            self.states.insert(raw_id, failed_outcome(state, &message, chain));
            return;
        }
        let expanded = chain_bytes + base.content.len();
        if expanded > self.budget.total_bytes || self.used_bytes + expanded > self.budget.total_bytes {
            self.paused = true;
            self.states.insert(raw_id, paused_outcome(vec![raw_id, base_id], "total expansion budget reached; retry is safe"));
            return;
        }
        if expanded * 100 > self.budget.single_ratio_percent * self.budget.total_bytes {
            self.paused = true;
            self.states.insert(raw_id, paused_outcome(vec![raw_id, base_id], "single-object expansion ratio reached; retry is safe"));
            return;
        }
        self.apply_one(raw_id, base_id, raw, base, depth);
    }

    fn resolve_plain(&mut self, raw: &RawRecord) {
        let kind = git_type(&raw.type_name).unwrap();
        let oid = git_object_id(kind, &raw.content);
        let valid = raw.declared_size == raw.inflated_size;
        let state = if valid { ResolveState::Resolved } else { ResolveState::Invalid };
        let steps = vec![StepRecord {
            base_raw_id: None,
            base_oid: None,
            op_start: None,
            op_end: None,
            op_kind: None,
            input_len: raw.content.len() as i64,
            output_len: raw.content.len() as i64,
            check_kind: "git-object-id".to_string(),
            check_ok: valid,
            detail: oid_hex(&oid),
        }];
        self.states.insert(raw.id, ResolveOutcome {
            state,
            oid: Some(oid),
            kind: Some(kind),
            content: raw.content.clone(),
            depth: 0,
            expanded_bytes: raw.content.len(),
            error_code: (!valid).then(|| "size-spoof".to_string()),
            error_message: (!valid).then(|| "declared size differs from inflated length".to_string()),
            blocked_chain: if valid { vec![] } else { vec![raw.id] },
            steps,
        });
    }

    fn find_base(&self, raw: &RawRecord, edge: &(String, Option<String>, Option<i64>, Option<i64>)) -> Option<i64> {
        if edge.0 == "ofs" {
            if let Some(raw_id) = edge.3 {
                return Some(raw_id);
            }
            let target = edge.2?;
            return self.raws.values()
                .find(|candidate| candidate.source_id == raw.source_id && candidate.offset == Some(target))
                .map(|candidate| candidate.id);
        }
        let base_oid = edge.1.as_ref()?;
        let options = self.candidates.get(base_oid)?;
        let valid: Vec<&CandidateRecord> = options.iter().filter(|c| c.valid).collect();
        let pool = if valid.is_empty() { options.iter().collect() } else { valid };
        pool.first().map(|candidate| candidate.raw_id)
    }

    fn apply_one(&mut self, raw_id: i64, base_id: i64, raw: RawRecord, base: ResolveOutcome, depth: usize) {
        match apply_delta(&base.content, &raw.content) {
            Ok(applied) => {
                let kind = base.kind.unwrap_or(GitType::Blob);
                let oid = git_object_id(kind, &applied.data);
                let expanded_len = applied.data.len();
                let mut steps = vec![StepRecord {
                    base_raw_id: Some(base_id),
                    base_oid: base.oid.map(|oid| oid_hex(&oid)),
                    op_start: None,
                    op_end: None,
                    op_kind: None,
                    input_len: raw.content.len() as i64,
                    output_len: applied.result_size as i64,
                    check_kind: "delta-size".to_string(),
                    check_ok: applied.result_size == applied.data.len() && raw.declared_size == raw.inflated_size,
                    detail: format!("base={} result={}", applied.base_size, applied.result_size),
                }];
                for instruction in &applied.instructions {
                    let (op_kind, detail, output_len) = match instruction.kind {
                        crate::git::DeltaInstructionKind::Insert { length } => ("insert", format!("length={length}"), length),
                        crate::git::DeltaInstructionKind::Copy { offset, length } => ("copy", format!("offset={offset} length={length}"), length),
                    };
                    steps.push(StepRecord {
                        base_raw_id: Some(base_id),
                        base_oid: base.oid.map(|oid| oid_hex(&oid)),
                        op_start: Some(instruction.op_offset as i64),
                        op_end: Some(instruction.op_end as i64),
                        op_kind: Some(op_kind.to_string()),
                        input_len: (instruction.op_end - instruction.op_offset) as i64,
                        output_len: output_len as i64,
                        check_kind: "delta-op".to_string(),
                        check_ok: true,
                        detail,
                    });
                }
                steps.push(StepRecord {
                    base_raw_id: Some(base_id),
                    base_oid: base.oid.map(|oid| oid_hex(&oid)),
                    op_start: None,
                    op_end: None,
                    op_kind: None,
                    input_len: raw.content.len() as i64,
                    output_len: applied.data.len() as i64,
                    check_kind: "git-object-id".to_string(),
                    check_ok: true,
                    detail: oid_hex(&oid),
                });
                self.used_bytes += applied.data.len();
                self.states.insert(raw_id, ResolveOutcome {
                    state: ResolveState::Resolved,
                    oid: Some(oid),
                    kind: Some(kind),
                    content: applied.data,
                    depth: depth + 1,
                    expanded_bytes: base.expanded_bytes + expanded_len,
                    error_code: None,
                    error_message: None,
                    blocked_chain: vec![],
                    steps,
                });
            }
            Err(err) => {
                self.states.insert(raw_id, failed_outcome(ResolveState::Invalid, &err.to_string(), vec![raw_id]));
            }
        }
    }
}

fn failed_outcome(state: ResolveState, message: &str, chain: Vec<i64>) -> ResolveOutcome {
    let error_code = Some(format!("{:?}", state).to_lowercase());
    ResolveOutcome {
        state,
        oid: None,
        kind: None,
        content: Vec::new(),
        depth: 0,
        expanded_bytes: 0,
        error_code,
        error_message: Some(message.to_string()),
        blocked_chain: chain,
        steps: Vec::new(),
    }
}

fn paused_outcome(chain: Vec<i64>, message: &str) -> ResolveOutcome {
    ResolveOutcome {
        state: ResolveState::Paused,
        oid: None,
        kind: None,
        content: Vec::new(),
        depth: 0,
        expanded_bytes: 0,
        error_code: Some("budget-paused".to_string()),
        error_message: Some(message.to_string()),
        blocked_chain: chain,
        steps: Vec::new(),
    }
}

fn reverse_edges(edges: &HashMap<i64, (String, Option<String>, Option<i64>, Option<i64>)>) -> HashMap<i64, Vec<i64>> {
    let mut reverse = HashMap::new();
    for (child, edge) in edges {
        if let Some(base_raw) = edge.3 {
            reverse.entry(base_raw).or_insert_with(Vec::new).push(*child);
        }
    }
    reverse
}

fn map_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        id: row.get(0)?,
        source_id: row.get(1)?,
        source_kind: row.get(2)?,
        source_name: row.get(3)?,
        source_sha: row.get(4)?,
        origin_rank: row.get(5)?,
        offset: row.get(6)?,
        type_name: row.get(7)?,
        declared_size: row.get(8)?,
        inflated_size: row.get(9)?,
        content: row.get(10)?,
        content_sha: row.get(11)?,
        parse_error: row.get(12)?,
        crc32: row.get(13)?,
        base_ref_oid: row.get(14)?,
        base_offset: row.get(15)?,
    })
}

fn state_name(state: &ResolveState) -> &'static str {
    match state {
        ResolveState::Resolved => "resolved",
        ResolveState::MissingBase => "missing_base",
        ResolveState::Cycle => "cycle",
        ResolveState::Invalid => "invalid",
        ResolveState::Paused => "paused",
        ResolveState::Conflict => "conflict",
    }
}

fn classify(filename: &str, bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"PACK") {
        "pack"
    } else if bytes.starts_with(b"\xfftOc") {
        "idx"
    } else if filename.ends_with(".idx") {
        "idx"
    } else if filename.ends_with(".pack") {
        "pack"
    } else {
        "loose"
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_raw(
    tx: &rusqlite::Transaction<'_>,
    source_id: i64,
    source_kind: &str,
    pack_offset: Option<i64>,
    type_name: &str,
    declared_size: i64,
    inflated_size: i64,
    compressed_size: i64,
    content: &[u8],
    header_offset: Option<i64>,
    zlib_end: Option<i64>,
    base_ref_oid: Option<String>,
    base_offset: Option<i64>,
    parse_error: Option<String>,
    crc32: Option<i64>,
) -> rusqlite::Result<i64> {
    let content_sha = sha256_hex(content);
    tx.execute(
        "INSERT INTO raw_objects(source_id,source_kind,pack_offset,type_name,declared_size,inflated_size,
         compressed_size,content,content_sha256,header_offset,zlib_end,base_ref_oid,base_offset,parse_error,crc32)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![source_id, source_kind, pack_offset, type_name, declared_size, inflated_size,
                compressed_size, content, content_sha, header_offset, zlib_end, base_ref_oid,
                base_offset, parse_error, crc32],
    )?;
    Ok(tx.last_insert_rowid())
}

impl Analyzer {
    fn persist(&self, states: &HashMap<i64, ResolveOutcome>, run_id: i64, used_bytes: usize, paused: bool) -> Result<(), String> {
        let _ = run_id;
        let tx = self.db.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for (raw_id, outcome) in states {
            tx.execute(
                "INSERT OR REPLACE INTO resolved(raw_id,state,oid,type_name,content,depth,expanded_bytes,error_code,error_message,blocked_chain,version)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,
                          COALESCE((SELECT version FROM resolved WHERE raw_id=?1),0)+1)",
                params![
                    raw_id,
                    state_name(&outcome.state),
                    outcome.oid.map(|oid| oid_hex(&oid)),
                    outcome.kind.map(|kind| kind.name()),
                    outcome.content,
                    outcome.depth as i64,
                    outcome.expanded_bytes as i64,
                    outcome.error_code,
                    outcome.error_message,
                    serde_json::to_string(&outcome.blocked_chain).unwrap(),
                ],
            ).map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM resolution_steps WHERE raw_id=?1", params![raw_id]).ok();
            for (seq, step) in outcome.steps.iter().enumerate() {
                tx.execute(
                    "INSERT INTO resolution_steps(raw_id,seq,base_raw_id,base_oid,op_start,op_end,op_kind,
                     input_len,output_len,check_kind,check_ok,detail)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![raw_id, seq as i64, step.base_raw_id, step.base_oid, step.op_start, step.op_end,
                            step.op_kind, step.input_len, step.output_len, step.check_kind, step.check_ok, step.detail],
                ).map_err(|e| e.to_string())?;
            }
        }
        tx.execute(
            "UPDATE analysis_runs SET state=?1, used_bytes=?2, finished_at=strftime('%s','now') WHERE id=?3",
            params![if paused { "paused" } else { "complete" }, used_bytes as i64, run_id],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn total_used_bytes(&self) -> Result<usize, String> {
        self.db.conn.query_row(
            "SELECT COALESCE(SUM(expanded_bytes),0) FROM resolved WHERE state='resolved'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|value| value.max(0) as usize).map_err(|e| e.to_string())
    }

    fn load_resolved(&self, raws: &HashMap<i64, RawRecord>) -> Result<HashMap<i64, ResolveOutcome>, String> {
        let mut map = HashMap::new();
        let mut stmt = self.db.conn.prepare(
            "SELECT r.raw_id,r.state,r.oid,r.type_name,r.content,r.depth,r.expanded_bytes,
                    r.error_code,r.error_message,r.blocked_chain
             FROM resolved r WHERE r.state='resolved'",
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| {
            let oid_hex: Option<String> = row.get(2)?;
            let type_name: Option<String> = row.get(3)?;
            let content: Vec<u8> = row.get(4)?;
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, oid_hex, type_name, content,
                row.get::<_, i64>(5)?, row.get::<_, i64>(6)?))
        }).map_err(|e| e.to_string())?;
        for row in rows {
            let (id, state, oid_text, type_name, content, depth, expanded) = row.map_err(|e| e.to_string())?;
            if state != "resolved" || !raws.contains_key(&id) {
                continue;
            }
            let oid = oid_text.and_then(|text| crate::git::parse_oid(&text));
            let kind = type_name.and_then(|name| git_type(&name));
            map.insert(id, ResolveOutcome {
                state: ResolveState::Resolved,
                oid,
                kind,
                content,
                depth: depth as usize,
                expanded_bytes: expanded as usize,
                error_code: None,
                error_message: None,
                blocked_chain: vec![],
                steps: vec![],
            });
        }
        Ok(map)
    }
}
