use crate::git::{self, apply_delta, git_object_id, oid_hex, parse_oid, GitError, ObjectType};
use crate::store::AppState;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub total_expand_bytes: usize,
    pub max_object_ratio: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_depth: 50,
            total_expand_bytes: 64 * 1024 * 1024,
            max_object_ratio: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Complete,
    PausedBudget,
    Blocked,
}

#[derive(Debug, Clone)]
struct ObjectRow {
    id: i64,
    source_id: i64,
    pack_id: Option<i64>,
    pack_offset: Option<i64>,
    object_type: String,
    expanded_size: i64,
    payload_path: String,
    base_offset: Option<i64>,
    base_ref_oid: Option<String>,
    parse_status: String,
    compressed_size: i64,
}

#[derive(Debug, Clone)]
struct CandidateRow {
    oid: String,
    object_id: i64,
    valid: bool,
    sort_key: i64,
    source_kind: String,
}

#[derive(Debug, Clone)]
struct Resolved {
    kind: ObjectType,
    data: Vec<u8>,
    depth: usize,
}

#[derive(Debug, Clone)]
enum ResolveError {
    MissingBase {
        oid: Option<String>,
        offset: Option<i64>,
    },
    Cycle(Vec<i64>),
    BadDelta(String),
    BadObject(String),
    OidMismatch {
        expected: String,
        actual: String,
    },
    DepthLimit,
    BudgetTotal {
        needed: usize,
        remaining: usize,
    },
    ObjectRatio {
        output: usize,
        compressed_limit: usize,
    },
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn ensure_default_reconstructions(state: &AppState, branch_id: i64) -> rusqlite::Result<()> {
    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT OR IGNORE INTO reconstructions(branch_id,object_id,status)
         SELECT ?1,id,'new' FROM objects",
        params![branch_id],
    )?;
    Ok(())
}

pub fn run_analysis(
    state: &AppState,
    branch_id: i64,
    budget: Budget,
    only_object_id: Option<i64>,
) -> rusqlite::Result<RunOutcome> {
    ensure_default_reconstructions(state, branch_id)?;
    let db = state.db.lock().unwrap();
    let objects = load_objects(&db)?;
    let by_id = objects.iter().map(|row| (row.id, row.clone())).collect::<HashMap<_, _>>();
    let mut candidates = load_candidates(&db, branch_id)?;
    candidates.sort_by(|a, b| {
        b.valid
            .cmp(&a.valid)
            .then_with(|| a.oid.cmp(&b.oid))
            .then_with(|| a.sort_key.cmp(&b.sort_key))
            .then_with(|| a.object_id.cmp(&b.object_id))
            .then_with(|| a.source_kind.cmp(&b.source_kind))
    });
    let mut by_oid: HashMap<String, Vec<CandidateRow>> = HashMap::new();
    for candidate in candidates {
        by_oid.entry(candidate.oid.clone()).or_default().push(candidate);
    }
    let mut offsets = HashMap::new();
    for row in &objects {
        if let (Some(pack_id), Some(offset)) = (row.pack_id, row.pack_offset) {
            offsets.insert((pack_id, offset), row.id);
        }
    }

    let mut resolved: HashMap<i64, Resolved> = HashMap::new();
    let mut charged: HashSet<i64> = HashSet::new();
    let mut used_total = db
        .query_row(
            "SELECT COALESCE(SUM(charged_bytes),0) FROM reconstructions WHERE branch_id=?1",
            params![branch_id],
            |row| row.get::<_, i64>(0),
        )? as usize;
    let mut outcome = RunOutcome::Complete;
    let ordered = topological_order(&objects);

    for object_id in ordered {
        if let Some(only) = only_object_id {
            if only != object_id && !is_dependency_target(&db, branch_id, only, object_id)? {
                continue;
            }
        }
        let current_status: String = db
            .query_row(
                "SELECT status FROM reconstructions WHERE branch_id=?1 AND object_id=?2",
                params![branch_id, object_id],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "new".to_string());
        if current_status == "resolved" {
            if let Some(row) = by_id.get(&object_id) {
                if let Some(output) = read_existing_output(&db, state, object_id, branch_id) {
                    resolved.insert(
                        object_id,
                        Resolved {
                            kind: parse_type(&row.object_type),
                            data: output,
                            depth: 0,
                        },
                    );
                }
            }
            continue;
        }
        if !matches!(current_status.as_str(), "new" | "paused_budget" | "blocked" | "bad") {
            continue;
        }
        let mut path = Vec::new();
        let result = resolve_object(
            object_id,
            &by_id,
            &by_oid,
            &offsets,
            &db,
            state,
            branch_id,
            budget,
            used_total,
            &mut charged,
            &mut path,
            &mut resolved,
        );
        match result {
            Ok(found) => {
                used_total = found.used_total;
                persist_success(&db, state, branch_id, object_id, &found)?;
            }
            Err(err) => {
                let next = persist_failure(&db, branch_id, object_id, &err)?;
                if matches!(next, RunOutcome::PausedBudget) {
                    outcome = RunOutcome::PausedBudget;
                } else if outcome == RunOutcome::Complete {
                    outcome = RunOutcome::Blocked;
                }
            }
        }
    }
    Ok(outcome)
}

fn parse_type(value: &str) -> ObjectType {
    match value {
        "commit" => ObjectType::Commit,
        "tree" => ObjectType::Tree,
        "tag" => ObjectType::Tag,
        _ => ObjectType::Blob,
    }
}

fn load_objects(db: &rusqlite::Connection) -> rusqlite::Result<Vec<ObjectRow>> {
    let mut rows = Vec::new();
    let mut stmt = db.prepare(
        "SELECT id,source_id,pack_id,pack_offset,object_type,expanded_size,
                COALESCE(stored_payload_path,''),base_offset,base_ref_oid,parse_status,
                COALESCE(payload_end-payload_offset,expanded_size)
         FROM objects ORDER BY id",
    )?;
    let iter = stmt.query_map([], |row| {
        Ok(ObjectRow {
            id: row.get(0)?,
            source_id: row.get(1)?,
            pack_id: row.get(2)?,
            pack_offset: row.get(3)?,
            object_type: row.get(4)?,
            expanded_size: row.get(5)?,
            payload_path: row.get(6)?,
            base_offset: row.get(7)?,
            base_ref_oid: row.get(8)?,
            parse_status: row.get(9)?,
            compressed_size: row.get(10)?,
        })
    })?;
    for row in iter {
        rows.push(row?);
    }
    Ok(rows)
}

fn load_candidates(db: &rusqlite::Connection, branch_id: i64) -> rusqlite::Result<Vec<CandidateRow>> {
    let mut rows = Vec::new();
    let mut stmt = db.prepare(
        "SELECT candidates.oid,candidates.object_id,candidates.valid,candidates.sort_key,
                candidates.source_kind
         FROM candidates
         LEFT JOIN branch_pins ON branch_pins.branch_id=?1
            AND branch_pins.oid=candidates.oid AND branch_pins.object_id=candidates.object_id
         ORDER BY CASE WHEN branch_pins.oid IS NULL THEN 1 ELSE 0 END, candidates.id",
    )?;
    let iter = stmt.query_map(params![branch_id], |row| {
        Ok(CandidateRow {
            oid: row.get(0)?,
            object_id: row.get(1)?,
            valid: row.get::<_, i64>(2)? != 0,
            sort_key: row.get(3)?,
            source_kind: row.get(4)?,
        })
    })?;
    for row in iter {
        rows.push(row?);
    }
    Ok(rows)
}

fn topological_order(objects: &[ObjectRow]) -> Vec<i64> {
    let ids = objects.iter().map(|row| row.id).collect::<HashSet<_>>();
    let mut incoming = HashMap::new();
    let mut outgoing = HashMap::<i64, Vec<i64>>::new();
    let offset_index = objects
        .iter()
        .filter_map(|row| {
            row.pack_id
                .zip(row.pack_offset)
                .map(|key| (key, row.id))
        })
        .collect::<HashMap<_, _>>();
    for row in objects {
        incoming.entry(row.id).or_insert(0usize);
        let parent = if row.object_type == "ofs-delta" {
            row.pack_id.zip(row.base_offset).and_then(|key| offset_index.get(&key).copied())
        } else {
            None
        };
        if let Some(parent) = parent {
            if ids.contains(&parent) {
                outgoing.entry(parent).or_default().push(row.id);
                *incoming.entry(row.id).or_insert(0) += 1;
            }
        }
    }
    let mut queue = incoming
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| *id)
        .collect::<VecDeque<_>>();
    let mut ordered = Vec::new();
    while let Some(id) = queue.pop_front() {
        ordered.push(id);
        if let Some(children) = outgoing.get(&id) {
            for child in children {
                let count = incoming.get_mut(child).unwrap();
                *count -= 1;
                if *count == 0 {
                    queue.push_back(*child);
                }
            }
        }
    }
    if ordered.len() != objects.len() {
        for row in objects {
            if !ordered.contains(&row.id) {
                ordered.push(row.id);
            }
        }
    }
    ordered
}

struct FoundObject {
    id: i64,
    resolved: Resolved,
    steps: Vec<StepRecord>,
    expected_oid: Option<String>,
    charged_ids: Vec<i64>,
    used_total: usize,
}

#[derive(Debug, Clone)]
struct StepRecord {
    ordinal: i64,
    base_object_id: Option<i64>,
    delta_object_id: i64,
    base_offset: Option<i64>,
    input_size: i64,
    output_size: i64,
    instruction_count: i64,
    instruction_start: i64,
    instruction_end: i64,
    check_ok: bool,
    error_message: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_object(
    object_id: i64,
    objects: &HashMap<i64, ObjectRow>,
    candidates: &HashMap<String, Vec<CandidateRow>>,
    offsets: &HashMap<(i64, i64), i64>,
    db: &rusqlite::Connection,
    state: &AppState,
    branch_id: i64,
    budget: Budget,
    used_total_start: usize,
    already_charged: &mut HashSet<i64>,
    path: &mut Vec<i64>,
    memo: &mut HashMap<i64, Resolved>,
) -> Result<FoundObject, ResolveError> {
    if let Some(existing) = memo.get(&object_id) {
        return Ok(FoundObject {
            id: object_id,
            resolved: existing.clone(),
            steps: Vec::new(),
            expected_oid: None,
            charged_ids: Vec::new(),
            used_total: used_total_start,
        });
    }
    if path.contains(&object_id) {
        path.push(object_id);
        return Err(ResolveError::Cycle(path.clone()));
    }
    path.push(object_id);
    let row = objects
        .get(&object_id)
        .ok_or_else(|| ResolveError::BadObject("object record missing".into()))?;
    if row.parse_status != "parsed" {
        return Err(ResolveError::BadObject("source entry was not parsed".into()));
    }
    let payload = read_payload(state, row).map_err(ResolveError::BadObject)?;
    let mut steps = Vec::new();
    let mut charged_ids = Vec::new();
    let mut used_total = used_total_start;

    let resolved = if row.object_type == "ofs-delta" || row.object_type == "ref-delta" {
        let (base_id, base_offset) = if row.object_type == "ofs-delta" {
            let key = row
                .pack_id
                .zip(row.base_offset)
                .ok_or(ResolveError::BadObject("ofs-delta missing base location".into()))?;
            let id = offsets
                .get(&key)
                .copied()
                .ok_or_else(|| ResolveError::MissingBase { oid: None, offset: row.base_offset })?;
            (id, row.base_offset)
        } else {
            let oid = row
                .base_ref_oid
                .clone()
                .ok_or_else(|| ResolveError::BadObject("ref-delta missing base OID".into()))?;
            let candidate = candidates
                .get(&oid)
                .and_then(|entries| entries.first())
                .ok_or_else(|| ResolveError::MissingBase {
                    oid: Some(oid.clone()),
                    offset: None,
                })?;
            (candidate.object_id, None)
        };
        let base = resolve_object(
            base_id,
            objects,
            candidates,
            offsets,
            db,
            state,
            branch_id,
            budget,
            used_total,
            already_charged,
            path,
            memo,
        )?;
        used_total = base.used_total;
        steps.extend(base.steps);
        charged_ids.extend(base.charged_ids);
        let depth = base.resolved.depth + 1;
        if depth > budget.max_depth {
            return Err(ResolveError::DepthLimit);
        }
        let instructions = git::parse_delta_instructions(&payload)
            .map_err(|err: GitError| ResolveError::BadDelta(err.to_string()))?;
        if instructions.source_size != base.resolved.data.len() {
            return Err(ResolveError::BadDelta(format!(
                "input length {} differs from delta source length {}",
                base.resolved.data.len(),
                instructions.source_size
            )));
        }
        let compressed_limit = row
            .compressed_size
            .max(1)
            .checked_mul(budget.max_object_ratio as i64)
            .unwrap_or(i64::MAX) as usize;
        if instructions.target_size > compressed_limit {
            return Err(ResolveError::ObjectRatio {
                output: instructions.target_size,
                compressed_limit,
            });
        }
        if used_total + instructions.target_size > budget.total_expand_bytes {
            return Err(ResolveError::BudgetTotal {
                needed: instructions.target_size,
                remaining: budget.total_expand_bytes.saturating_sub(used_total),
            });
        }
        let (target, checked_instructions) =
            apply_delta(&base.resolved.data, &payload).map_err(|err| ResolveError::BadDelta(err.to_string()))?;
        used_total += target.len();
        if !already_charged.contains(&object_id) {
            already_charged.insert(object_id);
            charged_ids.push(object_id);
        }
        let ordinal = steps.len() as i64 + 1;
        steps.push(StepRecord {
            ordinal,
            base_object_id: Some(base_id),
            delta_object_id: object_id,
            base_offset,
            input_size: base.resolved.data.len() as i64,
            output_size: target.len() as i64,
            instruction_count: checked_instructions.ops.len() as i64,
            instruction_start: checked_instructions.instruction_range_start as i64,
            instruction_end: checked_instructions.instruction_range_end as i64,
            check_ok: checked_instructions.target_size == target.len()
                && checked_instructions.source_size == base.resolved.data.len(),
            error_message: None,
        });
        Resolved {
            kind: base.resolved.kind,
            data: target,
            depth,
        }
    } else {
        let (kind, content) = git::split_loose_object(&payload)
            .map_err(|err| ResolveError::BadObject(err.to_string()))?;
        if used_total + content.len() > budget.total_expand_bytes {
            return Err(ResolveError::BudgetTotal {
                needed: content.len(),
                remaining: budget.total_expand_bytes.saturating_sub(used_total),
            });
        }
        used_total += content.len();
        if !already_charged.contains(&object_id) {
            already_charged.insert(object_id);
            charged_ids.push(object_id);
        }
        Resolved { kind, data: content, depth: 1 }
    };
    path.pop();
    memo.insert(object_id, resolved.clone());
    let expected_oid = expected_oid_for(db, object_id)?;
    Ok(FoundObject {
        id: object_id,
        resolved,
        steps,
        expected_oid,
        charged_ids,
        used_total,
    })
}
