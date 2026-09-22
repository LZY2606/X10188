use crate::db::Db;
use crate::gitobj::{apply_delta, git_oid};
use crate::types::{ErrCode, ObjStatus, ObjType};
use rusqlite::params;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Default, Serialize)]
pub struct RecomputeReport {
    pub resolved: usize,
    pub blocked: usize,
    pub errored: usize,
    pub paused: usize,
    pub affected_reset: usize,
}

#[derive(Clone, Debug)]
struct NodeRec {
    id: i64,
    oid: String,
    kind: String,
    source_id: i64,
    pack_id: Option<i64>,
    pack_offset: Option<i64>,
    base_offset: Option<i64>,
    base_oid: Option<String>,
    status: String,
    error_code: Option<String>,
    pinned: bool,
    filename: String,
}

struct Env<'a> {
    nodes: Vec<NodeRec>,
    by_id: HashMap<i64, usize>,
    by_oid: HashMap<String, Vec<usize>>,
    by_pack_offset: HashMap<(i64, i64), usize>,
    raw: HashMap<i64, Vec<u8>>,
    resolved_data: HashMap<i64, Vec<u8>>,
    visited: HashSet<i64>,
    depth: u32,
    budget_total: u64,
    budget_single: u64,
    max_depth: u32,
    used_total: u64,
    base_stack: Vec<i64>,
    final_kind: HashMap<i64, ObjType>,
    steps: HashMap<i64, Vec<crate::gitobj::OpRange>>,
    step_meta: HashMap<i64, (i64, i64)>,
    depths: HashMap<i64, u32>,
    db: &'a Db,
}

fn kind_of(s: &str) -> ObjType {
    ObjType::parse(s).unwrap_or(ObjType::Blob)
}

pub fn kv_get(conn: &rusqlite::Connection, k: &str) -> String {
    conn.query_row("SELECT v FROM kv WHERE k=?1", params![k], |r| {
        r.get::<_, String>(0)
    })
    .unwrap()
}

pub fn set_budgets(db: &Db, max_depth: Option<i64>, total: Option<i64>, ratio: Option<i64>) {
    let mut conn = db.0.lock().unwrap();
    if let Some(v) = max_depth {
        conn.execute("UPDATE kv SET v=?1 WHERE k='budget_max_depth'", params![v.to_string()])
            .unwrap();
    }
    if let Some(v) = total {
        conn.execute("UPDATE kv SET v=?1 WHERE k='budget_total_bytes'", params![v.to_string()])
            .unwrap();
    }
    if let Some(v) = ratio {
        conn.execute("UPDATE kv SET v=?1 WHERE k='budget_single_ratio'", params![v.to_string()])
            .unwrap();
    }
}

pub fn reset_used(db: &Db) {
    let mut conn = db.0.lock().unwrap();
    conn.execute("UPDATE kv SET v='0' WHERE k='budget_used_total_bytes'", [])
        .unwrap();
}

pub fn incremental(db: &Db) -> RecomputeReport {
    {
        let c = db.0.lock().unwrap();
        c.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS _reset_ids AS
             SELECT id FROM nodes WHERE status='blocked';
             DELETE FROM steps WHERE node_id IN (SELECT id FROM _reset_ids);
             DELETE FROM evidence WHERE node_id IN (SELECT id FROM _reset_ids);
             UPDATE nodes SET status='pending',error_code=NULL,error_note=NULL
              WHERE id IN (SELECT id FROM _reset_ids);
             DROP TABLE _reset_ids;"
        ).unwrap();
    }
    rebuild_edges(db);

    let conn = db.0.lock().unwrap();
    let max_depth: u32 = kv_get(&conn, "budget_max_depth").parse().unwrap();
    let budget_total: u64 = kv_get(&conn, "budget_total_bytes").parse().unwrap();
    let ratio: u64 = kv_get(&conn, "budget_single_ratio").parse().unwrap();
    let used_total: u64 = kv_get(&conn, "budget_used_total_bytes").parse().unwrap();
    let budget_single = budget_total.saturating_mul(ratio) / 100;

    let nodes = load_nodes(&conn);
    let raw = load_stage(&conn, "raw");
    let resolved_data = load_stage(&conn, "resolved");
    drop(conn);

    let mut by_id = HashMap::new();
    let mut by_oid: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_pack_offset = HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        by_id.insert(n.id, i);
        if !n.oid.is_empty() {
            by_oid.entry(n.oid.clone()).or_default().push(i);
        }
        if let (Some(p), Some(o)) = (n.pack_id, n.pack_offset) {
            by_pack_offset.insert((p, o), i);
        }
    }

    let mut env = Env {
        nodes,
        by_id,
        by_oid,
        by_pack_offset,
        raw,
        resolved_data,
        visited: HashSet::new(),
        depth: 0,
        budget_total,
        budget_single,
        max_depth,
        used_total,
        base_stack: Vec::new(),
        final_kind: HashMap::new(),
        steps: HashMap::new(),
        step_meta: HashMap::new(),
        depths: HashMap::new(),
        db,
    };

    let mut report = RecomputeReport::default();
    let order: Vec<i64> = env.nodes.iter().map(|n| n.id).collect();
    for id in order {
        if env.visited.contains(&id) {
            continue;
        }
        resolve_id(&mut env, id);
    }

    let mut conn = db.0.lock().unwrap();
    let tx = conn.transaction().unwrap();
    for n in &env.nodes {
        if n.status == "resolved" {
            report.resolved += 1;
        } else if n.status == "blocked" {
            report.blocked += 1;
        } else if n.status == "error" {
            report.errored += 1;
        } else if n.status == "paused" {
            report.paused += 1;
        }
    }

    let ids: Vec<i64> = env.nodes.iter().map(|n| n.id).collect();
    for id in ids {
        persist_node(&tx, &mut env, id);
    }
    tx.execute(
        "UPDATE kv SET v=?1 WHERE k='budget_used_total_bytes'",
        params![env.used_total.to_string()],
    )
    .unwrap();
    tx.commit().unwrap();

    report.affected_reset = 0;
    report
}

pub fn resume(db: &Db) -> RecomputeReport {
    {
        let conn = db.0.lock().unwrap();
        conn.execute(
            "UPDATE nodes SET status='pending',error_code=NULL,error_note=NULL
             WHERE status='paused'",
            [],
        )
        .unwrap();
        clear_steps_for_pending(&conn);
    }
    incremental(db)
}

fn clear_steps_for_pending(conn: &rusqlite::Connection) {
    conn.execute(
        "DELETE FROM steps WHERE node_id IN (SELECT id FROM nodes WHERE status='pending')",
        [],
    )
    .unwrap();
}

fn load_nodes(conn: &rusqlite::Connection) -> Vec<NodeRec> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id,n.oid,n.kind,n.source_id,n.pack_id,n.pack_offset,n.base_offset,
                    n.base_oid,n.status,COALESCE(n.error_code,''),n.pinned,s.filename
             FROM nodes n JOIN sources s ON s.id=n.source_id
             ORDER BY n.id",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok(NodeRec {
            id: r.get(0)?,
            oid: r.get(1)?,
            kind: r.get(2)?,
            source_id: r.get(3)?,
            pack_id: r.get(4)?,
            pack_offset: r.get(5)?,
            base_offset: r.get(6)?,
            base_oid: r.get::<_, Option<String>>(7)?,
            status: r.get(8)?,
            error_code: {
                let v: String = r.get(9)?;
                if v.is_empty() { None } else { Some(v) }
            },
            pinned: r.get::<_, i64>(10)? != 0,
            filename: r.get(11)?,
        })
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

fn load_stage(conn: &rusqlite::Connection, stage: &str) -> HashMap<i64, Vec<u8>> {
    let mut out = HashMap::new();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT node_id,data FROM objects WHERE stage='{}'",
            stage
        ))
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap();
    for row in rows {
        let (id, data) = row.unwrap();
        out.insert(id, data);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Resolved,
    Blocked,
    Error(ErrCode),
    Paused(ErrCode),
}

fn status_outcome(n: &NodeRec) -> Option<Outcome> {
    Some(match n.status.as_str() {
        "resolved" => Outcome::Resolved,
        "blocked" => Outcome::Blocked,
        "paused" => Outcome::Paused(ErrCode::TotalBudget),
        "error" => Outcome::Error(n.error_code.as_deref().and_then(ErrCode::parse).unwrap_or(ErrCode::BadDelta)),
        _ => return None,
    })
}

fn resolve_id(env: &mut Env, id: i64) -> Outcome {
    let idx = env.by_id[&id];
    if let Some(o) = status_outcome(&env.nodes[idx].clone()) {
        return o;
    }
    if env.base_stack.contains(&id) {
        let chain = env
            .base_stack
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        set_status(env, id, ObjStatus::Error, ErrCode::DeltaCycle,
            Some(format!("delta chain forms a cycle: {} -> {}", chain, id)));
        return Outcome::Error(ErrCode::DeltaCycle);
    }
    if env.depth >= env.max_depth {
        set_status(env, id, ObjStatus::Paused, ErrCode::DepthLimit,
            Some(format!("delta depth limit {} reached", env.max_depth)));
        return Outcome::Paused(ErrCode::DepthLimit);
    }

    let rec = env.nodes[idx].clone();
    let t = kind_of(&rec.kind);
    if !t.is_delta() {
        let payload = match env.raw.get(&id) {
            Some(p) => p.clone(),
            None => {
                set_status(env, id, ObjStatus::Error, ErrCode::CorruptZlib,
                    Some("raw payload missing".into()));
                return Outcome::Error(ErrCode::CorruptZlib);
            }
        };
        if payload.len() as u64 > env.budget_single {
            set_status(env, id, ObjStatus::Paused, ErrCode::SingleBudget,
                Some(format!("object {} bytes exceeds per-object budget", payload.len())));
            return Outcome::Paused(ErrCode::SingleBudget);
        }
        if env.used_total + payload.len() as u64 > env.budget_total {
            set_status(env, id, ObjStatus::Paused, ErrCode::TotalBudget,
                Some("total expansion budget exhausted before object materialization".into()));
            return Outcome::Paused(ErrCode::TotalBudget);
        }
        let base_t = t.base_type().unwrap();
        let computed = git_oid(base_t, &payload);
        env.used_total += payload.len() as u64;
        env.depths.insert(id, 0);
        env.final_kind.insert(id, base_t);
        env.resolved_data.insert(id, payload);
        env.visited.insert(id);
        let note: Option<String>;
        if !rec.oid.is_empty() && computed != rec.oid {
            note = Some(format!(
                "recomputed oid {} != declared {}",
                computed, rec.oid
            ));
            set_status_full(env, id, ObjStatus::Error, Some(ErrCode::OidMismatch), note.clone(),
                Some(computed), Some(base_t));
            return Outcome::Error(ErrCode::OidMismatch);
        }
        if rec.oid.is_empty() {
            set_resolved(env, id, computed, base_t);
        } else {
            set_resolved(env, id, rec.oid.clone(), base_t);
        }
        Outcome::Resolved
    } else {
        env.base_stack.push(id);
        env.depth += 1;
        let result = resolve_delta(env, idx);
        env.depth -= 1;
        env.base_stack.pop();
        result
    }
}

fn candidate_indices(env: &Env, oid: &str) -> Vec<usize> {
    let Some(list) = env.by_oid.get(oid) else {
        return Vec::new();
    };
    let mut v: Vec<usize> = list.iter().copied().collect();
    v.sort_by(|&a, &b| {
        let na = &env.nodes[a];
        let nb = &env.nodes[b];
        nb.pinned
            .cmp(&na.pinned)
            .then_with(|| na.filename.cmp(&nb.filename))
            .then_with(|| na.pack_offset.unwrap_or(-1).cmp(&nb.pack_offset.unwrap_or(-1)))
            .then_with(|| na.id.cmp(&nb.id))
    });
    v
}

fn set_status(
    env: &mut Env,
    id: i64,
    status: ObjStatus,
    code: ErrCode,
    note: Option<String>,
) {
    set_status_full(env, id, status, Some(code), note, None, None);
}

fn set_status_full(
    env: &mut Env,
    id: i64,
    status: ObjStatus,
    code: Option<ErrCode>,
    note: Option<String>,
    _computed_oid: Option<String>,
    final_kind: Option<ObjType>,
) {
    let idx = env.by_id[&id];
    env.nodes[idx].status = status.name().to_string();
    env.nodes[idx].error_code = code.map(|c| c.name().to_string());
    if let Some(k) = final_kind {
        env.final_kind.insert(id, k);
    }
    if let Some(msg) = note {
        record_evidence(env, id, status, code, msg);
    }
    env.visited.insert(id);
}

fn set_resolved(env: &mut Env, id: i64, oid: String, kind: ObjType) {
    let idx = env.by_id[&id];
    env.nodes[idx].status = "resolved".to_string();
    env.nodes[idx].error_code = None;
    if env.nodes[idx].oid.is_empty() {
        env.nodes[idx].oid = oid.clone();
        env.by_oid.entry(oid.clone()).or_default().push(idx);
    } else if env.nodes[idx].oid != oid {
        // declared mismatch handled earlier
    }
    env.final_kind.insert(id, kind);
    env.visited.insert(id);
}

fn record_evidence(
    env: &mut Env,
    node_id: i64,
    status: ObjStatus,
    code: Option<ErrCode>,
    msg: String,
) {
    let level = match status {
        ObjStatus::Error => "error",
        ObjStatus::Paused => "warning",
        ObjStatus::Blocked => "warning",
        _ => "info",
    };
    env.db.0.lock().unwrap().execute(
        "INSERT INTO evidence(node_id,level,code,message) VALUES(?1,?2,?3,?4)",
        params![
            node_id,
            level,
            code.map(|c| c.name()).unwrap_or("info"),
            msg
        ],
    ).unwrap();
}

fn resolve_delta(env: &mut Env, idx: usize) -> Outcome {
    let id = env.nodes[idx].id;
    let rec = env.nodes[idx].clone();

    let base_idx: usize = match rec.kind.as_str() {
        "ofs-delta" => {
            let (Some(pack), Some(off)) = (rec.pack_id, rec.base_offset) else {
                set_status(env, id, ObjStatus::Error, ErrCode::BadOffset,
                    Some("ofs-delta missing base offset".into()));
                return Outcome::Error(ErrCode::BadOffset);
            };
            match env.by_pack_offset.get(&(pack, off)).copied() {
                Some(b) => b,
                None => {
                    set_status(env, id, ObjStatus::Blocked, ErrCode::MissingBase,
                        Some(format!("ofs base at offset {} not present in pack {}", off, pack)));
                    return Outcome::Blocked;
                }
            }
        }
        "ref-delta" => {
            let Some(oid) = rec.base_oid.clone() else {
                set_status(env, id, ObjStatus::Error, ErrCode::BadHeader,
                    Some("ref-delta without base oid".into()));
                return Outcome::Error(ErrCode::BadHeader);
            };
            let candidates = candidate_indices(env, &oid);
            if candidates.is_empty() {
                set_status(env, id, ObjStatus::Blocked, ErrCode::MissingBase,
                    Some(format!("ref base {} not imported yet", oid)));
                return Outcome::Blocked;
            }
            let mut chosen = None;
            for &c in &candidates {
                let cid = env.nodes[c].id;
                if env.base_stack.contains(&cid) {
                    continue;
                }
                let outcome = resolve_id(env, cid);
                if outcome == Outcome::Resolved {
                    chosen = Some(c);
                    break;
                }
            }
            match chosen {
                Some(c) => c,
                None => {
                    let in_cycle = candidates.iter().any(|c| {
                        env.base_stack.contains(&env.nodes[*c].id)
                    });
                    if in_cycle {
                        set_status(env, id, ObjStatus::Error, ErrCode::DeltaCycle,
                            Some(format!("delta base {} participates in a cycle", oid)));
                        Outcome::Error(ErrCode::DeltaCycle)
                    } else {
                        set_status(env, id, ObjStatus::Blocked, ErrCode::MissingBase,
                            Some(format!("base {} has no resolvable candidate", oid)));
                        Outcome::Blocked
                    };
                    return if in_cycle {
                        Outcome::Error(ErrCode::DeltaCycle)
                    } else {
                        Outcome::Blocked
                    };
                }
            }
        }
        other => panic!("not a delta: {}", other),
    };

    let base_id = env.nodes[base_idx].id;
    let base_outcome = resolve_id(env, base_id);
    if base_outcome != Outcome::Resolved {
        return match base_outcome {
            Outcome::Blocked => {
                set_status(env, id, ObjStatus::Blocked, ErrCode::MissingBase,
                    Some(format!("base node {} not resolved", base_id)));
                Outcome::Blocked
            }
            Outcome::Paused(c) => {
                set_status(env, id, ObjStatus::Paused, c,
                    Some("paused while waiting for budget-limited base".into()));
                Outcome::Paused(c)
            }
            Outcome::Error(c) => {
                set_status(env, id, ObjStatus::Blocked, c,
                    Some(format!("base node {} failed: {}", base_id, c.name())));
                Outcome::Blocked
            }
            Outcome::Resolved => unreachable!(),
        };
    }

    let base_data = env.resolved_data.get(&base_id).cloned().unwrap();
    let delta = env.raw.get(&id).cloned().unwrap();

    let (target_size, instr_start) = match crate::gitobj::read_varint(&delta, 0)
        .and_then(|(bs, p)| {
            if bs as usize != base_data.len() {
                return None;
            }
            crate::gitobj::read_varint(&delta, p).map(|(r, p2)| (r, p2))
        }) {
        Some(v) => v,
        None => {
            set_status(env, id, ObjStatus::Error, ErrCode::BadDelta,
                Some("delta header base/result size invalid".into()));
            return Outcome::Error(ErrCode::BadDelta);
        }
    };

    if target_size > env.budget_single {
        set_status(env, id, ObjStatus::Paused, ErrCode::SingleBudget,
            Some(format!("delta result {} exceeds per-object budget", target_size)));
        return Outcome::Paused(ErrCode::SingleBudget);
    }
    if env.used_total + target_size > env.budget_total {
        set_status(env, id, ObjStatus::Paused, ErrCode::TotalBudget,
            Some("total expansion budget exhausted before applying delta".into()));
        return Outcome::Paused(ErrCode::TotalBudget);
    }

    match apply_delta(&base_data, &delta) {
        Ok((out, report)) => {
            let computed = {
                let base_kind = *env.final_kind.get(&base_id).unwrap();
                let oid = git_oid(base_kind, &out);
                env.used_total += out.len() as u64;
                let d = env.depths.get(&base_id).copied().unwrap_or(0) + 1;
                env.depths.insert(id, d);
                env.resolved_data.insert(id, out.clone());
                env.final_kind.insert(id, base_kind);
                env.steps.insert(
                    id,
                    report.ops.iter().map(|(_, r)| r.clone()).collect(),
                );
                env.step_meta.insert(id, (instr_start as i64, report.instr_end as i64));
                env.visited.insert(id);
                (oid, base_kind)
            };
            if !rec.oid.is_empty() && computed.0 != rec.oid {
                set_status_full(env, id, ObjStatus::Error, Some(ErrCode::OidMismatch),
                    Some(format!("recomputed oid {} != declared {}", computed.0, rec.oid)),
                    None, Some(computed.1));
                return Outcome::Error(ErrCode::OidMismatch);
            }
            let oid = if rec.oid.is_empty() { computed.0.clone() } else { rec.oid.clone() };
            set_resolved(env, id, oid, computed.1);
            Outcome::Resolved
        }
        Err(e) => {
            set_status(env, id, ObjStatus::Error, ErrCode::BadDelta,
                Some(format!("delta instruction failure: {:?}", e)));
            Outcome::Error(ErrCode::BadDelta)
        }
    }
}

fn persist_node(tx: &rusqlite::Transaction, env: &mut Env, id: i64) {
    let idx = env.by_id[&id];
    let n = env.nodes[idx].clone();
    let final_kind = env.final_kind.get(&id).map(|k| k.name());
    tx.execute(
        "UPDATE nodes SET status=?1,error_code=?2,error_note=?3,
         final_kind=COALESCE(?4,final_kind),
         resolved_kind=COALESCE(?4,resolved_kind),
         oid=CASE WHEN oid='' THEN ?5 ELSE oid END,
         resolve_depth=?6
         WHERE id=?7",
        params![
            n.status,
            n.error_code,
            tx.query_row(
                "SELECT message FROM evidence WHERE node_id=?1
                 ORDER BY id DESC LIMIT 1",
                params![id],
                |r| r.get::<_, String>(0)
            )
            .ok()
            .unwrap_or_default(),
            final_kind,
            n.oid,
            env.depths.get(&id).copied().unwrap_or(0) as i64,
            id
        ],
    )
    .unwrap();

    if n.status == "resolved" {
        if let Some(data) = env.resolved_data.get(&id) {
            let kind = final_kind.unwrap_or("blob");
            tx.execute(
                "INSERT INTO objects(oid,node_id,kind,data,stage)
                 VALUES(?1,?2,?3,?4,'resolved')
                 ON CONFLICT(oid,node_id,stage) DO UPDATE SET data=excluded.data,kind=excluded.kind",
                params![n.oid, id, kind, data],
            )
            .unwrap();
        }
    }

    if let Some(ranges) = env.steps.get(&id) {
        tx.execute("DELETE FROM steps WHERE node_id=?1", params![id]).unwrap();
        let (instr_start, instr_end) = env.step_meta.get(&id).copied().unwrap_or((0, 0));
        let mut in_len = 0i64;
        let mut out_len = 0i64;
        for (seq, r) in ranges.iter().enumerate() {
            let note = serde_json::json!({"start":r.start,"end":r.end}).to_string();
            tx.execute(
                "INSERT INTO steps(node_id,seq,base_node,base_oid,instr_start,instr_end,
                 in_len,out_len,check_ok,note)
                 VALUES(?1,?2,?3,?4,?5,?6,0,0,1,?7)",
                params![
                    id,
                    seq as i64,
                    base_node_id(env, id),
                    base_oid_for(env, id),
                    instr_start,
                    instr_end,
                    note
                ],
            )
            .unwrap();
            let _ = (&mut in_len, &mut out_len);
        }
    }
}

fn base_node_id(env: &Env, id: i64) -> Option<i64> {
    let idx = env.by_id[&id];
    let n = &env.nodes[idx];
    if let Some(off) = n.base_offset {
        if let Some(p) = n.pack_id {
            return env.by_pack_offset.get(&(p, off)).map(|i| env.nodes[*i].id);
        }
    }
    if let Some(oid) = &n.base_oid {
        if let Some(list) = env.by_oid.get(oid) {
            return list
                .iter()
                .find(|&&i| env.nodes[i].status == "resolved")
                .map(|&i| env.nodes[i].id)
                .or_else(|| list.first().map(|&i| env.nodes[i].id));
        }
    }
    None
}

fn base_oid_for(env: &Env, id: i64) -> Option<String> {
    let bid = base_node_id(env, id)?;
    let idx = env.by_id[&bid];
    Some(env.nodes[idx].oid.clone())
}

pub fn rebuild_edges(db: &Db) {
    let mut conn = db.0.lock().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("DELETE FROM edges", []).unwrap();
    let mut stmt = tx
        .prepare(
            "SELECT id,pack_id,base_offset,base_oid FROM nodes
             WHERE kind IN ('ofs-delta','ref-delta')",
        )
        .unwrap();
    let deltas: Vec<(i64, Option<i64>, Option<i64>, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    drop(stmt);

    for (id, pack_id, base_offset, base_oid) in deltas {
        if let (Some(p), Some(off)) = (pack_id, base_offset) {
            let target: Option<i64> = tx
                .query_row(
                    "SELECT id FROM nodes WHERE pack_id=?1 AND pack_offset=?2",
                    params![p, off],
                    |r| r.get(0),
                )
                .ok();
            let oid = target
                .and_then(|t| {
                    tx.query_row("SELECT oid FROM nodes WHERE id=?1", params![t], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                })
                .unwrap_or_default();
            tx.execute(
                "INSERT OR IGNORE INTO edges(from_node,to_oid,to_node,kind) VALUES(?1,?2,?3,'ofs')",
                params![id, oid, target],
            )
            .unwrap();
        }
        if let Some(oid) = base_oid {
            let target: Option<i64> = tx
                .query_row(
                    "SELECT id FROM nodes WHERE oid=?1 AND status='resolved' ORDER BY pinned DESC LIMIT 1",
                    params![oid],
                    |r| r.get(0),
                )
                .ok();
            tx.execute(
                "INSERT OR IGNORE INTO edges(from_node,to_oid,to_node,kind) VALUES(?1,?2,?3,'ref')",
                params![id, oid, target],
            )
            .unwrap();
        }
    }
    tx.commit().unwrap();
}
