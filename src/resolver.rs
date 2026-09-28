use crate::db::Store;
use crate::gitcore::*;
use crate::model::{Budgets, ObjType};
use crate::parser;
use rusqlite::params;
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct CandidateRow {
    pub id: i64,
    pub source_id: i64,
    pub origin: String,
    pub declared_type: String,
    pub declared_size: i64,
    pub parse_status: String,
    pub oid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub from_cid: i64,
    pub to_cid: Option<i64>,
    pub to_oid: Option<String>,
    pub kind: String,
}

fn load_candidates(store: &Store) -> HashMap<i64, CandidateRow> {
    let db = store.conn.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id, source_id, origin, declared_type, declared_size, parse_status, oid
             FROM candidates",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(CandidateRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                origin: r.get(2)?,
                declared_type: r.get(3)?,
                declared_size: r.get(4)?,
                parse_status: r.get(5)?,
                oid: r.get(6)?,
            })
        })
        .unwrap();
    let mut map = HashMap::new();
    for r in rows.flatten() {
        map.insert(r.id, r);
    }
    map
}

fn load_edges(store: &Store) -> Vec<EdgeRow> {
    let db = store.conn.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT from_cid, to_cid, to_oid, kind FROM edges")
        .unwrap();
    stmt.query_map([], |r| {
        Ok(EdgeRow {
            from_cid: r.get(0)?,
            to_cid: r.get(1)?,
            to_oid: r.get(2)?,
            kind: r.get(3)?,
        })
    })
    .unwrap()
    .flatten()
    .collect()
}

#[derive(Clone)]
struct Memo {
    status: String,
    object_type: Option<String>,
    oid: Option<String>,
    content: Option<Vec<u8>>,
    reason: Option<String>,
    blocking: Vec<i64>,
    budget: Option<String>,
    steps: Vec<StepRec>,
}

#[derive(Clone)]
struct StepRec {
    step_idx: i64,
    base_candidate_id: Option<i64>,
    base_kind: String,
    instr_start: i64,
    instr_end: i64,
    in_len: i64,
    out_len: i64,
    declared_target_size: i64,
    size_match: bool,
    ok: bool,
    note: Option<String>,
}

pub struct RunReport {
    pub resolved_ok: usize,
    pub bad: usize,
    pub missing: usize,
    pub cycle: usize,
    pub paused: usize,
    pub total_expand_used: u64,
    pub budget_hit: bool,
}

struct Engine<'a> {
    store: &'a Store,
    cands: HashMap<i64, CandidateRow>,
    base_of: HashMap<i64, Option<i64>>,
    missing_oid_of: HashMap<i64, String>,
    branch_id: i64,
    budgets: Budgets,
    memo: HashMap<i64, Memo>,
    active: HashSet<i64>,
    total_expand_used: u64,
    total_budget: u64,
}

fn object_type_name(declared: &str) -> Option<&'static str> {
    match declared {
        "commit" => Some("commit"),
        "tree" => Some("tree"),
        "blob" => Some("blob"),
        "tag" => Some("tag"),
        _ => None,
    }
}

impl<'a> Engine<'a> {
    fn pinned_base(&self, oid: &str) -> Option<i64> {
        let db = self.store.conn.lock().unwrap();
        db.query_row(
            "SELECT candidate_id FROM pins WHERE branch_id=?1 AND oid=?2",
            params![self.branch_id, oid],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    fn resolve(&mut self, cid: i64) -> Memo {
        if let Some(m) = self.memo.get(&cid) {
            return m.clone();
        }
        if self.active.contains(&cid) {
            let chain: Vec<i64> = self.active.iter().copied().collect();
            return Memo {
                status: "cycle".into(),
                object_type: None,
                oid: None,
                content: None,
                reason: Some(format!("delta cycle detected at candidate {}", cid)),
                blocking: chain,
                budget: None,
                steps: Vec::new(),
            };
        }
        self.active.insert(cid);
        let memo = self.compute(cid);
        self.active.remove(&cid);
        self.memo.insert(cid, memo.clone());
        memo
    }

    fn fail(&self, status: &str, reason: String, blocking: Vec<i64>) -> Memo {
        Memo {
            status: status.into(),
            object_type: None,
            oid: None,
            content: None,
            reason: Some(reason),
            blocking,
            budget: None,
            steps: Vec::new(),
        }
    }

    fn compute(&mut self, cid: i64) -> Memo {
        let cand = match self.cands.get(&cid) {
            Some(c) => c.clone(),
            None => return self.fail("bad", format!("candidate {} vanished", cid), vec![cid]),
        };
        if cand.parse_status == "size_spoof" || cand.parse_status == "corrupt" {
            return self.fail(
                "bad",
                format!("candidate {} parse isolation: {}", cid, cand.parse_status),
                vec![cid],
            );
        }
        if cand.parse_status == "bad_ofs" {
            return self.fail(
                "bad",
                format!("candidate {} ofs distance out of bounds", cid),
                vec![cid],
            );
        }
        if cand.declared_type == "ofs_delta" || cand.declared_type == "ref_delta" {
            self.compute_delta(cid, &cand)
        } else {
            self.compute_full(&cand)
        }
    }

    fn compute_full(&mut self, cand: &CandidateRow) -> Memo {
        let type_name = match object_type_name(&cand.declared_type) {
            Some(t) => t,
            None => {
                return self.fail(
                    "bad",
                    format!("candidate {} unknown type {}", cand.id, cand.declared_type),
                    vec![cand.id],
                )
            }
        };
        let content = match self.store.read_payload(cand.id) {
            Ok(c) => c,
            Err(e) => {
                return self.fail(
                    "bad",
                    format!("candidate {} payload missing: {}", cand.id, e),
                    vec![cand.id],
                )
            }
        };
        if content.len() as u64 > self.budgets.max_object_bytes {
            return Memo {
                status: "paused".into(),
                object_type: Some(type_name.into()),
                oid: None,
                content: None,
                reason: Some(format!(
                    "object bytes {} exceeds per-object budget {}",
                    content.len(),
                    self.budgets.max_object_bytes
                )),
                blocking: vec![cand.id],
                budget: Some(
                    json!({
                        "need_bytes": content.len(),
                        "max_object_bytes": self.budgets.max_object_bytes,
                        "depth": 0,
                    })
                    .to_string(),
                ),
                steps: Vec::new(),
            };
        }
        let calc = git_oid(type_name, &content);
        let oid_match = cand.oid.as_deref() == Some(calc.as_str())
            || idx_oid_of(self.store, cand.id).as_deref() == Some(calc.as_str());
        Memo {
            status: "ok".into(),
            object_type: Some(type_name.into()),
            oid: Some(calc),
            content: Some(content),
            reason: if oid_match {
                None
            } else {
                Some("recomputed object id differs from pack/index name".into())
            },
            blocking: Vec::new(),
            budget: None,
            steps: Vec::new(),
        }
    }
}

fn idx_oid_of(store: &Store, cid: i64) -> Option<String> {
    let db = store.conn.lock().unwrap();
    db.query_row("SELECT idx_oid FROM candidates WHERE id=?1", params![cid], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

impl<'a> Engine<'a> {
    fn base_candidate(&self, cid: i64) -> Result<i64, String> {
        if let Some(opt) = self.base_of.get(&cid) {
            return opt.ok_or_else(|| {
                self.missing_oid_of
                    .get(&cid)
                    .cloned()
                    .unwrap_or_else(|| "external base missing".into())
            });
        }
        Err(format!("no edge for candidate {}", cid))
    }

    fn compute_delta(&mut self, leaf: i64, leaf_cand: &CandidateRow) -> Memo {
        // Walk to the bottom of the chain, detecting cycles via active set.
        let mut chain_ids: Vec<i64> = Vec::new();
        let mut cur = leaf;
        loop {
            if let Some(m) = self.memo.get(&cur) {
                if m.status != "ok" {
                    return self.propagate(leaf, m.clone());
                }
                break;
            }
            if chain_ids.contains(&cur) {
                let reason = format!(
                    "delta cycle: {}",
                    chain_ids
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                );
                return self.fail("cycle", reason, chain_ids);
            }
            chain_ids.push(cur);
            let base = match self.base_candidate(cur) {
                Ok(b) => b,
                Err(oid_or_msg) => {
                    return self.fail(
                        "missing",
                        format!("candidate {} needs unavailable base: {}", cur, oid_or_msg),
                        chain_ids,
                    );
                }
            };
            cur = base;
        }

        // Resolve bottom-most unknown base via the recursive memo.
        let mut current_cid = cur;
        let mut current_content;
        let mut object_type;
        if let Some(m) = self.memo.get(&cur) {
            current_content = m.content.clone().unwrap();
            object_type = m.object_type.clone();
        } else {
            let m = self.resolve(cur);
            if m.status != "ok" {
                return self.propagate(leaf, m);
            }
            current_content = m.content.unwrap();
            object_type = m.object_type;
        }

        let depth_total = chain_ids.len();
        if depth_total as u32 > self.budgets.max_depth {
            return self.pause(
                leaf_cand,
                format!(
                    "delta depth {} exceeds max {}",
                    depth_total, self.budgets.max_depth
                ),
                chain_ids,
                json!({"depth": depth_total, "max_depth": self.budgets.max_depth}).to_string(),
            );
        }

        // Apply deltas from base outward: chain order is leaf..root, so reverse.
        let mut steps: Vec<StepRec> = Vec::new();
        let mut blocking: Vec<i64> = chain_ids.clone();
        let mut step_idx = 0i64;
        let deltas: Vec<i64> = chain_ids.iter().rev().copied().collect();
        for &dcid in &deltas {
            let delta_cand = self.cands.get(&dcid).cloned();
            let delta_bytes = match self.store.read_payload(dcid) {
                Ok(d) => d,
                Err(e) => {
                    return self.fail(
                        "bad",
                        format!("delta candidate {} payload: {}", dcid, e),
                        blocking,
                    );
                }
            };
            let header = match read_delta_header(&delta_bytes) {
                Ok(h) => h,
                Err(e) => {
                    return self.fail(
                        "bad",
                        format!("delta candidate {} header unreadable: {}", dcid, e),
                        blocking,
                    );
                }
            };
            if header.base_size != current_content.len() as u64 {
                return self.fail(
                    "bad",
                    format!(
                        "delta {} base size spoof: header {} actual {}",
                        dcid,
                        header.base_size,
                        current_content.len()
                    ),
                    blocking,
                );
            }
            if header.result_size > self.budgets.max_object_bytes {
                return self.pause(
                    leaf_cand,
                    format!(
                        "target bytes {} exceeds per-object budget {}",
                        header.result_size, self.budgets.max_object_bytes
                    ),
                    blocking,
                    json!({
                        "target_bytes": header.result_size,
                        "max_object_bytes": self.budgets.max_object_bytes,
                        "depth": step_idx + 1,
                    })
                    .to_string(),
                );
            }
            if header.result_size > self.budgets.max_ratio.saturating_mul(current_content.len().max(1) as u64)
                && header.result_size > 64 * 1024
            {
                return self.pause(
                    leaf_cand,
                    format!(
                        "target/base ratio {}:1 exceeds max {}:1",
                        header.result_size / current_content.len().max(1) as u64,
                        self.budgets.max_ratio
                    ),
                    blocking,
                    json!({
                        "target_bytes": header.result_size,
                        "base_bytes": current_content.len(),
                        "max_ratio": self.budgets.max_ratio,
                    })
                    .to_string(),
                );
            }
            if self.total_expand_used + header.result_size > self.total_budget {
                return self.pause(
                    leaf_cand,
                    format!(
                        "total expansion budget {} exhausted ({} used, {} requested)",
                        self.total_budget, self.total_expand_used, header.result_size
                    ),
                    blocking,
                    json!({
                        "total_used": self.total_expand_used,
                        "total_budget": self.total_budget,
                        "requested": header.result_size,
                    })
                    .to_string(),
                );
            }
            let outcome = apply_delta(
                &current_content,
                &delta_bytes,
                self.budgets.max_object_bytes,
            );
            let applied = match outcome {
                Ok(o) => o,
                Err(e) => {
                    steps.push(StepRec {
                        step_idx,
                        base_candidate_id: Some(current_cid),
                        base_kind: base_kind_of(self.store, dcid),
                        instr_start: header.header_len as i64,
                        instr_end: delta_bytes.len() as i64,
                        in_len: current_content.len() as i64,
                        out_len: 0,
                        declared_target_size: header.result_size as i64,
                        size_match: false,
                        ok: false,
                        note: Some(e.message()),
                    });
                    return self.fail_with_steps(
                        "bad",
                        format!("delta candidate {} apply failed: {}", dcid, e.message()),
                        blocking,
                        steps,
                    );
                }
            };
            self.total_expand_used += applied.output.len() as u64;
            let size_match = applied.output.len() as u64 == header.result_size;
            steps.push(StepRec {
                step_idx,
                base_candidate_id: Some(current_cid),
                base_kind: base_kind_of(self.store, dcid),
                instr_start: applied.instr_start as i64,
                instr_end: applied.instr_end as i64,
                in_len: current_content.len() as i64,
                out_len: applied.output.len() as i64,
                declared_target_size: header.result_size as i64,
                size_match,
                ok: true,
                note: delta_cand
                    .as_ref()
                    .and_then(|c| c.oid.clone())
                    .map(|o| format!("recomputed chain toward {}", &o[..7.min(o.len())])),
            });
            current_content = applied.output;
            current_cid = dcid;
            step_idx += 1;
        }

        // Object type inherits from the chain base.
        let type_name = match object_type {
            Some(t) => t,
            None => {
                return self.fail_with_steps(
                    "bad",
                    format!("delta chain {} has no typed base", leaf),
                    blocking,
                    steps,
                );
            }
        };
        if ObjType::parse(&type_name).is_none() {
            return self.fail_with_steps(
                "bad",
                format!("chain base produced unknown type {}", type_name),
                blocking,
                steps,
            );
        }
        let calc = git_oid(&type_name, &current_content);
        let expected = leaf_cand
            .oid
            .clone()
            .or_else(|| idx_oid_of(self.store, leaf_cand.id));
        let oid_match = expected.as_deref() == Some(calc.as_str());
        Memo {
            status: "ok".into(),
            object_type: Some(type_name),
            oid: Some(calc.clone()),
            content: Some(current_content),
            reason: if oid_match {
                None
            } else {
                Some(format!(
                    "recomputed oid {} differs from declared {}",
                    calc,
                    expected.unwrap_or_else(|| "<none>".into())
                ))
            },
            blocking: Vec::new(),
            budget: None,
            steps,
        }
    }

    fn propagate(&self, _leaf: i64, base_memo: Memo) -> Memo {
        let mut blocking = base_memo.blocking.clone();
        blocking.push(_leaf);
        let status = match base_memo.status.as_str() {
            "paused" => "blocked_paused".to_string(),
            "missing" => "missing".to_string(),
            "cycle" => "cycle".to_string(),
            _ => "bad".to_string(),
        };
        Memo {
            status,
            object_type: None,
            oid: None,
            content: None,
            reason: base_memo.reason,
            blocking,
            budget: base_memo.budget,
            steps: Vec::new(),
        }
    }

    fn pause(
        &self,
        cand: &CandidateRow,
        reason: String,
        blocking: Vec<i64>,
        budget: String,
    ) -> Memo {
        let _ = cand;
        Memo {
            status: "paused".into(),
            object_type: None,
            oid: None,
            content: None,
            reason: Some(reason),
            blocking,
            budget: Some(budget),
            steps: Vec::new(),
        }
    }

    fn fail_with_steps(
        &self,
        status: &str,
        reason: String,
        blocking: Vec<i64>,
        steps: Vec<StepRec>,
    ) -> Memo {
        Memo {
            status: status.into(),
            object_type: None,
            oid: None,
            content: None,
            reason: Some(reason),
            blocking,
            budget: None,
            steps,
        }
    }
}

fn base_kind_of(store: &Store, delta_cid: i64) -> String {
    let db = store.conn.lock().unwrap();
    db.query_row(
        "SELECT kind FROM edges WHERE from_cid=?1 ORDER BY id LIMIT 1",
        params![delta_cid],
        |r| r.get(0),
    )
    .unwrap_or_else(|_| "unknown".to_string())
}

fn build_base_map(
    store: &Store,
    branch_id: i64,
    cands: &HashMap<i64, CandidateRow>,
) -> (HashMap<i64, Option<i64>>, HashMap<i64, String>) {
    let db = store.conn.lock().unwrap();
    let mut base_of = HashMap::new();
    let mut missing_oid = HashMap::new();
    let mut stmt = db
        .prepare("SELECT from_cid, to_cid, to_oid FROM edges")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap();
    for row in rows.flatten() {
        let (from, to, to_oid) = row;
        let mut chosen = to;
        if chosen.is_none() {
            if let Some(oid) = &to_oid {
                // Pin override first.
                if let Some(pin_cid) = db
                    .query_row(
                        "SELECT candidate_id FROM pins WHERE branch_id=?1 AND oid=?2",
                        params![branch_id, oid],
                        |r| r.get::<_, i64>(0),
                    )
                    .optional()
                    .ok()
                    .flatten()
                {
                    chosen = Some(pin_cid);
                }
            }
        }
        base_of.insert(from, chosen);
        if chosen.is_none() {
            if let Some(oid) = to_oid {
                missing_oid.insert(from, oid);
            } else {
                missing_oid.insert(from, "<ofs target missing>".into());
            }
        }
    }
    let _ = cands;
    (base_of, missing_oid)
}

fn clear_branch_state(store: &Store, branch_id: i64, cids: &[i64]) {
    let db = store.conn.lock().unwrap();
    for &cid in cids {
        db.execute(
            "DELETE FROM resolved WHERE branch_id=?1 AND candidate_id=?2",
            params![branch_id, cid],
        )
        .ok();
        db.execute(
            "DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2",
            params![branch_id, cid],
        )
        .ok();
        store.remove_resolved(branch_id, cid);
    }
}

fn persist(store: &Store, branch_id: i64, gen: i64, cid: i64, memo: &Memo) {
    let db = store.conn.lock().unwrap();
    let chain_json = serde_json::to_string(&memo.blocking).unwrap_or_else(|_| "[]".into());
    db.execute(
        "INSERT INTO resolved
         (branch_id, candidate_id, status, object_type, oid, out_size, oid_match,
          reason, blocking_chain, budget, gen)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(branch_id,candidate_id) DO UPDATE SET
           status=excluded.status, object_type=excluded.object_type, oid=excluded.oid,
           out_size=excluded.out_size, oid_match=excluded.oid_match, reason=excluded.reason,
           blocking_chain=excluded.blocking_chain, budget=excluded.budget, gen=excluded.gen",
        params![
            branch_id,
            cid,
            memo.status,
            memo.object_type,
            memo.oid,
            memo.content.as_ref().map(|c| c.len() as i64).unwrap_or(0),
            match memo.status.as_str() {
                "ok" => {
                    // oid_match conveyed via reason emptiness for deltas; recompute here is done
                    // by caller context. Store NULL unless reason absent is insufficient,
                    // so encode in reason. Keep simple: set based on reason.
                    Some(memo.reason.is_none() as i64)
                }
                _ => None::<i64>,
            },
            memo.reason,
            chain_json,
            memo.budget,
            gen,
        ],
    )
    .ok();
    db.execute(
        "DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2",
        params![branch_id, cid],
    )
    .ok();
    for st in &memo.steps {
        db.execute(
            "INSERT INTO delta_steps
             (branch_id, candidate_id, step_idx, base_candidate_id, base_kind,
              instr_start, instr_end, in_len, out_len, declared_target_size,
              size_match, ok, note)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                branch_id,
                cid,
                st.step_idx,
                st.base_candidate_id,
                st.base_kind,
                st.instr_start,
                st.instr_end,
                st.in_len,
                st.out_len,
                st.declared_target_size,
                st.size_match as i64,
                st.ok as i64,
                st.note,
            ],
        )
        .ok();
    }
    drop(db);
    if memo.status == "ok" {
        if let Some(content) = &memo.content {
            store.write_resolved(branch_id, cid, content).ok();
        }
    } else {
        store.remove_resolved(branch_id, cid);
    }
}

pub fn run_all(store: &Store, branch_id: i64, budgets: Budgets) -> RunReport {
    parser::link_ref_edges(store);
    let cands = load_candidates(store);
    let (base_of, missing_oid_of) = build_base_map(store, branch_id, &cands);
    let all_ids: Vec<i64> = cands.keys().copied().collect();
    clear_branch_state(store, branch_id, &all_ids);

    let mut engine = Engine {
        store,
        cands,
        base_of,
        missing_oid_of,
        branch_id,
        budgets,
        memo: HashMap::new(),
        active: HashSet::new(),
        total_expand_used: 0,
        total_budget: budgets.total_expand_bytes,
    };

    let mut report = RunReport {
        resolved_ok: 0,
        bad: 0,
        missing: 0,
        cycle: 0,
        paused: 0,
        total_expand_used: 0,
        budget_hit: false,
    };

    // Deterministic traversal order so candidate ordering never changes results.
    let mut ordered: Vec<i64> = engine.cands.keys().copied().collect();
    ordered.sort_unstable();
    for cid in ordered {
        let memo = engine.resolve(cid);
        persist(store, branch_id, 1, cid, &memo);
        match memo.status.as_str() {
            "ok" => report.resolved_ok += 1,
            "missing" => report.missing += 1,
            "cycle" => report.cycle += 1,
            "paused" | "blocked_paused" => report.paused += 1,
            _ => report.bad += 1,
        }
    }
    report.total_expand_used = engine.total_expand_used;
    report.budget_hit = report.paused > 0;
    report
}

/// Recompute only cid and every candidate whose chain depends on it.
pub fn recompute_affected(store: &Store, branch_id: i64, budgets: Budgets, seeds: &[i64]) -> RunReport {
    parser::link_ref_edges(store);
    let cands = load_candidates(store);
    let (base_of, missing_oid_of) = build_base_map(store, branch_id, &cands);

    // Reverse dependency closure.
    let mut dependents: HashSet<i64> = seeds.iter().copied().collect();
    let mut changed = true;
    while changed {
        changed = false;
        for (child, parent) in &base_of {
            if let Some(p) = parent {
                if dependents.contains(p) && dependents.insert(*child) {
                    changed = true;
                }
            }
        }
    }
    let affected: Vec<i64> = dependents.iter().copied().collect();
    clear_branch_state(store, branch_id, &affected);

    // Also drop memo-ish persisted statuses of dependents already cleared.
    let mut engine = Engine {
        store,
        cands,
        base_of,
        missing_oid_of,
        branch_id,
        budgets,
        memo: HashMap::new(),
        active: HashSet::new(),
        total_expand_used: 0,
        total_budget: budgets.total_expand_bytes,
    };

    let mut report = RunReport {
        resolved_ok: 0,
        bad: 0,
        missing: 0,
        cycle: 0,
        paused: 0,
        total_expand_used: 0,
        budget_hit: false,
    };
    let mut ordered = affected.clone();
    ordered.sort_unstable();
    for cid in ordered {
        let memo = engine.resolve(cid);
        persist(store, branch_id, 1, cid, &memo);
        match memo.status.as_str() {
            "ok" => report.resolved_ok += 1,
            "missing" => report.missing += 1,
            "cycle" => report.cycle += 1,
            "paused" | "blocked_paused" => report.paused += 1,
            _ => report.bad += 1,
        }
    }
    report.total_expand_used = engine.total_expand_used;
    report.budget_hit = report.paused > 0;
    report
}

/// Retry paused resolutions with a fresh (possibly larger) budget set.
pub fn retry_paused(store: &Store, branch_id: i64, budgets: Budgets) -> RunReport {
    let paused_ids: Vec<i64> = {
        let db = store.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT candidate_id FROM resolved
                 WHERE branch_id=?1 AND status IN ('paused','blocked_paused')",
            )
            .unwrap();
        stmt.query_map(params![branch_id], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    if paused_ids.is_empty() {
        return RunReport {
            resolved_ok: 0,
            bad: 0,
            missing: 0,
            cycle: 0,
            paused: 0,
            total_expand_used: 0,
            budget_hit: false,
        };
    }
    recompute_affected(store, branch_id, budgets, &paused_ids)
}
