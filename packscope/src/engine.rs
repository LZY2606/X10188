use crate::delta;
use crate::gitobj::{hash_object, preview, ObjType};
use crate::oid::Oid;
use crate::store::{Checkpoint, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSummary {
    pub branch_id: i64,
    pub resolved: usize,
    pub errors: usize,
    pub blocked: usize,
    pub paused: usize,
    pub used_bytes: i64,
    pub checkpoints: Vec<Checkpoint>,
}

struct Cand {
    cid: i64,
    source_id: String,
    source_kind: String,
    kind: ObjType,
    actual_oid: Option<Oid>,
    declared_oid: Option<Oid>,
    payload_key: Option<String>,
    declared_size: i64,
    parse_error: Option<String>,
    quality: i64,
    ofs_base: Option<i64>,
    ref_base_oid: Option<Oid>,
    ref_base_cid_pinned: Option<i64>,
}

pub struct Engine<'a> {
    store: &'a Store,
}

impl<'a> Engine<'a> {
    pub fn new(store: &'a Store) -> Self {
        Engine { store }
    }

    fn evidence(
        &self,
        branch: Option<i64>,
        cid: Option<i64>,
        oid: Option<&str>,
        level: &str,
        code: &str,
        msg: &str,
        ctx: &str,
    ) {
        let c = self.store.conn.lock().unwrap();
        c.execute(
            "INSERT INTO evidence(branch_id,cid,oid,level,code,message,context,created_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![branch, cid, oid, level, code, msg, ctx, crate::store::now_ms()],
        )
        .unwrap();
    }

    /// Load all candidates with their dependency info for one branch.
    fn load(&self, branch_id: i64) -> Vec<Cand> {
        let c = self.store.conn.lock().unwrap();
        let mut pins = BTreeMap::<String, i64>::new();
        {
            let mut st = c
                .prepare("SELECT oid, cid FROM pins WHERE branch_id=?1")
                .unwrap();
            for row in st
                .query_map(params![branch_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .unwrap()
            {
                let (o, cid) = row.unwrap();
                pins.insert(o, cid);
            }
        }
        let mut out = Vec::new();
        let mut st = c
            .prepare(
                "SELECT c.cid, c.source_id, c.source_kind, c.kind, c.actual_oid, c.declared_oid,
                        c.payload_key, c.declared_size, c.parse_error, c.quality
                 FROM candidates c",
            )
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, i64>(9)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (cid, source_id, source_kind, kind_s, actual, declared, payload_key,
                declared_size, parse_error, quality) = row.unwrap();
            let (ofs_base, ref_base_oid, _) = c
                .query_row(
                    "SELECT
                        (SELECT base_cid FROM edges WHERE from_cid=?1 AND base_kind='ofs' LIMIT 1),
                        (SELECT base_oid FROM edges WHERE from_cid=?1 AND base_kind='ref' LIMIT 1),
                        (SELECT base_cid FROM edges WHERE from_cid=?1 AND base_kind='ref' LIMIT 1)",
                    params![cid],
                    |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<i64>>(2)?)),
                )
                .unwrap_or((None, None, None));
            let kind = ObjType::from_name(&kind_s).unwrap_or(ObjType::Blob);
            let actual_oid = actual.and_then(|s| Oid::from_hex(&s));
            let declared_oid = declared.and_then(|s| Oid::from_hex(&s));
            let ref_base_oid = ref_base_oid.and_then(|s| Oid::from_hex(&s));
            let ref_base_cid_pinned = ref_base_oid
                .as_ref()
                .and_then(|o| pins.get(&o.hex()).copied());
            out.push(Cand {
                cid,
                source_id,
                source_kind,
                kind,
                actual_oid,
                declared_oid,
                payload_key,
                declared_size,
                parse_error,
                quality,
                ofs_base,
                ref_base_oid,
                ref_base_cid_pinned,
            });
        }
        out
    }

    #[derive(Clone)]
    struct Res {
        oid: Oid,
        kind: ObjType,
        body_key: String,
        depth: i64,
        input_bytes: i64,
        output_bytes: i64,
        steps: Vec<crate::store::StepRow>,
    }

    #[derive(Clone)]
    enum Fail {
        Error { code: String, message: String },
        Blocked { chain: Vec<i64> },
        Cycle { chain: Vec<i64> },
        Paused { reason: String, chain: Vec<i64> },
        DepthLimit { chain: Vec<i64> },
        Budget { reason: String, chain: Vec<i64> },
    }

    /// Clear derived analysis for one branch, then re-resolve every candidate.
    pub fn run_branch(&self, branch_id: i64, reset_meter: bool) -> RunSummary {
        if reset_meter {
            self.store.reset_budget_meter(branch_id);
        }
        {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "DELETE FROM resolved WHERE branch_id=?1;
                 DELETE FROM node_state WHERE branch_id=?1;
                 DELETE FROM steps WHERE branch_id=?1;
                 DELETE FROM evidence WHERE branch_id=?1 AND code NOT IN ('pack_parse','idx_parse','loose_parse','loose_oid_mismatch','ofs_oob','idx_orphan');
                 DELETE FROM checkpoints WHERE branch_id=?1;",
                params![branch_id],
            )
            .unwrap();
        }
        let cands = self.load(branch_id);
        let by_cid: BTreeMap<i64, Cand> = cands.iter().map(|c| (c.cid, c.clone())).collect();

        let budget = self.store.budgets();
        let mut done_ok: HashSet<i64> = HashSet::new();
        let mut done_fail: HashSet<i64> = HashSet::new();
        let mut summary = RunSummary {
            branch_id,
            resolved: 0,
            errors: 0,
            blocked: 0,
            paused: 0,
            used_bytes: 0,
            checkpoints: vec![],
        };

        let root_ids: Vec<i64> = cands.iter().map(|c| c.cid).collect();
        for root in root_ids {
            if done_ok.contains(&root) || done_fail.contains(&root) {
                continue;
            }
            let mut stack: Vec<i64> = Vec::new();
            match self.resolve(
                root,
                &by_cid,
                &mut stack,
                &mut done_ok,
                &mut done_fail,
                branch_id,
                &budget,
            ) {
                Ok(res) => {
                    self.persist_resolved(branch_id, root, &res);
                    summary.resolved += 1;
                }
                Err(f) => {
                    self.persist_failure(branch_id, root, &f, &by_cid);
                    match f {
                        Fail::Error { .. } => summary.errors += 1,
                        Fail::Blocked { .. } => summary.blocked += 1,
                        Fail::Cycle { .. } => summary.errors += 1,
                        Fail::Paused { .. }
                        | Fail::DepthLimit { .. }
                        | Fail::Budget { .. } => summary.paused += 1,
                    }
                }
            }
        }
        summary.used_bytes = self.store.used_bytes(branch_id);
        {
            let c = self.store.conn.lock().unwrap();
            let mut st = c
                .prepare("SELECT branch_id, root_cid, depth, total_used, chain_json, reason
                          FROM checkpoints WHERE branch_id=?1 ORDER BY root_cid")
                .unwrap();
            summary.checkpoints = st
                .query_map(params![branch_id], |r| {
                    Ok(Checkpoint {
                        branch_id: r.get(0)?,
                        root_cid: r.get(1)?,
                        depth: r.get(2)?,
                        total_used: r.get(3)?,
                        chain_json: r.get(4)?,
                        reason: r.get(5)?,
                    })
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
        }
        summary
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve(
        &self,
        cid: i64,
        all: &BTreeMap<i64, Cand>,
        stack: &mut Vec<i64>,
        done_ok: &mut HashSet<i64>,
        done_fail: &mut HashSet<i64>,
        branch_id: i64,
        budget: &crate::store::Budgets,
    ) -> Result<Res, Fail> {
        if let Some(pos) = stack.iter().position(|x| *x == cid) {
            let mut chain = stack[pos..].to_vec();
            chain.push(cid);
            return Err(Fail::Cycle { chain });
        }
        if done_ok.contains(&cid) {
            return self.load_resolved(branch_id, cid, all);
        }
        if done_fail.contains(&cid) {
            // A previously failed dependency: blocked unless that failure was transient.
            let st = self.node_state(branch_id, cid);
            return match st.as_deref() {
                Some("error") => Err(Fail::Blocked { chain: vec![cid] }),
                Some("blocked") => Err(Fail::Blocked { chain: vec![cid] }),
                Some("paused") => Err(Fail::Paused {
                    reason: "dependency paused earlier in this run".into(),
                    chain: vec![cid],
                }),
                _ => Err(Fail::Blocked { chain: vec![cid] }),
            };
        }
        let cand = all.get(&cid).cloned().ok_or_else(|| Fail::Error {
            code: "missing_candidate".into(),
            message: format!("candidate {} vanished", cid),
        })?;

        if let Some(err) = &cand.parse_error {
            return Err(Fail::Error {
                code: "parse_error".into(),
                message: err.clone(),
            });
        }
        let payload_key = cand.payload_key.clone().ok_or_else(|| Fail::Error {
            code: "no_payload".into(),
            message: "inflated payload unavailable".into(),
        })?;
        let payload = self
            .store
            .read_blob(&payload_key)
            .map_err(|e| Fail::Error { code: "io".into(), message: e.to_string() })?;

        stack.push(cid);

        // Leaf object in a pack / loose: verify hash.
        if !cand.kind.is_delta() {
            let out_len = payload.len() as i64;
            let depth = stack.len() as i64 - 1;
            stack.pop();
            return self.finish_leaf(branch_id, cand, payload, depth, out_len, done_ok);
        }

        // Delta: check depth budget.
        let depth = stack.len() as i64;
        if depth > budget.max_depth {
            let f = Fail::DepthLimit { chain: stack.clone() };
            stack.pop();
            done_fail.insert(cid);
            return Err(f);
        }

        // Determine base candidate.
        let base_cid = if cand.kind == ObjType::OfsDelta {
            match cand.ofs_base {
                Some(b) => Some(b),
                None => {
                    stack.pop();
                    done_fail.insert(cid);
                    return Err(Fail::Blocked { chain: vec![cid] });
                }
            }
        } else if let Some(p) = cand.ref_base_cid_pinned {
            Some(p)
        } else {
            self.choose_ref_base(&cand, branch_id, all)
        };

        let base_cid = match base_cid {
            Some(b) => b,
            None => {
                stack.pop();
                done_fail.insert(cid);
                let mut chain = stack.clone();
                chain.push(cid);
                return Err(Fail::Blocked { chain });
            }
        };

        // Pre-flight: parse delta instructions before touching budgets so that
        // malformed deltas are hard errors, not pauses.
        let info = match delta::inspect(&payload) {
            Ok(i) => i,
            Err(e) => {
                stack.pop();
                done_fail.insert(cid);
                return Err(Fail::Error { code: "bad_delta".into(), message: e });
            }
        };
        if info.header.base_size as i64 >= 0
            && info.output_len as i64 > info.header.result_size as i64
        {
            stack.pop();
            done_fail.insert(cid);
            return Err(Fail::Error {
                code: "delta_result_spoof".into(),
                message: format!(
                    "instructions emit {} bytes but header says {}",
                    info.output_len, info.header.result_size
                ),
            });
        }

        let total = self.store.used_bytes(branch_id);
        let result_size = info.header.result_size;
        let base_size = info.header.base_size;
        let need = result_size.max(base_size);
        if total.saturating_add(need as i64) > budget.total_bytes {
            let f = Fail::Budget {
                reason: format!(
                    "total expansion budget {} exceeded ({} already used, this object needs {})",
                    budget.total_bytes, total, need
                ),
                chain: stack.clone(),
            };
            self.save_checkpoint(branch_id, &f, depth, total);
            stack.pop();
            done_fail.insert(cid);
            return Err(f);
        }
        // Single-object ratio relative to the total budget.
        let ratio = budget.single_ratio_pct as i128 * budget.total_bytes as i128 / 100;
        if result_size as i128 > ratio {
            let f = Fail::Paused {
                reason: format!(
                    "single object result {} exceeds {}% of total budget ({} bytes)",
                    result_size, budget.single_ratio_pct, budget.total_bytes
                ),
                chain: stack.clone(),
            };
            self.save_checkpoint(branch_id, &f, depth, total);
            stack.pop();
            done_fail.insert(cid);
            return Err(f);
        }

        // Recurse into the base first.
        let base_res = match self.resolve(base_cid, all, stack, done_ok, done_fail, branch_id, budget)
        {
            Ok(r) => r,
            Err(ef) => {
                let f = self.map_base_failure(cid, ef, stack);
                done_fail.insert(cid);
                stack.pop();
                return Err(f);
            }
        };
        let base_body = self
            .store
            .read_blob(&base_res.body_key)
            .map_err(|e| Fail::Error { code: "io".into(), message: e.to_string() })?;

        // Charge budget, then apply (apply validates every instruction range).
        self.store.add_used(branch_id, need as i64);
        let result = match delta::apply(&base_body, &payload) {
            Ok(r) => r,
            Err(e) => {
                stack.pop();
                done_fail.insert(cid);
                return Err(Fail::Error { code: "delta_apply".into(), message: e });
            }
        };

        let kind = base_res.kind;
        let actual = hash_object(kind, &result);
        let expected = cand.declared_oid.or(Some(actual));
        let check_ok = actual == expected;
        let key = format!("resolved/{}", actual.hex());
        self.store.write_blob(&key, &result).ok();

        let mut steps = base_res.steps.clone();
        steps.push(crate::store::StepRow {
            cid,
            depth,
            base_cid: Some(base_cid),
            base_kind: Some(if cand.kind == ObjType::OfsDelta { "ofs".into() } else { "ref".into() }),
            input_len: payload.len() as i64,
            output_len: result.len() as i64,
            instr_start: info.instruction_bytes.0 as i64,
            instr_end: info.instruction_bytes.1 as i64,
            op_count: info.ops.len() as i64,
            check: if check_ok { "ok".into() } else { "mismatch".into() },
            expected_oid: Some(expected.hex()),
            actual_oid: Some(actual.hex()),
            note: Some(format!("base candidate {}", base_cid)),
        });

        if !check_ok {
            self.evidence(
                Some(branch_id),
                Some(cid),
                Some(&actual.hex()),
                "error",
                "oid_mismatch",
                &format!(
                    "reconstructed object hashes to {} but idx/name expects {}",
                    actual.short(),
                    expected.short()
                ),
                "delta chain",
            );
        }

        let res = Res {
            oid: actual,
            kind,
            body_key: key,
            depth,
            input_bytes: base_res.input_bytes + payload.len() as i64,
            output_bytes: base_res.output_bytes + result.len() as i64,
            steps,
        };
        done_ok.insert(cid);
        stack.pop();
        Ok(res)
    }
