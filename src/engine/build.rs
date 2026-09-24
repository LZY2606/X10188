//! Candidate reconstruction: recursive delta resolution with cycle
//! detection, budgets, blocker chains and persistent intermediate state.

use super::*;
use crate::git::delta::parse_ops;
use crate::git::types::ObjType;
use crate::model::status as st;
use rusqlite::params;
use std::collections::{BTreeSet, VecDeque};

impl App {
    /// Resolve every candidate that currently has no stored resolution.
    pub fn resolve_all(&self) -> Result<ResolveReport> {
        let cands = self.all_candidates()?;
        let mut rt = Runtime::new(self);
        rt.used_seed = self.db.used_bytes()?;
        let mut report = ResolveReport::default();
        for cand in cands {
            if self.has_resolution(cand.id)? {
                continue;
            }
            let res = self.resolve_candidate(&mut rt, cand.id)?;
            self.persist(&mut rt, cand.id, &res)?;
        }
        self.db.set_used_bytes(rt.used_seed)?;
        report.summarize(self)?;
        Ok(report)
    }

    /// Retry candidates in paused / missing_base state (after a budget
    /// raise or new bases arriving).
    pub fn resume(&self) -> Result<ResolveReport> {
        let ids = self.resolution_ids_in(&[st::PAUSED, st::MISSING_BASE])?;
        let mut rt = Runtime::new(self);
        rt.used_seed = self.db.used_bytes()?;
        for id in ids {
            let res = self.resolve_candidate(&mut rt, id)?;
            self.persist(&mut rt, id, &res)?;
        }
        // A resumed resolution may unblock dependents that were recorded as
        // missing_base/paused but are not themselves in the retry list yet.
        self.recompute_consumers(&mut rt, rt.touched.iter().copied().collect())?;
        self.db.set_used_bytes(rt.used_seed)?;
        let mut report = ResolveReport::default();
        report.summarize(self)?;
        Ok(report)
    }

    fn has_resolution(&self, id: i64) -> Result<bool> {
        let c = self.db.lock();
        Ok(c
            .query_row(
                "SELECT 1 FROM resolution WHERE candidate_id = ?1",
                params![id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn resolution_ids_in(&self, states: &[&str]) -> Result<Vec<i64>> {
        let c = self.db.lock();
        let placeholders = (0..states.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT candidate_id FROM resolution WHERE status IN ({placeholders}) ORDER BY candidate_id"
        );
        let mut stmt = c.prepare(&sql)?;
        let params_iter: Vec<&dyn rusqlite::ToSql> =
            states.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(params_iter.as_slice(), |r| r.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

impl App {
    fn resolve_candidate(&self, rt: &mut Runtime, id: i64) -> Result<Res> {
        let cand = match self.get_candidate(id) {
            Ok(c) => c,
            Err(_) => {
                return Ok(Res::Bad {
                    code: "missing_candidate".into(),
                    detail: format!("candidate {id} vanished"),
                    blockers: vec![],
                })
            }
        };

        if rt.visiting.contains(&id) {
            let start = rt.chain.iter().position(|c| *c == id).unwrap_or(0);
            let mut chain = rt.chain[start..].to_vec();
            chain.push(id);
            return Ok(Res::Cycle { chain });
        }

        // Structurally bad candidate (size spoof / truncated stream / ...):
        // isolate it permanently; no part of its output is ever stored.
        if cand.parse_status != "ok" {
            return Ok(Res::Bad {
                code: format!("parse_{}", cand.parse_status),
                detail: cand.parse_detail.clone(),
                blockers: vec![Blocker {
                    code: format!("parse_{}", cand.parse_status),
                    message: cand.parse_detail.clone(),
                    candidate_id: Some(id),
                    chain: rt.chain.clone(),
                }],
            });
        }

        // CRC mismatch recorded by a paired index is evidence of corruption
        // but structurally parseable; we still treat it as isolated.
        if cand.crc_ok == Some(false) {
            return Ok(Res::Bad {
                code: "crc_mismatch".into(),
                detail: format!(
                    "pack entry crc32 {:#010x} != index crc32 {:#010x}",
                    cand.entry_crc32.unwrap_or(0),
                    cand.idx_crc32.unwrap_or(0)
                ),
                blockers: vec![Blocker {
                    code: "crc_mismatch".into(),
                    message: "index CRC does not match on-disk entry".into(),
                    candidate_id: Some(id),
                    chain: rt.chain.clone(),
                }],
            });
        }

        rt.visiting.insert(id);
        rt.chain.push(id);

        let res = match cand.obj_type.as_str() {
            "ofs-delta" | "ref-delta" => self.resolve_delta(rt, &cand),
            _ => self.resolve_leaf(rt, &cand),
        };

        let mut res = res?;

        // Cycle detection only at the back-edge target: when a recursion
        // returns Cycle whose chain begins at this candidate, mark this node
        // too; intermediate nodes receive propagated blockers instead.
        if let Res::Cycle { ref chain } = res {
            if chain.first() == Some(&id) {
                rt.chain.pop();
                rt.visiting.remove(&id);
                return Ok(res);
            }
        }

        // Attach this node to blocker chains for every failure kind.
        match &mut res {
            Res::MissingBase { blockers }
            | Res::Bad { blockers, .. }
            | Res::Paused { blockers, .. } => {
                for b in blockers.iter_mut() {
                    if b.candidate_id.is_none() {
                        b.candidate_id = Some(id);
                    }
                    b.chain.push(id);
                }
            }
            Res::Done(_) | Res::Cycle { .. } => {}
        }

        rt.chain.pop();
        rt.visiting.remove(&id);
        Ok(res)
    }

    fn charge(&self, rt: &mut Runtime, n: u64) -> Result<()> {
        if n > self.budgets().max_total_bytes.saturating_sub(rt.used_seed) {
            return Err(Error::BudgetPaused {
                kind: "total_expansion".into(),
                limit: self.budgets().max_total_bytes,
                used: rt.used_seed.saturating_add(n),
                retryable: true,
            });
        }
        rt.used_seed = rt.used_seed.saturating_add(n);
        Ok(())
    }
}

impl App {
    fn resolve_leaf(&self, rt: &mut Runtime, cand: &CandidateRow) -> Result<Res> {
        let kind = match ObjType::from_loose_name(&cand.obj_type) {
            Ok(k) => k,
            Err(_) => {
                return Ok(Res::Bad {
                    code: "unknown_type".into(),
                    detail: format!("object type '{}' not a leaf", cand.obj_type),
                    blockers: vec![],
                })
            }
        };
        if rt.chain.len() as u32 - 1 >= self.budgets().max_depth
            && self.budgets().max_depth == 0
        {
            // unreachable defensive branch
        }
        let comp = match self.candidate_compressed(cand) {
            Ok(c) => c,
            Err(e) => return Ok(Res::from_err(&e)),
        };
        let remaining = self.budgets().max_total_bytes.saturating_sub(rt.used_seed);
        let outcome = match inflate_budgeted(
            &comp,
            cand.claimed_size.max(0) as u64,
            remaining,
            self.budgets().max_single_ratio,
        ) {
            Ok(o) => o,
            Err(e) => return Ok(Res::from_err(&e)),
        };

        match outcome.status {
            crate::git::zlib::InflateStatus::Ok => {}
            crate::git::zlib::InflateStatus::SizeSpoof { ref detail } => {
                return Ok(Res::Bad {
                    code: "size_spoof".into(),
                    detail: detail.clone(),
                    blockers: vec![Blocker {
                        code: "size_spoof".into(),
                        message: detail.clone(),
                        candidate_id: Some(cand.id),
                        chain: rt.chain.clone(),
                    }],
                });
            }
            crate::git::zlib::InflateStatus::Truncated => {
                return Ok(Res::Bad {
                    code: "truncated".into(),
                    detail: "zlib stream truncated".into(),
                    blockers: vec![Blocker {
                        code: "truncated".into(),
                        message: "zlib stream truncated".into(),
                        candidate_id: Some(cand.id),
                        chain: rt.chain.clone(),
                    }],
                });
            }
            crate::git::zlib::InflateStatus::HardCapExceeded => {
                return Ok(Res::Bad {
                    code: "hard_cap".into(),
                    detail: "single object exceeds hard expansion cap".into(),
                    blockers: vec![],
                });
            }
            crate::git::zlib::InflateStatus::BudgetPaused { kind, limit, need } => {
                return Ok(Res::Paused {
                    kind,
                    limit,
                    used: need,
                    blockers: vec![Blocker {
                        code: "budget_paused".into(),
                        message: format!("leaf inflation needs {need} bytes (limit {limit})"),
                        candidate_id: Some(cand.id),
                        chain: rt.chain.clone(),
                    }],
                });
            }
        }

        if let Err(e) = self.charge(rt, outcome.actual) {
            return Ok(Res::from_err(&e));
        }

        let computed = git_hash(kind, &outcome.data);
        let computed_hex = hex_id(&computed);
        let oid_match = cand
            .declared_oid_hex
            .as_ref()
            .map(|d| d.eq_ignore_ascii_case(&computed_hex));

        if oid_match == Some(false) {
            return Ok(Res::Bad {
                code: "oid_mismatch".into(),
                detail: format!(
                    "recomputed object id {computed_hex} but index declares {}",
                    cand.declared_oid_hex.as_deref().unwrap_or("?")
                ),
                blockers: vec![Blocker {
                    code: "oid_mismatch".into(),
                    message: "recomputed Git object id disagrees with declared identity".into(),
                    candidate_id: Some(cand.id),
                    chain: rt.chain.clone(),
                }],
            });
        }

        let step = StepJson {
            step: 0,
            candidate_id: cand.id,
            kind: kind.name().into(),
            base_candidate_id: None,
            delta_header_len: 0,
            ops_count: 0,
            ops_range_start: 0,
            ops_range_end: 0,
            input_len: 0,
            output_len: outcome.actual,
            compressed_len: outcome.compressed_len,
            check: oid_check_label(oid_match),
            check_detail: match oid_match {
                Some(true) => format!("sha1 ok: {computed_hex}"),
                None => format!("sha1 computed: {computed_hex} (no declared oid)"),
                Some(false) => "sha1 mismatch".into(),
            },
        };

        Ok(Res::Done(ResolvedObj {
            kind,
            data: outcome.data,
            depth: 0,
            steps: vec![step],
        }))
    }
}

fn oid_check_label(m: Option<bool>) -> String {
    match m {
        Some(true) => "oid_match".into(),
        Some(false) => "oid_mismatch".into(),
        None => "oid_computed".into(),
    }
}

impl App {
    fn resolve_delta(&self, rt: &mut Runtime, cand: &CandidateRow) -> Result<Res> {
        let depth = rt.chain.len() as u32; // about to add 1 link
        if depth >= self.budgets().max_depth {
            return Ok(Res::Paused {
                kind: "max_delta_depth".into(),
                limit: self.budgets().max_depth as u64,
                used: depth as u64 + 1,
                blockers: vec![Blocker {
                    code: "budget_paused".into(),
                    message: format!(
                        "delta chain depth {} exceeds max {}",
                        depth + 1,
                        self.budgets().max_depth
                    ),
                    candidate_id: Some(cand.id),
                    chain: rt.chain.clone(),
                }],
            });
        }

        // ---- locate the declared base ------------------------------------
        let (base_id, decl) = if cand.obj_type == "ofs-delta" {
            match self.ofs_base_candidate(cand)? {
                Some(b) => (b.id, format!("ofs@{}", b.pack_offset.unwrap_or(-1))),
                None => {
                    return Ok(Res::MissingBase {
                        blockers: vec![Blocker {
                            code: "ofs_base_unreachable".into(),
                            message: format!(
                                "ofs-delta references offset {} which is not a parseable entry",
                                cand.ofs_base_offset.unwrap_or(-1)
                            ),
                            candidate_id: Some(cand.id),
                            chain: rt.chain.clone(),
                        }],
                    });
                }
            }
        } else {
            let oid = cand.ref_base_oid_hex.as_deref().unwrap_or("");
            match self.choose_ref_base(oid) {
                Some(b) => (b.id, format!("ref:{oid}")),
                None => {
                    return Ok(Res::MissingBase {
                        blockers: vec![Blocker {
                            code: "external_base_missing".into(),
                            message: format!("ref-delta base {oid} is not present in any source"),
                            candidate_id: Some(cand.id),
                            chain: rt.chain.clone(),
                        }],
                    });
                }
            }
        };

        // ---- resolve base recursively ------------------------------------
        let base_res = self.resolve_candidate(rt, base_id)?;
        let base_obj = match base_res {
            Res::Done(o) => o,
            Res::Cycle { chain } => return Ok(Res::Cycle { chain }),
            Res::MissingBase { blockers } => {
                return Ok(Res::MissingBase {
                    blockers: propagate(blockers, cand.id, rt.chain.clone()),
                });
            }
            Res::Bad { code, detail, blockers } => {
                return Ok(Res::Bad {
                    code: format!("base_bad:{code}"),
                    detail: format!("base candidate {base_id} unusable: {detail}"),
                    blockers: propagate(blockers, cand.id, rt.chain.clone()),
                });
            }
            Res::Paused { kind, limit, used, blockers } => {
                return Ok(Res::Paused {
                    kind,
                    limit,
                    used,
                    blockers: propagate(blockers, cand.id, rt.chain.clone()),
                });
            }
        };

        // ---- inflate the delta payload (bounded) --------------------------
        let comp = match self.candidate_compressed(cand) {
            Ok(c) => c,
            Err(e) => return Ok(Res::from_err(&e)),
        };
        let remaining = self.budgets().max_total_bytes.saturating_sub(rt.used_seed);
        let outcome = match inflate_budgeted(
            &comp,
            cand.claimed_size.max(0) as u64,
            remaining,
            self.budgets().max_single_ratio,
        ) {
            Ok(o) => o,
            Err(e) => return Ok(Res::from_err(&e)),
        };

        match outcome.status {
            crate::git::zlib::InflateStatus::Ok => {}
            crate::git::zlib::InflateStatus::SizeSpoof { ref detail } => {
                return Ok(self.delta_bad(cand, rt, "size_spoof", detail));
            }
            crate::git::zlib::InflateStatus::Truncated => {
                return Ok(self.delta_bad(
                    cand,
                    rt,
                    "truncated",
                    "delta zlib stream truncated",
                ));
            }
            crate::git::zlib::InflateStatus::HardCapExceeded => {
                return Ok(self.delta_bad(
                    cand,
                    rt,
                    "hard_cap",
                    "delta exceeds single-object hard cap",
                ));
            }
            crate::git::zlib::InflateStatus::BudgetPaused { kind, limit, need } => {
                return Ok(Res::Paused {
                    kind,
                    limit,
                    used: need,
                    blockers: vec![Blocker {
                        code: "budget_paused".into(),
                        message: format!("delta inflation needs {need} bytes (limit {limit})"),
                        candidate_id: Some(cand.id),
                        chain: rt.chain.clone(),
                    }],
                });
            }
        }
        if let Err(e) = self.charge(rt, outcome.actual) {
            return Ok(Res::from_err(&e));
        }

        let payload = outcome.data;
        let step_no = base_obj.steps.len();

        // Parse instructions first so bad ranges are evidence even when
        // application later fails.
        let (declared_base, declared_result, header_len, ops) = match parse_ops(&payload) {
            Ok(v) => v,
            Err(e) => {
                return Ok(self.delta_bad(
                    cand,
                    rt,
                    "bad_delta_opcode",
                    &e.to_string(),
                ));
            }
        };
        if declared_base as usize != base_obj.data.len() {
            return Ok(self.delta_bad(
                cand,
                rt,
                "delta_base_size",
                &format!(
                    "delta declares base size {declared_base} but base is {} bytes",
                    base_obj.data.len()
                ),
            ));
        }

        let total_remaining =
            self.budgets().max_total_bytes.saturating_sub(rt.used_seed);
        let applied = match delta_apply(
            &base_obj.data,
            &payload,
            total_remaining,
            self.budgets().max_result_bytes,
        ) {
            Ok(a) => a,
            Err(Error::BudgetPaused { kind, limit, used, .. }) => {
                return Ok(Res::Paused {
                    kind,
                    limit,
                    used,
                    blockers: vec![Blocker {
                        code: "budget_paused".into(),
                        message: format!(
                            "delta result needs {used} bytes ({kind} limit {limit})"
                        ),
                        candidate_id: Some(cand.id),
                        chain: rt.chain.clone(),
                    }],
                });
            }
            Err(e) => return Ok(self.delta_bad(cand, rt, "delta_apply", &e.to_string())),
        };

        // The result bytes are newly materialised output: charge them.
        if let Err(Error::BudgetPaused { kind, limit, used, .. }) =
            self.charge(rt, applied.result_size)
        {
            return Ok(Res::Paused {
                kind,
                limit,
                used,
                blockers: vec![Blocker {
                    code: "budget_paused".into(),
                    message: format!("delta result charge {used} > {limit}"),
                    candidate_id: Some(cand.id),
                    chain: rt.chain.clone(),
                }],
            });
        }

        let computed = git_hash(base_obj.kind, &applied.output);
        let computed_hex = hex_id(&computed);
        let oid_match = cand
            .declared_oid_hex
            .as_ref()
            .map(|d| d.eq_ignore_ascii_case(&computed_hex));
        if oid_match == Some(false) {
            return Ok(self.delta_bad(
                cand,
                rt,
                "oid_mismatch",
                &format!(
                    "recomputed {computed_hex} != declared {}",
                    cand.declared_oid_hex.as_deref().unwrap_or("?")
                ),
            ));
        }

        let ops_start = ops.first().map(|o| o.start).unwrap_or(header_len);
        let ops_end = ops.last().map(|o| o.end).unwrap_or(header_len);
        let step = StepJson {
            step: step_no,
            candidate_id: cand.id,
            kind: cand.obj_type.clone(),
            base_candidate_id: Some(base_id),
            delta_header_len: header_len,
            ops_count: ops.len(),
            ops_range_start: ops_start,
            ops_range_end: ops_end,
            input_len: base_obj.data.len() as u64,
            output_len: applied.output.len() as u64,
            compressed_len: outcome.compressed_len,
            check: oid_check_label(oid_match),
            check_detail: format!(
                "{} ops; base {}->result {}; {} {}",
                ops.len(),
                declared_base,
                declared_result,
                decl,
                oid_check_detail(oid_match, &computed_hex)
            ),
        };

        let mut steps = base_obj.steps;
        steps.push(step);

        Ok(Res::Done(ResolvedObj {
            kind: base_obj.kind,
            data: applied.output,
            depth: base_obj.depth + 1,
            steps,
        }))
    }

    fn delta_bad(
        &self,
        cand: &CandidateRow,
        rt: &Runtime,
        code: &str,
        detail: &str,
    ) -> Res {
        Res::Bad {
            code: code.into(),
            detail: detail.into(),
            blockers: vec![Blocker {
                code: code.into(),
                message: detail.into(),
                candidate_id: Some(cand.id),
                chain: rt.chain.clone(),
            }],
        }
    }
}

fn oid_check_detail(m: Option<bool>, hex: &str) -> String {
    match m {
        Some(true) => format!("sha1 ok: {hex}"),
        Some(false) => "sha1 mismatch".into(),
        None => format!("sha1 computed: {hex}"),
    }
}

fn propagate(incoming: Vec<Blocker>, id: i64, chain: Vec<i64>) -> Vec<Blocker> {
    let mut out = incoming;
    for b in out.iter_mut() {
        if b.candidate_id.is_none() {
            b.candidate_id = Some(id);
        }
        b.chain.push(id);
        let _ = chain;
    }
    out
}

impl App {
    pub(crate) fn persist(&self, rt: &mut Runtime, id: i64, res: &Res) -> Result<()> {
        // Remove any previous content file / row first.
        if let Ok(existing) = self.get_resolution(id) {
            if let Some(p) = existing.content_path {
                self.remove_content(&p);
            }
        }
        rt.touched.insert(id);

        match res {
            Res::Done(obj) => {
                let cand = self.get_candidate(id)?;
                let name = self.write_content(id, &obj.data)?;
                let computed = git_hash(obj.kind, &obj.data);
                let hex = hex_id(&computed);
                let oid_match = cand
                    .declared_oid_hex
                    .as_ref()
                    .map(|d| d.eq_ignore_ascii_case(&hex));
                let steps_json =
                    serde_json::to_string(&obj.steps).unwrap_or_else(|_| "[]".into());
                let c = self.db.lock();
                c.execute(
                    "UPDATE candidate SET computed_oid_hex = ?2 WHERE id = ?1",
                    params![id, hex],
                )?;
                c.execute(
                    "INSERT INTO resolution(candidate_id,status,resolved_type,content_len,
                        content_path,oid_hex,oid_match,depth,error_code,error_detail,
                        blockers_json,steps_json)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,NULL,'[]',?9)
                     ON CONFLICT(candidate_id) DO UPDATE SET
                        status=excluded.status, resolved_type=excluded.resolved_type,
                        content_len=excluded.content_len, content_path=excluded.content_path,
                        oid_hex=excluded.oid_hex, oid_match=excluded.oid_match,
                        depth=excluded.depth, error_code=NULL, error_detail=NULL,
                        blockers_json='[]', steps_json=excluded.steps_json,
                        updated_at=datetime('now')",
                    params![
                        id,
                        st::RESOLVED,
                        obj.kind.name(),
                        obj.data.len() as i64,
                        name,
                        hex,
                        oid_match.map(|b| b as i64),
                        obj.depth as i64,
                        steps_json,
                    ],
                )?;
            }
            Res::Cycle { chain } => {
                let blockers = vec![Blocker {
                    code: "delta_cycle".into(),
                    message: format!("delta cycle: {}", chain_str(chain)),
                    candidate_id: Some(id),
                    chain: chain.clone(),
                }];
                self.persist_failure(
                    id,
                    st::CYCLE,
                    "delta_cycle",
                    &format!("delta cycle through {}", chain_str(chain)),
                    blockers,
                )?;
            }
            Res::MissingBase { blockers } => {
                self.persist_failure(
                    id,
                    st::MISSING_BASE,
                    "missing_base",
                    "base object is unavailable",
                    blockers.clone(),
                )?;
            }
            Res::Bad { code, detail, blockers } => {
                self.persist_failure(
                    id,
                    st::BAD,
                    code,
                    detail,
                    blockers.clone(),
                )?;
            }
            Res::Paused { kind, limit, used, blockers } => {
                let mut blockers = blockers.clone();
                if blockers.is_empty() {
                    blockers.push(Blocker {
                        code: "budget_paused".into(),
                        message: format!("{kind}: {used} > {limit}"),
                        candidate_id: Some(id),
                        chain: vec![id],
                    });
                }
                self.persist_failure(
                    id,
                    st::PAUSED,
                    "budget_paused",
                    &format!("{kind}: used {used}, limit {limit}"),
                    blockers,
                )?;
            }
        }
        Ok(())
    }

    fn persist_failure(
        &self,
        id: i64,
        status: &str,
        code: &str,
        detail: &str,
        blockers: Vec<Blocker>,
    ) -> Result<()> {
        let json = serde_json::to_string(&blockers).unwrap_or_else(|_| "[]".into());
        let c = self.db.lock();
        c.execute(
            "INSERT INTO resolution(candidate_id,status,resolved_type,content_len,
                content_path,oid_hex,oid_match,depth,error_code,error_detail,
                blockers_json,steps_json)
             VALUES(?1,?2,NULL,0,NULL,NULL,NULL,0,?3,?4,?5,NULL)
             ON CONFLICT(candidate_id) DO UPDATE SET
                status=excluded.status, resolved_type=NULL, content_len=0,
                content_path=NULL, oid_hex=NULL, oid_match=NULL, depth=0,
                error_code=excluded.error_code, error_detail=excluded.error_detail,
                blockers_json=excluded.blockers_json, steps_json=NULL,
                updated_at=datetime('now')",
            params![id, status, code, detail, json],
        )?;
        Ok(())
    }

    pub fn get_resolution(&self, id: i64) -> Result<ResolutionRow> {
        let c = self.db.lock();
        c.query_row(
            "SELECT * FROM resolution WHERE candidate_id = ?1",
            params![id],
            |r| {
                Ok(ResolutionRow {
                    candidate_id: r.get("candidate_id")?,
                    status: r.get("status")?,
                    resolved_type: r.get("resolved_type")?,
                    content_len: r.get("content_len")?,
                    content_path: r.get("content_path")?,
                    oid_hex: r.get("oid_hex")?,
                    oid_match: r
                        .get::<_, Option<i64>>("oid_match")?
                        .map(|v| v != 0),
                    depth: r.get("depth")?,
                    error_code: r.get("error_code")?,
                    error_detail: r.get("error_detail")?,
                    blockers_json: r.get("blockers_json")?,
                    steps_json: r.get("steps_json")?,
                })
            },
        )
        .optional_row()
    }

    /// Recompute only the consumer subgraph of the given changed candidate
    /// ids (plus transitively). Consumers are reached through *declared*
    /// edges so this also revisits nodes that previously failed to link.
    pub fn recompute_consumers(&self, rt: &mut Runtime, seeds: Vec<i64>) -> Result<()> {
        let mut queue: VecDeque<i64> = seeds.into_iter().collect();
        let mut done: BTreeSet<i64> = BTreeSet::new();
        while let Some(base_id) = queue.pop_front() {
            if !done.insert(base_id) {
                continue;
            }
            let base = match self.get_candidate(base_id) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for consumer in self.declared_consumers(&base)? {
                // Only revisit this consumer if it actually depended on the
                // chosen base path; declared edges make that true.
                if rt.visiting.contains(&consumer) {
                    continue;
                }
                let res = self.resolve_candidate(rt, consumer)?;
                self.persist(rt, consumer, &res)?;
                queue.push_back(consumer);
            }
        }
        Ok(())
    }
}

fn chain_str(chain: &[i64]) -> String {
    chain
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ResolveReport {
    pub resolved: usize,
    pub missing_base: usize,
    pub cycle: usize,
    pub bad: usize,
    pub paused: usize,
    pub total: usize,
}

impl ResolveReport {
    fn summarize(&mut self, app: &App) -> Result<()> {
        let c = app.db.lock();
        let mut stmt = c.prepare("SELECT status, COUNT(*) FROM resolution GROUP BY status")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (status, n) = r?;
            self.total += n as usize;
            match status.as_str() {
                "resolved" => self.resolved += n as usize,
                "missing_base" => self.missing_base += n as usize,
                "cycle" => self.cycle += n as usize,
                "bad" => self.bad += n as usize,
                "paused" => self.paused += n as usize,
                _ => {}
            }
        }
        Ok(())
    }
}
