//! The reconstruction engine: turns structural entries into verified Git
//! objects by walking ofs-delta/ref-delta chains under resource budgets.
//!
//! Failure isolation rule: one bad object never aborts analysis of the others.
//! Every unresolved object records an ordered blocking chain.

use anyhow::Result;
use rusqlite::params;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::db::{next_seq, Db};
use crate::delta::{apply_delta, Budget};
use crate::gitfmt::{git_oid, inflate_zlib, parse_loose_body, ObjType};

#[derive(Debug, Clone, Serialize)]
pub struct BudgetCfg {
    pub max_depth: usize,
    pub max_expand_bytes: u64,
    pub max_single_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeReport {
    pub branch_id: i64,
    pub run_id: i64,
    pub analysis_seq: i64,
    pub status: String,
    pub resolved: usize,
    pub paused: usize,
    pub blocked: usize,
    pub corrupt: usize,
    pub total: usize,
    pub spent_expand: u64,
    pub resolved_entry_ids: Vec<i64>,
}

#[derive(Debug, Clone)]
struct EntryRow {
    id: i64,
    source_id: i64,
    obj_type: String,
    declared_size: Option<i64>,
    raw_offset: i64,
    data_start: i64,
    data_end: i64,
    ofs_base_offset: Option<i64>,
    ref_base_oid: Option<String>,
    inflate_ok: bool,
    parse_error: Option<String>,
    claimed_oid: Option<String>,
}

#[derive(Debug, Clone)]
struct CandidateRow {
    entry_id: i64,
    oid: String,
    source_id: i64,
}

#[derive(Debug, Clone, Serialize)]
struct ChainLink {
    entry_id: i64,
    obj_type: String,
    kind: String, // loose | ofs | ref | base
    ref_detail: String,
    reason: String,
}

/// Outcome of materializing one entry within a run.
#[derive(Clone)]
enum Mat {
    Resolved {
        kind: ObjType,
        content: Vec<u8>,
        depth: usize,
        steps: Vec<crate::delta::StepRecord>,
        spent: u64,
    },
    Paused,
    Fail {
        code: String,
        message: String,
        chain: Vec<ChainLink>,
    },
}

impl Db {
    /// Read the current budget configuration from settings.
    pub fn budget_cfg(&self) -> Result<BudgetCfg> {
        let max_depth: usize = self.setting("budget_depth")?.parse().unwrap_or(50);
        let max_expand: u64 = self.setting("budget_expand")?.parse().unwrap_or(64 << 20);
        let ratio: f64 = self.setting("budget_single_ratio")?.parse().unwrap_or(0.5);
        let max_single = ((max_expand as f64) * ratio.clamp(0.01, 1.0)) as u64;
        Ok(BudgetCfg {
            max_depth,
            max_expand_bytes: max_expand,
            max_single_bytes: max_single,
        })
    }

    /// Reanalyze one branch. Idempotent: results/steps/contents for the branch
    /// are rebuilt deterministically so result ordering never depends on the
    /// order files were imported.
    pub fn analyze_branch(&self, branch_id: i64) -> Result<AnalyzeReport> {
        self.analyze_branch_scoped(branch_id, None)
    }

    /// Continue a paused run: only entries not already resolved are visited.
    pub fn resume_branch(&self, branch_id: i64) -> Result<AnalyzeReport> {
        // Results already on disk are kept; scoped analysis skips resolved ids.
        self.analyze_branch_scoped(branch_id, None)
    }

    pub(crate) fn analyze_branch_scoped(
        &self,
        branch_id: i64,
        scope: Option<&HashSet<i64>>,
    ) -> Result<AnalyzeReport> {
        let cfg = self.budget_cfg()?;
        let budget = Budget {
            max_depth: cfg.max_depth,
            max_expand_bytes: cfg.max_expand_bytes,
            max_single_bytes: cfg.max_single_bytes,
        };

        let entries = self.load_entries();
        let sources = self.load_source_bytes();
        let cands = self.load_candidates();
        let pins = self.load_pins(branch_id);

        let mut by_oid: HashMap<String, Vec<CandidateRow>> = HashMap::new();
        for c in cands {
            by_oid.entry(c.oid.clone()).or_default().push(c.clone());
        }
        for rows in by_oid.values_mut() {
            rows.sort_by(|a, b| {
                let pa = pins.contains(&(a.oid.clone(), a.source_id)) as u8;
                let pb = pins.contains(&(b.oid.clone(), b.source_id)) as u8;
                pb.cmp(&pa)
                    .then_with(|| a.oid.cmp(&b.oid))
                    .then_with(|| a.source_id.cmp(&b.source_id))
                    .then_with(|| a.entry_id.cmp(&b.entry_id))
            });
        }

        let mut run_spent: u64 = 0;
        let mut paused_global = false;
        let mut counts = (0usize, 0usize, 0usize, 0usize);
        let mut resolved_ids: HashSet<i64> = HashSet::new();
        let mut handled: HashSet<i64> = HashSet::new();

        let mut ctx = Ctx {
            entries: &entries,
            sources: &sources,
            by_oid: &by_oid,
            pins: &pins,
            budget,
            cache: HashMap::new(),
            chain: Vec::new(),
            run_spent: 0,
            paused: false,
        };

        let already_resolved: HashSet<i64> = {
            let conn = self.conn.lock().unwrap();
            let mut st = conn.prepare(
                "SELECT entry_id FROM results WHERE branch_id=?1 AND status='resolved'").unwrap();
            st.query_map([branch_id], |r| r.get::<_, i64>(0)).unwrap()
                .filter_map(|r| r.ok()).collect()
        };

        for e in &entries {
            if let Some(set) = scope {
                if !set.contains(&e.id) {
                    continue;
                }
            }
            if already_resolved.contains(&e.id) {
                counts.0 += 1;
                continue;
            }
            if ctx.paused {
                break;
            }
            let mat = ctx.materialize(e.id, 0, 0);
            run_spent = ctx.run_spent;
            match mat {
                Mat::Resolved { kind, content, depth, steps, spent: _ } => {
                    resolved_ids.insert(e.id);
                    handled.insert(e.id);
                    self.persist_resolved(branch_id, e, kind, &content, depth, &steps)?;
                }
                Mat::Paused => {
                    counts.1 += 1;
                    handled.insert(e.id);
                    self.persist_unresolved(branch_id, e, "paused", "BUDGET_PAUSED",
                        "达到资源预算上限，已保留中间状态，可在补入预算/base 后重试",
                        chain_for(&ctx.chain, e.id))?;
                    paused_global = true;
                }
                Mat::Fail { code, message, chain } => {
                    handled.insert(e.id);
                    let status = if is_corrupt(&code) {
                        counts.3 += 1;
                        "corrupt"
                    } else {
                        counts.2 += 1;
                        "blocked"
                    };
                    self.persist_unresolved(branch_id, e, status, &code, &message, chain)?;
                }
            }
        }

        // Anything not visited because the run paused stays in a retryable
        // intermediate state, never as a partial/complete object.
        if ctx.paused {
            for e in &entries {
                if let Some(set) = scope {
                    if !set.contains(&e.id) { continue; }
                }
                if already_resolved.contains(&e.id) { continue; }
                if !handled.contains(&e.id) {
                    counts.1 += 1;
                    self.persist_unresolved(
                        branch_id, e, "paused", "BUDGET_PAUSED",
                        "预算暂停后尚未处理的排队对象（可重试的中间状态）",
                        vec![],
                    )?;
                }
            }
        }

        let (mut conn, seq, run_id);
        {
            conn = self.conn.lock().unwrap();
            seq = next_seq(&conn)?;
            conn.execute(
                "INSERT INTO runs(branch_id,status,max_depth,max_expand,max_single,spent_expand,created_seq)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    branch_id,
                    if paused_global { "paused" } else { "completed" },
                    cfg.max_depth as i64,
                    cfg.max_expand_bytes as i64,
                    cfg.max_single_bytes as i64,
                    run_spent as i64,
                    seq
                ],
            )?;
            run_id = conn.last_insert_rowid();
            conn.execute(
                "UPDATE results SET run_id=?1, analysis_seq=?2 WHERE branch_id=?3",
                params![run_id, seq, branch_id],
            )?;
            conn.execute(
                "INSERT INTO analysis_meta(branch_id,analysis_seq) VALUES(?1,?2)
                 ON CONFLICT(branch_id) DO UPDATE SET analysis_seq=excluded.analysis_seq",
                params![branch_id, seq],
            )?;
        }

        Ok(AnalyzeReport {
            branch_id,
            run_id,
            analysis_seq: seq,
            status: if paused_global { "paused".into() } else { "completed".into() },
            resolved: counts.0,
            paused: counts.1,
            blocked: counts.2,
            corrupt: counts.3,
            total: scope.map(|s| s.len()).unwrap_or(entries.len()),
            spent_expand: run_spent,
            resolved_entry_ids: resolved_ids.into_iter().collect(),
        })
    }
}

fn is_corrupt(code: &str) -> bool {
    matches!(
        code,
        "PARSE_ERROR" | "INFLATE_ERROR" | "SIZE_SPOOF" | "CRC_MISMATCH"
            | "OID_MISMATCH" | "DELTA_ERROR" | "BAD_LOOSE"
    )
}

fn chain_for(stack: &[i64], self_id: i64) -> Vec<ChainLink> {
    let mut v: Vec<ChainLink> = stack.iter().copied().map(|id| ChainLink {
        entry_id: id,
        obj_type: String::new(),
        kind: "path".into(),
        ref_detail: String::new(),
        reason: String::new(),
    }).collect();
    v.push(ChainLink { entry_id: self_id, obj_type: String::new(), kind: "self".into(),
        ref_detail: String::new(), reason: String::new() });
    v
}

struct Ctx<'a> {
    entries: &'a [EntryRow],
    sources: &'a HashMap<i64, (String, Vec<u8>)>,
    by_oid: &'a HashMap<String, Vec<CandidateRow>>,
    pins: &'a HashSet<(String, i64)>,
    budget: Budget,
    /// Fully materialized entries within this run: entry id -> (kind, bytes, depth, steps).
    cache: HashMap<i64, Mat>,
    chain: Vec<i64>,
    run_spent: u64,
    paused: bool,
}

impl<'a> Ctx<'a> {
    fn entry(&self, id: i64) -> Option<&EntryRow> {
        self.entries.iter().find(|e| e.id == id)
    }

    fn fail(code: impl Into<String>, message: impl Into<String>, chain: Vec<ChainLink>) -> Mat {
        Mat::Fail { code: code.into(), message: message.into(), chain }
    }

    fn materialize(&mut self, id: i64, depth: usize, chain_spent: u64) -> Mat {
        if let Some(m) = self.cache.get(&id) {
            return m.clone();
        }
        if depth > self.budget.max_depth {
            return Self::fail(
                "DEPTH_EXCEEDED",
                format!("delta 深度 {} 超过上限 {}", depth, self.budget.max_depth),
                self.describe_chain(id, "depth"),
            );
        }
        if self.chain.contains(&id) {
            let mut chain = self.describe_chain(id, "cycle");
            chain.push(ChainLink {
                entry_id: id, obj_type: String::new(), kind: "cycle-back".into(),
                ref_detail: String::new(),
                reason: format!("回到 entry {id}，形成 delta 环"),
            });
            return Self::fail("DELTA_CYCLE", "delta 依赖形成环，无法还原", chain);
        }
        if self.paused {
            return Mat::Paused;
        }

        let e = match self.entry(id) {
            Some(e) => e.clone(),
            None => return Self::fail("INTERNAL", format!("entry {id} 不存在"), vec![]),
        };
        self.chain.push(id);

        // Quarantine structurally broken entries immediately.
        if let Some(msg) = &e.parse_error {
            let code = if msg.contains("CRC") {
                "CRC_MISMATCH"
            } else if msg.contains("size spoof") {
                "SIZE_SPOOF"
            } else {
                "PARSE_ERROR"
            };
            let chain = self.describe_chain(id, "parse");
            self.chain.pop();
            let m = Self::fail(code, msg.clone(), chain);
            self.cache.insert(id, clone_fail(&m));
            return m;
        }
        if !e.inflate_ok {
            let chain = self.describe_chain(id, "inflate");
            self.chain.pop();
            let m = Self::fail("INFLATE_ERROR", "该条目 zlib 数据无法解压", chain);
            self.cache.insert(id, clone_fail(&m));
            return m;
        }

        let source = match self.sources.get(&e.source_id) {
            Some(s) => s.clone(),
            None => {
                self.chain.pop();
                return Self::fail("MISSING_SOURCE",
                    format!("源文件 id={} 字节缺失", e.source_id), self.describe_chain(id, "source"));
            }
        };

        let m = match e.obj_type.as_str() {
            "commit" | "tree" | "blob" | "tag" => {
                self.materialize_base(&e, &source.1, depth, chain_spent)
            }
            "loose" => {
                // loose rows store obj_type as concrete type; handled above.
                Self::fail("BAD_LOOSE", "loose 条目标型未知", self.describe_chain(id, "loose"))
            }
            "ofs-delta" => self.materialize_ofs(&e, &source.1, depth, chain_spent),
            "ref-delta" => self.materialize_ref(&e, &source.1, depth, chain_spent),
            other => Self::fail(
                "PARSE_ERROR",
                format!("未知对象类型 {other}"),
                self.describe_chain(id, "type"),
            ),
        };

        self.chain.pop();
        if matches!(m, Mat::Resolved { .. }) {
            self.cache.insert(id, clone_resolved(&m));
        } else if let Mat::Fail { .. } = &m {
            self.cache.insert(id, clone_fail(&m));
        }
        m
    }

    /// Inflate one entry's zlib region from its pack, or whole-file for loose.
    fn inflate_entry(&self, e: &EntryRow, pack: &[u8]) -> std::result::Result<Vec<u8>, String> {
        let start = if e.data_start == 0 && e.data_end == 0 {
            0
        } else {
            e.data_start as usize
        };
        let end = if e.data_end as usize <= pack.len() {
            e.data_end as usize
        } else {
            pack.len()
        };
        let region = if e.raw_offset == 0 {
            // loose: whole file
            pack
        } else {
            &pack[start..end]
        };
        inflate_zlib(region, self.budget.max_single_bytes as usize)
            .map(|o| o.data)
            .map_err(|er| er.to_string())
    }

    fn materialize_base(
        &mut self,
        e: &EntryRow,
        pack: &[u8],
        depth: usize,
        chain_spent: u64,
    ) -> Mat {
        let raw = match self.inflate_entry(e, pack) {
            Ok(r) => r,
            Err(er) => return Self::fail("INFLATE_ERROR", er, self.describe_chain(e.id, "inflate")),
        };
        let kind = match e.obj_type.as_str() {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            other => {
                return Self::fail("PARSE_ERROR", format!("非基础类型 {other}"),
                    self.describe_chain(e.id, "type"))
            }
        };
        // Decompression discovered half-way that the declared size lied.
        if let Some(decl) = e.declared_size {
            if decl as usize != raw.len() {
                return Self::fail(
                    "SIZE_SPOOF",
                    format!("头部声明大小 {decl}，实际解压 {} 字节（大小欺骗）", raw.len()),
                    self.describe_chain(e.id, "size"),
                );
            }
        }
        if raw.len() as u64 > self.budget.max_single_bytes {
            return Self::fail(
                "SINGLE_BUDGET",
                format!("单对象 {} 字节超过上限 {}", raw.len(), self.budget.max_single_bytes),
                self.describe_chain(e.id, "budget"),
            );
        }
        let added = raw.len() as u64;
        if chain_spent + added > self.budget.max_expand_bytes
            || self.run_spent + added > self.budget.max_expand_bytes
        {
            self.paused = true;
            return Mat::Paused;
        }
        let computed = hex::encode(git_oid(kind, &raw));
        if let Some(claim) = &e.claimed_oid {
            if claim != &computed {
                return Self::fail(
                    "OID_MISMATCH",
                    format!("还原对象 oid 为 {computed}，但 idx/路径声明 {claim}"),
                    self.describe_chain(e.id, "oid"),
                );
            }
        }
        self.run_spent += added;
        Mat::Resolved { kind, content: raw, depth, steps: vec![], spent: added }
    }
}

impl<'a> Ctx<'a> {
    /// Choose the base entry for a ref-delta, honoring pinned conflict sources.
    /// Returns `(entry_id, oid, detail)` or a fail-producing error tuple.
    fn choose_ref_base(&self, oid: &str) -> Result<(i64, String), (String, String)> {
        let rows = match self.by_oid.get(oid) {
            Some(r) if !r.is_empty() => r,
            _ => return Err((
                "MISSING_BASE".to_string(),
                format!("ref-delta 引用的外部 base {oid} 不存在（缺少 base 对象）"),
            )),
        };
        let first = &rows[0];
        let pinned = rows
            .iter()
            .find(|r| self.pins.contains(&(r.oid.clone(), r.source_id)))
            .cloned();
        let chosen = pinned.unwrap_or_else(|| first.clone());
        let detail = if rows.len() > 1 {
            format!("{} 有 {} 个候选来源，{}", oid, rows.len(),
                if self.pins.contains(&(chosen.oid.clone(), chosen.source_id)) {
                    format!("已固定 source_id={}", chosen.source_id)
                } else {
                    format!("按确定性排序选用 source_id={}", chosen.source_id)
                })
        } else {
            format!("{oid} 唯一候选 source_id={}", chosen.source_id)
        };
        Ok((chosen.entry_id, detail))
    }

    fn finish_delta(
        &mut self,
        e: &EntryRow,
        base_id: i64,
        base_ref: &str,
        edge_kind: &str,
        depth: usize,
        chain_spent: u64,
    ) -> Mat {
        // Recursively materialize the base first.
        let base_chain_spent = chain_spent;
        let base_mat = self.materialize(base_id, depth + 1, base_chain_spent);
        let (base_kind, base_content, base_depth) = match &base_mat {
            Mat::Resolved { kind, content, depth: bd, .. } => (*kind, content.clone(), *bd),
            Mat::Paused => return Mat::Paused,
            Mat::Fail { code, message, chain } => {
                let mut ch = chain.clone();
                ch.insert(0, ChainLink {
                    entry_id: e.id, obj_type: e.obj_type.clone(),
                    kind: edge_kind.into(), ref_detail: base_ref.into(),
                    reason: format!("依赖的 base(entry {base_id}) 处于 {code}: {message}"),
                });
                // A corrupt/missing base propagates as blocked for dependents.
                let code = if code == "MISSING_BASE" || code == "MISSING_SOURCE" {
                    "BASE_UNRESOLVED"
                } else {
                    "BASE_CORRUPT"
                };
                return Self::fail(code,
                    format!("base(entry {base_id}) 不可用：{message}"), ch);
            }
        };

        // Inflate this delta's own zlib region.
        let source = match self.sources.get(&e.source_id) {
            Some(s) => s.clone(),
            None => return Self::fail("MISSING_SOURCE",
                format!("源文件 id={} 缺失", e.source_id), self.describe_chain(e.id, "source")),
        };
        let delta_blob = match self.inflate_entry(e, &source.1) {
            Ok(b) => b,
            Err(er) => return Self::fail("INFLATE_ERROR", er,
                self.describe_chain(e.id, "inflate")),
        };

        if let Some(decl) = e.declared_size {
            if decl as usize != delta_blob.len() {
                return Self::fail("SIZE_SPOOF",
                    format!("delta 头部声明 {decl} 字节，实际解压 {} 字节", delta_blob.len()),
                    self.describe_chain(e.id, "size"));
            }
        }

        let ordinal = depth + 1;
        let applied = apply_delta(
            &base_content,
            &delta_blob,
            ordinal,
            base_kind.name(),
            base_ref,
            self.budget,
            self.run_spent,
        );
        let applied = match applied {
            Ok(a) => a,
            Err(er) => {
                let msg = er.to_string();
                let code = if msg.contains("budget exceeded") {
                    if msg.contains("global expand budget") {
                        self.paused = true;
                        return Mat::Paused;
                    }
                    "SINGLE_BUDGET"
                } else if msg.contains("base size mismatch") {
                    "SIZE_SPOOF"
                } else {
                    "DELTA_ERROR"
                };
                return Self::fail(code, msg, self.describe_chain(e.id, "delta"));
            }
        };

        let result = applied.output;
        let kind = base_kind; // delta preserves the underlying object type.
        if result.len() as u64 > self.budget.max_single_bytes {
            self.paused = true;
            return Mat::Paused;
        }
        if self.run_spent + result.len() as u64 > self.budget.max_expand_bytes {
            self.paused = true;
            return Mat::Paused;
        }

        let computed = hex::encode(git_oid(kind, &result));
        if let Some(claim) = &e.claimed_oid {
            if claim != &computed {
                let mut chain = self.describe_chain(e.id, "oid");
                chain.push(ChainLink {
                    entry_id: e.id, obj_type: kind.name().into(), kind: "verify".into(),
                    ref_detail: claim.clone(),
                    reason: format!("delta 还原后 oid={computed}，与声明 {claim} 不一致"),
                });
                return Self::fail("OID_MISMATCH",
                    format!("delta 还原后 oid={computed}，声明 {claim}"), chain);
            }
        }

        self.run_spent += result.len() as u64;
        let mut steps = match &base_mat {
            Mat::Resolved { steps, .. } => steps.clone(),
            _ => vec![],
        };
        steps.push(applied.record);
        Mat::Resolved {
            kind,
            content: result,
            depth: base_depth + 1,
            steps,
            spent: 0,
        }
    }

    fn materialize_ofs(
        &mut self,
        e: &EntryRow,
        _pack: &[u8],
        depth: usize,
        chain_spent: u64,
    ) -> Mat {
        let base_off = match e.ofs_base_offset {
            Some(o) if o >= 0 => o,
            _ => return Self::fail("OFS_OUT_OF_BOUNDS",
                "ofs-delta 负向距离越界，base 落在 pack 起始之前",
                self.describe_chain(e.id, "ofs")),
        };
        let base_entry = self.entries.iter().find(|x| {
            x.source_id == e.source_id && x.raw_offset == base_off
        });
        let base_entry = match base_entry {
            Some(b) => b.clone(),
            None => return Self::fail("OFS_OUT_OF_BOUNDS",
                format!("ofs-delta 指向 offset {base_off}，但该位置没有条目"),
                self.describe_chain(e.id, "ofs")),
        };
        let base_ref = format!("pack offset {base_off}");
        self.finish_delta(e, base_entry.id, &base_ref, "ofs", depth, chain_spent)
    }

    fn materialize_ref(
        &mut self,
        e: &EntryRow,
        _pack: &[u8],
        depth: usize,
        chain_spent: u64,
    ) -> Mat {
        let oid = match &e.ref_base_oid {
            Some(o) => o.clone(),
            None => return Self::fail("DELTA_ERROR", "ref-delta 缺少 base oid",
                self.describe_chain(e.id, "ref")),
        };
        let (base_id, detail) = match self.choose_ref_base(&oid) {
            Ok(v) => v,
            Err((code, msg)) => {
                let mut chain = self.describe_chain(e.id, "ref");
                chain.push(ChainLink {
                    entry_id: e.id, obj_type: e.obj_type.clone(), kind: "ref".into(),
                    ref_detail: oid.clone(), reason: msg.clone(),
                });
                return Self::fail(code, msg, chain);
            }
        };
        let base_ref = format!("ref {oid} ({detail})");
        self.finish_delta(e, base_id, &base_ref, "ref", depth, chain_spent)
    }

    /// Build a human-readable blocking chain from the current recursion stack.
    fn describe_chain(&self, terminal: i64, why: &str) -> Vec<ChainLink> {
        let mut out = Vec::new();
        for &id in &self.chain {
            if let Some(en) = self.entry(id) {
                let kind = if en.source_id == self.entry(terminal).map(|t| t.source_id).unwrap_or(-1)
                    && en.obj_type == "ofs-delta" { "ofs" }
                    else if en.obj_type == "ref-delta" { "ref" }
                    else if en.raw_offset == 0 { "loose" } else { "base" };
                let ref_detail = en.ref_base_oid.clone()
                    .or_else(|| en.ofs_base_offset.map(|o| format!("offset {o}")))
                    .unwrap_or_default();
                out.push(ChainLink {
                    entry_id: id, obj_type: en.obj_type.clone(), kind: kind.into(),
                    ref_detail, reason: String::new(),
                });
            }
        }
        if out.last().map(|l| l.entry_id) != Some(terminal) {
            if let Some(en) = self.entry(terminal) {
                out.push(ChainLink {
                    entry_id: terminal, obj_type: en.obj_type.clone(),
                    kind: why.into(), ref_detail: String::new(),
                    reason: format!("阻塞点 ({why})"),
                });
            }
        }
        out
    }
}

fn clone_resolved(m: &Mat) -> Mat {
    m.clone()
}
fn clone_fail(m: &Mat) -> Mat {
    m.clone()
}

impl Db {
    fn load_entries(&self) -> Vec<EntryRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id,source_id,COALESCE(obj_type,'unknown'),declared_size,
                        COALESCE(raw_offset,0),COALESCE(data_start,0),COALESCE(data_end,0),
                        ofs_base_offset,ref_base_oid,inflate_ok,parse_error,claimed_oid
                 FROM entries ORDER BY parse_seq ASC, id ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(EntryRow {
                    id: r.get(0)?,
                    source_id: r.get(1)?,
                    obj_type: r.get(2)?,
                    declared_size: r.get(3)?,
                    raw_offset: r.get(4)?,
                    data_start: r.get(5)?,
                    data_end: r.get(6)?,
                    ofs_base_offset: r.get(7)?,
                    ref_base_oid: r.get(8)?,
                    inflate_ok: r.get::<_, i64>(9)? != 0,
                    parse_error: r.get(10)?,
                    claimed_oid: r.get(11)?,
                })
            })
            .unwrap();
        rows.filter_map(|r| r.ok()).collect()
    }

    fn load_source_bytes(&self) -> HashMap<i64, (String, Vec<u8>)> {
        let rels: Vec<(i64, String)> = {
            let conn = self.conn.lock().unwrap();
            let mut st = conn.prepare("SELECT id,rel_path FROM sources").unwrap();
            st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };
        let mut map = HashMap::new();
        for (id, rel) in rels {
            if let Ok(bytes) = self.read_source_bytes(&rel) {
                map.insert(id, (rel, bytes));
            }
        }
        map
    }

    /// Candidates: loose entries (claimed oid) and idx-claimed pack entries.
    /// The oid used is the *declared* id; verification status is recorded
    /// separately so corrupt duplicates still surface as conflicts.
    fn load_candidates(&self) -> Vec<CandidateRow> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare(
                "SELECT e.id, e.claimed_oid, e.source_id
                 FROM entries e
                 WHERE e.claimed_oid IS NOT NULL
                 ORDER BY e.claimed_oid, e.source_id, e.id",
            )
            .unwrap();
        st.query_map([], |r| {
            Ok(CandidateRow { entry_id: r.get(0)?, oid: r.get(1)?, source_id: r.get(2)? })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn load_pins(&self, branch_id: i64) -> HashSet<(String, i64)> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT oid,source_id FROM pins WHERE branch_id=?1")
            .unwrap();
        st.query_map([branch_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn persist_resolved(
        &self,
        branch_id: i64,
        e: &EntryRow,
        kind: ObjType,
        content: &[u8],
        depth: usize,
        steps: &[crate::delta::StepRecord],
    ) -> Result<()> {
        let oid = hex::encode(git_oid(kind, content));
        let sha1 = hex::encode(crate::gitfmt::sha1_bytes(content));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO results(branch_id,entry_id,status,obj_type,size,oid,content_sha1,
                depth,error_code,error_message,blocking_chain,analysis_seq)
             VALUES(?1,?2,'resolved',?3,?4,?5,?6,?7,NULL,NULL,NULL,0)
             ON CONFLICT(branch_id,entry_id) DO UPDATE SET
               status='resolved',obj_type=excluded.obj_type,size=excluded.size,
               oid=excluded.oid,content_sha1=excluded.content_sha1,depth=excluded.depth,
               error_code=NULL,error_message=NULL,blocking_chain=NULL",
            params![branch_id, e.id, kind.name(), content.len() as i64, oid, sha1, depth as i64],
        )?;
        tx.execute("DELETE FROM steps WHERE branch_id=?1 AND entry_id=?2",
            params![branch_id, e.id])?;
        for s in steps {
            tx.execute(
                "INSERT INTO steps(branch_id,entry_id,ordinal,base_kind,base_ref,
                    instr_start,instr_end,copy_ops,insert_ops,input_len,output_len,
                    expected_size,check_ok,detail)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    branch_id, e.id, s.ordinal as i64, s.base_kind, s.base_ref,
                    s.instr_start as i64, s.instr_end as i64, s.copy_ops as i64,
                    s.insert_ops as i64, s.input_len as i64, s.output_len as i64,
                    s.expected_result_size as i64, s.check_ok as i64, s.detail
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO contents(branch_id,entry_id,content) VALUES(?1,?2,?3)
             ON CONFLICT(branch_id,entry_id) DO UPDATE SET content=excluded.content",
            params![branch_id, e.id, content],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn persist_unresolved(
        &self,
        branch_id: i64,
        e: &EntryRow,
        status: &str,
        code: &str,
        message: &str,
        chain: Vec<ChainLink>,
    ) -> Result<()> {
        let chain_json = serde_json::to_string(&chain).unwrap_or_else(|_| "[]".into());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO results(branch_id,entry_id,status,obj_type,size,oid,content_sha1,
               depth,error_code,error_message,blocking_chain,analysis_seq)
             VALUES(?1,?2,?3,?4,NULL,NULL,NULL,NULL,?5,?6,?7,0)
             ON CONFLICT(branch_id,entry_id) DO UPDATE SET status=excluded.status,
               obj_type=excluded.obj_type,error_code=excluded.error_code,
               error_message=excluded.error_message,blocking_chain=excluded.blocking_chain",
            params![branch_id, e.id, status, e.obj_type, code, message, chain_json],
        )?;
        conn.execute("DELETE FROM steps WHERE branch_id=?1 AND entry_id=?2",
            params![branch_id, e.id])?;
        conn.execute("DELETE FROM contents WHERE branch_id=?1 AND entry_id=?2",
            params![branch_id, e.id])?;
        Ok(())
    }
}

impl Db {
    /// Forward dependency closure: entries that (transitively) depend on any
    /// entry in `roots` through ofs/ref delta edges.
    pub fn dependents_closure(&self, roots: &[i64]) -> HashSet<i64> {
        let entries = self.load_entries();
        // base entry -> deltas pointing at it
        let mut ofs_fwd: HashMap<(i64, i64), Vec<i64>> = HashMap::new();
        let mut oid_of_entry: HashMap<i64, String> = HashMap::new();
        let mut ref_fwd: HashMap<String, Vec<i64>> = HashMap::new();
        for e in &entries {
            if let Some(claim) = &e.claimed_oid {
                oid_of_entry.insert(e.id, claim.clone());
            }
        }
        for e in &entries {
            match e.obj_type.as_str() {
                "ofs-delta" => {
                    if let Some(off) = e.ofs_base_offset {
                        if let Some(base) = entries.iter().find(|b| {
                            b.source_id == e.source_id && b.raw_offset == off
                        }) {
                            ofs_fwd.entry((e.source_id, off)).or_default().push(e.id);
                            let _ = base;
                        }
                    }
                }
                "ref-delta" => {
                    if let Some(oid) = &e.ref_base_oid {
                        ref_fwd.entry(oid.clone()).or_default().push(e.id);
                    }
                }
                _ => {}
            }
        }

        let mut affected: HashSet<i64> = roots.iter().copied().collect();
        let mut queue: Vec<i64> = roots.to_vec();
        while let Some(id) = queue.pop() {
            // anyone using `id` as ofs base (same source, matching offset)
            if let Some(en) = entries.iter().find(|x| x.id == id) {
                if let Some(list) = ofs_fwd.get(&(en.source_id, en.raw_offset)) {
                    for &d in list {
                        if affected.insert(d) {
                            queue.push(d);
                        }
                    }
                }
                if let Some(oid) = oid_of_entry.get(&id) {
                    if let Some(list) = ref_fwd.get(oid) {
                        for &d in list {
                            if affected.insert(d) {
                                queue.push(d);
                            }
                        }
                    }
                }
            }
        }
        affected
    }

    /// Recompute only the dependency subgraph affected by `roots`.
    /// Resolved objects outside the closure keep their analysis_seq (untouched).
    pub fn analyze_subgraph(&self, branch_id: i64, roots: &[i64]) -> Result<AnalyzeReport> {
        let affected = self.dependents_closure(roots);
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction()?;
            for id in &affected {
                tx.execute("DELETE FROM results WHERE branch_id=?1 AND entry_id=?2",
                    params![branch_id, id])?;
                tx.execute("DELETE FROM steps WHERE branch_id=?1 AND entry_id=?2",
                    params![branch_id, id])?;
                tx.execute("DELETE FROM contents WHERE branch_id=?1 AND entry_id=?2",
                    params![branch_id, id])?;
            }
            tx.commit()?;
        }
        self.analyze_branch_scoped(branch_id, Some(&affected))
    }

    pub fn pin_source(&self, branch_id: i64, oid: &str, source_id: i64) -> Result<HashSet<i64>> {
        let entry_id: i64 = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT id FROM entries WHERE source_id=?1 AND claimed_oid=?2
                 ORDER BY id LIMIT 1",
                params![source_id, oid], |r| r.get(0))?
        };
        {
            let mut conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO pins(branch_id,oid,source_id,entry_id) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(branch_id,oid) DO UPDATE SET source_id=excluded.source_id,
                   entry_id=excluded.entry_id",
                params![branch_id, oid, source_id, entry_id],
            )?;
        }
        let roots = vec![entry_id];
        self.analyze_subgraph(branch_id, &roots)?;
        Ok(self.dependents_closure(&roots))
    }

    pub fn unpin_source(&self, branch_id: i64, oid: &str) -> Result<HashSet<i64>> {
        let roots: Vec<i64> = {
            let conn = self.conn.lock().unwrap();
            let ids = conn
                .prepare("SELECT id FROM entries WHERE claimed_oid=?1")
                .unwrap()
                .query_map([oid], |r| r.get::<_, i64>(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            ids
        };
        {
            let mut conn = self.conn.lock().unwrap();
            conn.execute("DELETE FROM pins WHERE branch_id=?1 AND oid=?2",
                params![branch_id, oid])?;
        }
        if !roots.is_empty() {
            self.analyze_subgraph(branch_id, &roots)?;
        }
        Ok(self.dependents_closure(&roots))
    }

    /// Objects that currently depend (directly or transitively) on a source.
    /// Used to warn before deleting a source file.
    pub fn source_dependents(&self, source_id: i64) -> Vec<serde_json::Value> {
        let entries = self.load_entries();
        let roots: Vec<i64> = entries.iter().filter(|e| e.source_id == source_id).map(|e| e.id).collect();
        let closure = self.dependents_closure(&roots);
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        for id in closure {
            if let Ok((oid, status, typ)) = conn.query_row(
                "SELECT COALESCE(oid,claimed_oid),COALESCE(status,'pending'),
                        COALESCE(obj_type,'?')
                 FROM entries e LEFT JOIN results r
                   ON r.entry_id=e.id AND r.branch_id=1
                 WHERE e.id=?1",
                [id], |r| Ok((r.get::<_, Option<String>>(0)?,
                              r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            {
                out.push(serde_json::json!({
                    "entry_id": id, "oid": oid, "status": status, "obj_type": typ
                }));
            }
        }
        out
    }

    /// Delete a source and its entries; returns affected oid list.
    pub fn delete_source(&self, source_id: i64) -> Result<usize> {
        let rel: String = {
            let conn = self.conn.lock().unwrap();
            conn.query_row("SELECT rel_path FROM sources WHERE id=?1", [source_id],
                |r| r.get(0))?
        };
        let entries = self.load_entries();
        let roots: Vec<i64> = entries.iter().filter(|e| e.source_id == source_id).map(|e| e.id).collect();
        let affected = self.dependents_closure(&roots);
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction()?;
            for id in &affected {
                tx.execute("DELETE FROM results WHERE entry_id=?1", [id])?;
                tx.execute("DELETE FROM steps WHERE entry_id=?1", [id])?;
                tx.execute("DELETE FROM contents WHERE entry_id=?1", [id])?;
            }
            tx.execute("DELETE FROM pins WHERE source_id=?1", [source_id])?;
            tx.execute("DELETE FROM entries WHERE source_id=?1", [source_id])?;
            tx.execute("DELETE FROM sources WHERE id=?1", [source_id])?;
            tx.commit()?;
        }
        let _ = std::fs::remove_file(self.files_dir.join(&rel));
        self.invalidate_branches();
        let _ = self.analyze_branch(1);
        Ok(affected.len())
    }
}
