//! delta DAG 还原引擎。
//!
//! 核心保证：
//! * 单个坏对象被隔离（error/blocked/paused），其余对象继续分析；
//! * 环、缺 base、越界、伪造大小、坏 CRC 等都落成证据与“阻塞链”；
//! * 预算超限时写 `paused`（可重试），半成品内容绝不入库为完整对象；
//! * 同一 oid 多候选时按确定性规则排序（与导入顺序无关），分支可用 pin 固定来源；
//! * 增量重算：只重跑被影响的依赖子图。

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::json;

use crate::budget::{BudgetConfig, RunGuard};
use crate::delta::{apply_delta, DeltaError, DeltaStep as ParsedStep};
use crate::hash::{git_object_id, hex20};
use crate::store::{
    obj_code, CandidateBranchRow, CandidateMeta, Store, CB_BLOCKED, CB_COMPLETE, CB_ERROR, CB_FRESH, CB_PAUSED,
};
use crate::types::ObjType;

#[derive(Debug, Clone, Serialize)]
pub struct ResolveSummary {
    pub branch: String,
    pub complete: usize,
    pub blocked: usize,
    pub paused: usize,
    pub error: usize,
    pub fresh: usize,
    pub used_total_bytes: u64,
    pub paused_reasons: Vec<String>,
    /// 本次运行是否被预算打断（仍有可重试对象）。
    pub interrupted: bool,
    /// 受影响而被重新计算的候选数。
    pub recomputed: usize,
}

pub struct Resolver<'a> {
    store: &'a Store,
    branch_id: i64,
    guard: RunGuard,
    /// 当前正在递归的候选（环检测）。
    stack: Vec<i64>,
    /// 本次运行已解析缓存：candidate_id -> 成品（类型, oid, body）。
    memo: HashMap<i64, (ObjType, String, Vec<u8>)>,
    /// 本次运行被判定 paused/error/blocked 的集合（避免无限递归）。
    failed: HashSet<i64>,
    /// pinned: oid -> candidate_id（仅本分支）。
    pinned: HashMap<String, i64>,
    /// 每个候选最后使用的 base（用于增量依赖子图）。
    used_base: HashMap<i64, i64>,
    paused_reasons: HashSet<String>,
    pub recomputed: HashSet<i64>,
    interrupted: bool,
}

/// 递归解析一个候选的结果。
enum Resolved {
    Done(ObjType, String, Vec<u8>),
    Blocked(Vec<BlockedHop>),
    Paused { reason: String, detail: serde_json::Value },
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
struct BlockedHop {
    candidate_id: i64,
    stype: String,
    base_ref: String,
    reason: String,
}

impl<'a> Resolver<'a> {
    pub fn new(store: &'a Store, branch_name: &str, cfg: BudgetConfig) -> Option<Self> {
        let branch = store.branch_by_name(branch_name)?;
        let pinned = parse_pinned(&branch.pinned_json);
        let used_total = store.total_used_bytes(branch.id);
        Some(Resolver {
            store,
            branch_id: branch.id,
            guard: RunGuard::new(cfg, used_total),
            stack: Vec::new(),
            memo: HashMap::new(),
            failed: HashSet::new(),
            pinned,
            used_base: HashMap::new(),
            paused_reasons: HashSet::new(),
            recomputed: HashSet::new(),
            interrupted: false,
        })
    }

    fn stype_of(&self, id: i64) -> String {
        self.store.candidate_meta(id).map(|c| c.stype).unwrap_or_else(|| "missing".into())
    }

    /// 选择 base 候选：pin 优先，否则确定性排序。返回 `(候选, 是否多源冲突)`。
    fn choose_base(&self, oid: &str) -> Option<(CandidateMeta, bool)> {
        let mut cands = self.store.candidates_for_oid(oid);
        if cands.is_empty() {
            return None;
        }
        if let Some(&pid) = self.pinned.get(oid) {
            if let Some(c) = cands.iter().find(|c| c.id == pid) {
                return Some((c.clone(), cands.len() > 1));
            }
        }
        sort_candidates(&mut cands);
        let conflict = cands.len() > 1;
        Some((cands.remove(0), conflict))
    }

    /// 解析单个候选（带 memo / 状态短路）。
    fn resolve_id(&mut self, id: i64) -> Resolved {
        if let Some(v) = self.memo.get(&id) {
            return Resolved::Done(v.0, v.1.clone(), v.2.clone());
        }
        if self.failed.contains(&id) {
            // 失败原因已写入 cb 行；这里用 error 短路即可。
            return Resolved::Error("依赖对象已处于失败/暂停/阻塞状态".into());
        }
        if let Some(pos) = self.stack.iter().position(|&x| x == id) {
            let chain: Vec<i64> = self.stack[pos..].to_vec();
            return Resolved::Error(format!("检测到 delta 环：{} -> {id}", chain_str(&chain)));
        }
        let cand = match self.store.candidate_meta(id) {
            Some(c) => c,
            None => return Resolved::Error("候选对象不存在".into()),
        };
        self.stack.push(id);
        let result = self.resolve_inner(&cand);
        self.stack.pop();

        match &result {
            Resolved::Done(t, oid, body) => {
                self.memo.insert(id, (*t, oid.clone(), body.clone()));
            }
            Resolved::Paused { .. } | Resolved::Blocked(_) | Resolved::Error(_) => {
                self.failed.insert(id);
            }
        }
        result
    }

    fn resolve_inner(&mut self, cand: &CandidateMeta) -> Resolved {
        // 解析层（压缩/结构）硬错误直接隔离。
        if cand.parse_state == "error" {
            return Resolved::Error(format!("候选 {} 解析层已标记错误", cand.id));
        }
        let stype = parse_stype(&cand.stype);

        if !cand.delta {
            // 普通对象：body 已在导入时解压得到。校验类型/大小并重算 oid。
            if matches!(stype, ObjType::Bad) {
                return Resolved::Error("对象类型字段非法（保留值）".into());
            }
            let (body, _delta) = match self.store.candidate_payload(cand.id) {
                Some(v) => v,
                None => return Resolved::Error("对象内容缺失".into()),
            };
            if cand.declared_size as usize != body.len() {
                return Resolved::Error(format!(
                    "大小欺骗：声明 {} 实际 {}",
                    cand.declared_size,
                    body.len()
                ));
            }
            let oid = match git_object_id(stype, &body) {
                Some(o) => hex20(&o),
                None => return Resolved::Error("无法计算对象 id（类型非法）".into()),
            };
            if let Some(exp) = &cand.oid {
                if !exp.eq_ignore_ascii_case(&oid) {
                    // index/loose 路径给出的 oid 与内容不符：隔离并取证。
                    return Resolved::Error(format!("oid_mismatch：索引/路径 oid {exp} 与重算 {oid} 不符"));
                }
            }
            return Resolved::Done(stype, oid, body);
        }

        // delta 对象：先找 base。
        let depth = self.stack.len() as u32;
        let (base_cand, base_ref_label) = if stype == ObjType::OfsDelta {
            let off = cand.base_offset.unwrap_or(-1);
            match self.store.candidate_by_source_offset(cand.source_id, off) {
                Some(c) => (c, format!("ofs->pack_offset={off}")),
                None => {
                    return Resolved::Blocked(vec![BlockedHop {
                        candidate_id: cand.id,
                        stype: cand.stype.clone(),
                        base_ref: format!("ofs->pack_offset={off}"),
                        reason: "ofs 距离越界或 pack 内该偏移没有对象（base 缺失）".into(),
                    }])
                }
            }
        } else if stype == ObjType::RefDelta {
            let base_oid = cand.base_oid.clone().unwrap_or_default();
            match self.choose_base(&base_oid) {
                Some((c, _conflict)) => (c, format!("ref->{base_oid}")),
                None => {
                    return Resolved::Blocked(vec![BlockedHop {
                        candidate_id: cand.id,
                        stype: cand.stype.clone(),
                        base_ref: format!("ref->{base_oid}"),
                        reason: "外部 base 尚未导入".into(),
                    }])
                }
            }
        } else {
            return Resolved::Error("delta 候选的存储类型既不是 ofs 也不是 ref".into());
        };

        let base_id = base_cand.id;
        self.used_base.insert(cand.id, base_id);

        // 递归还原 base。
        let base_result = self.resolve_id(base_id);
        let (base_type, base_oid, base_body) = match base_result {
            Resolved::Done(t, o, b) => (t, o, b),
            Resolved::Blocked(chain) => {
                let mut chain = chain;
                chain.insert(0, BlockedHop {
                    candidate_id: cand.id,
                    stype: cand.stype.clone(),
                    base_ref: base_ref_label,
                    reason: "base 自身被阻塞".into(),
                });
                return Resolved::Blocked(chain);
            }
            Resolved::Paused { reason, detail } => return Resolved::Paused { reason, detail },
            Resolved::Error(e) => {
                return Resolved::Blocked(vec![BlockedHop {
                    candidate_id: cand.id,
                    stype: cand.stype.clone(),
                    base_ref: base_ref_label,
                    reason: format!("base 不可用：{e}"),
                }])
            }
        };

        // 取 delta 指令并应用。
        let (_body, delta_bytes) = match self.store.candidate_payload(cand.id) {
            Some(v) => v,
            None => return Resolved::Error("delta 指令缺失".into()),
        };

        let applied = apply_delta(&base_body, &delta_bytes, depth, &mut self.guard);
        match applied {
            Ok(res) => {
                self.store.clear_steps(self.branch_id, cand.id);
                write_steps(self.store, self.branch_id, cand.id, base_id, &base_oid, depth, &base_body, &res.output, &res.steps);
                self.store.upsert_edge(self.branch_id, cand.id, base_id, &cand.stype);
                let target_type = base_type; // delta 不改变对象类型
                let oid = match git_object_id(target_type, &res.output) {
                    Some(o) => hex20(&o),
                    None => return Resolved::Error("还原结果类型非法，无法计算 oid".into()),
                };
                if let Some(exp) = &cand.oid {
                    if !exp.eq_ignore_ascii_case(&oid) {
                        return Resolved::Error(format!("oid_mismatch：索引 oid {exp} 与 delta 还原结果 {oid} 不符"));
                    }
                }
                Resolved::Done(target_type, oid, res.output)
            }
            Err((DeltaError::BudgetExceeded { reason, .. }, steps, hdr)) => {
                self.store.clear_steps(self.branch_id, cand.id);
                write_steps(self.store, self.branch_id, cand.id, base_id, &base_oid, depth, &base_body, &[], &steps);
                self.store.upsert_edge(self.branch_id, cand.id, base_id, &cand.stype);
                self.paused_reasons.insert(reason.clone());
                self.interrupted = true;
                Resolved::Paused {
                    reason: "budget".into(),
                    detail: json!({
                        "reason": reason,
                        "depth": depth,
                        "declared_target_size": hdr.target_size,
                        "hint": "提高预算或稍后重试；已还原的上游对象会被复用，不会产生半成品对象",
                    }),
                }
            }
            Err((dlerr, steps, _hdr)) => {
                self.store.clear_steps(self.branch_id, cand.id);
                write_steps(self.store, self.branch_id, cand.id, base_id, &base_oid, depth, &base_body, &[], &steps);
                self.store.upsert_edge(self.branch_id, cand.id, base_id, &cand.stype);
                Resolved::Error(dlerr.message())
            }
        }
    }

    /// 把解析结果落到 candidate_branch / candidates。
    fn persist(&self, cand_id: i64, result: &Resolved, generation: i64) {
        let mut row = self
            .store
            .cb_row(self.branch_id, cand_id)
            .unwrap_or_else(|| CandidateBranchRow {
                branch_id: self.branch_id,
                candidate_id: cand_id,
                status: CB_FRESH.into(),
                final_type: None,
                oid: None,
                body_len: None,
                generation,
                blocked_chain_json: "[]".into(),
                pause_json: "{}".into(),
            });
        row.generation = generation;
        match result {
            Resolved::Done(t, oid, body) => {
                self.store.commit_candidate_content(cand_id, t.code(), oid, body);
                row.status = CB_COMPLETE.into();
                row.final_type = Some(t.code().to_string());
                row.oid = Some(oid.clone());
                row.body_len = Some(body.len() as i64);
                row.blocked_chain_json = "[]".into();
                row.pause_json = "{}".into();
            }
            Resolved::Blocked(chain) => {
                row.status = CB_BLOCKED.into();
                row.final_type = None;
                row.body_len = None;
                row.blocked_chain_json = serde_json::to_string(chain).unwrap_or_else(|_| "[]".into());
                row.pause_json = "{}".into();
            }
            Resolved::Paused { reason, detail } => {
                row.status = CB_PAUSED.into();
                row.body_len = None;
                row.pause_json = json!({ "kind": reason, "detail": detail }).to_string();
            }
            Resolved::Error(msg) => {
                self.store.mark_candidate_parse_error(cand_id);
                row.status = CB_ERROR.into();
                row.final_type = None;
                row.body_len = None;
                row.blocked_chain_json = json!([{ "candidate_id": cand_id, "reason": msg }]).to_string();
                row.pause_json = "{}".into();
            }
        }
        self.store.upsert_cb(&row);
    }

    /// 全量/给定集合解析。`roots` 给出需要重算的候选集合；None 表示所有候选。
    pub fn run(&mut self, roots: Option<HashSet<i64>>, generation: i64) -> ResolveSummary {
        let cands = self.store.all_candidates();
        let ids: Vec<i64> = cands.iter().map(|c| c.id).collect();
        let root_set = roots.unwrap_or_else(|| ids.iter().copied().collect());

        for id in &ids {
            if !root_set.contains(id) {
                continue;
            }
            // 强制重算：清掉旧的 cb 状态与边，保证增量结果与全量一致。
            self.store.delete_candidate_edges(self.branch_id, *id);
            self.recomputed.insert(*id);
        }

        // 顺序解析；memo 复用本运行已还原的上游。
        for id in ids.iter().filter(|i| root_set.contains(i)) {
            let result = self.resolve_id(*id);
            self.persist(*id, &result, generation);
        }

        // 统计：blocked 链 / paused 详情来自 cb 表。
        let mut counts = HashMap::new();
        for r in self.store.cb_rows_for_branch(self.branch_id) {
            *counts.entry(r.status).or_insert(0usize) += 1;
        }
        let used_total_bytes = self.store.total_used_bytes(self.branch_id);
        ResolveSummary {
            branch: self.store
                .branches()
                .into_iter()
                .find(|b| b.id == self.branch_id)
                .map(|b| b.name)
                .unwrap_or_default(),
            complete: *counts.get(CB_COMPLETE).unwrap_or(&0),
            blocked: *counts.get(CB_BLOCKED).unwrap_or(&0),
            paused: *counts.get(CB_PAUSED).unwrap_or(&0),
            error: *counts.get(CB_ERROR).unwrap_or(&0),
            fresh: *counts.get(CB_FRESH).unwrap_or(&0),
            used_total_bytes,
            paused_reasons: self.paused_reasons.iter().cloned().collect(),
            interrupted: self.interrupted || counts.get(CB_PAUSED).copied().unwrap_or(0) > 0,
            recomputed: self.recomputed.len(),
        }
    }

    pub fn used_base(&self) -> &HashMap<i64, i64> {
        &self.used_base
    }
}

/* ---------------- 增量：求受影响的依赖子图 ---------------- */

/// 给定“新出现/更新的 base 候选 id 集合”，返回所有受影响的 delta 候选闭包。
/// 依赖关系来自 edges（旧）与 candidates 中仍声明的 base_offset/base_oid（新）。
pub fn affected_subgraph(store: &Store, changed_base_ids: &[i64]) -> HashSet<i64> {
    let all = store.all_candidates();
    // oid -> candidate ids（非 delta 的候选才有资格当 base）
    let mut oid_index: HashMap<String, Vec<i64>> = HashMap::new();
    for c in &all {
        if !c.delta {
            if let Some(o) = &c.oid {
                oid_index.entry(o.to_lowercase()).or_default().push(c.id);
            }
        }
    }
    // offset base 直接按 (source, offset)。
    let by_off: HashMap<(i64, i64), i64> = all
        .iter()
        .filter_map(|c| c.pack_offset.map(|o| ((c.source_id, o), c.id)))
        .collect();

    // changed base oids
    let changed_oids: HashSet<String> = changed_base_ids
        .iter()
        .filter_map(|id| store.candidate_meta(*id).and_then(|c| c.oid.map(|o| o.to_lowercase())))
        .collect();

    let mut affected = HashSet::new();
    let mut queue: Vec<i64> = changed_base_ids.to_vec();
    while let Some(base_id) = queue.pop() {
        let base = match store.candidate_meta(base_id) {
            Some(b) => b,
            None => continue,
        };
        for c in &all {
            if !c.delta || affected.contains(&c.id) {
                continue;
            }
            let depends = match c.stype.as_str() {
                "ofs_delta" => c
                    .base_offset
                    .map(|o| by_off.get(&(c.source_id, o)).copied() == Some(base_id))
                    .unwrap_or(false),
                "ref_delta" => c
                    .base_oid
                    .as_ref()
                    .map(|bo| {
                        let bo = bo.to_lowercase();
                        bo == base.oid.clone().unwrap_or_default().to_lowercase() || changed_oids.contains(&bo)
                    })
                    .unwrap_or(false),
                _ => false,
            };
            if depends {
                affected.insert(c.id);
                queue.push(c.id);
            }
        }
    }
    affected
}

/* ---------------- 确定性候选排序 ---------------- */

/// 与导入顺序无关的排序键：rank_score 高优先；oid 非空优先；证据少优先；
/// 之后用 content_sig、source_id、offset、id 做稳定 tie-break。
pub fn sort_candidates(cands: &mut Vec<CandidateMeta>) {
    cands.sort_by(|a, b| {
        b.rank_score
            .cmp(&a.rank_score)
            .then_with(|| b.oid.is_some().cmp(&a.oid.is_some()))
            .then_with(|| evidence_count(&a.evidence_json).cmp(&evidence_count(&b.evidence_json)))
            .then_with(|| a.content_sig.cmp(&b.content_sig))
            .then_with(|| a.source_id.cmp(&b.source_id))
            .then_with(|| a.pack_offset.unwrap_or(-1).cmp(&b.pack_offset.unwrap_or(-1)))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn evidence_count(json: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

fn parse_stype(code: &str) -> ObjType {
    match code {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        "ofs_delta" => ObjType::OfsDelta,
        "ref_delta" => ObjType::RefDelta,
        _ => ObjType::Bad,
    }
}

fn parse_pinned(json_str: &str) -> HashMap<String, i64> {
    let v: serde_json::Value = serde_json::from_str(json_str).unwrap_or(serde_json::Value::Object(Default::default()));
    let mut m = HashMap::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if let Some(id) = val.as_i64() {
                m.insert(k.to_lowercase(), id);
            }
        }
    }
    m
}

fn chain_str(chain: &[i64]) -> String {
    chain.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" -> ")
}

fn write_steps(
    store: &Store,
    branch_id: i64,
    cand_id: i64,
    base_id: i64,
    base_oid: &str,
    depth: u32,
    base: &[u8],
    output: &[u8],
    steps: &[ParsedStep],
) {
    for s in steps {
        let check = json!({
            "base_len": base.len(),
            "stage_output_len": output.len(),
            "op_in_bounds": s.ok,
            "input_len_so_far": s.out_before + s.length,
        });
        store.lock()
            .execute(
                "INSERT OR REPLACE INTO delta_steps(branch_id,candidate_id,seq,depth,base_candidate_id,base_oid,
                    kind,op_start,op_len,src_offset,length,out_before,out_after,input_len,output_len,ok,note,check_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                rusqlite::params![
                    branch_id,
                    cand_id,
                    s.seq,
                    depth,
                    base_id,
                    base_oid,
                    s.kind.code(),
                    s.op_start as i64,
                    s.op_len as i64,
                    s.src_offset as i64,
                    s.length as i64,
                    s.out_before as i64,
                    s.out_after as i64,
                    base.len() as i64,
                    output.len() as i64,
                    s.ok as i64,
                    s.note,
                    check.to_string()
                ],
            )
            .unwrap();
    }
}

impl StepKind {
    fn code(self) -> &'static str {
        match self {
            StepKind::Copy => "copy",
            StepKind::Insert => "insert",
        }
    }
}

use crate::delta::StepKind;

/// 读取预算配置（settings 表，缺省用默认）。
pub fn load_budget(store: &Store) -> BudgetConfig {
    let mut cfg = BudgetConfig::default();
    let c = store.lock();
    let get = |key: &str| -> Option<String> {
        c.query_row("SELECT value FROM settings WHERE key=?1", rusqlite::params![key], |r| r.get(0))
            .ok()
    };
    if let Some(v) = get("max_depth").and_then(|s| s.parse().ok()) {
        cfg.max_depth = v;
    }
    if let Some(v) = get("max_total_bytes").and_then(|s| s.parse().ok()) {
        cfg.max_total_bytes = v;
    }
    if let Some(v) = get("max_obj_ratio").and_then(|s| s.parse().ok()) {
        cfg.max_obj_ratio = v;
    }
    if let Some(v) = get("max_obj_bytes").and_then(|s| s.parse().ok()) {
        cfg.max_obj_bytes = v;
    }
    cfg
}

pub fn save_budget(store: &Store, cfg: &BudgetConfig) {
    let c = store.lock();
    for (k, v) in [
        ("max_depth", cfg.max_depth.to_string()),
        ("max_total_bytes", cfg.max_total_bytes.to_string()),
        ("max_obj_ratio", cfg.max_obj_ratio.to_string()),
        ("max_obj_bytes", cfg.max_obj_bytes.to_string()),
    ] {
        c.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![k, v],
        )
        .unwrap();
    }
}

/// 便捷入口：对指定分支做一次 resolve（全量）。
pub fn resolve_branch(store: &Store, branch: &str) -> Option<ResolveSummary> {
    let cfg = load_budget(store);
    let mut r = Resolver::new(store, branch, cfg)?;
    Some(r.run(None, 0))
}

/// 对任意命名分支做一次全量 resolve。
pub fn resolve_branch_named(store: &Store, branch: &str) -> Option<ResolveSummary> {
    let cfg = load_budget(store);
    let mut r = Resolver::new(store, branch, cfg)?;
    Some(r.run(None, 0))
}

/// 便捷入口：只重算受影响的子图。
pub fn resolve_subgraph(store: &Store, branch: &str, changed_base_ids: &[i64]) -> Option<ResolveSummary> {
    let cfg = load_budget(store);
    let roots = affected_subgraph(store, changed_base_ids);
    let mut r = Resolver::new(store, branch, cfg)?;
    let bid = r.branch_id;
    let gen = store.cb_rows_for_branch(bid).iter().map(|x| x.generation).max().unwrap_or(0) + 1;
    Some(r.run(Some(roots), gen))
}

#[allow(dead_code)]
fn keep_imports(_: &dyn std::any::Any) {}

// 让 obj_code 在某些编译配置下保持引用。
#[allow(dead_code)]
fn obj_type_code(t: ObjType) -> String {
    obj_code(t)
}
