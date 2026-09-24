//! 纯解析逻辑：在候选图上沿 ofs/ref delta 边解析对象。
//!
//! 设计要点：
//! - 不调用系统 git；delta 应用与 object id 全部本 crate 完成。
//! - 坏对象被隔离为 Error，不影响其他对象。
//! - 缺 base → Blocked 并列出阻塞链；delta 环 → Cycle。
//! - 预算超限 → Paused（可重试），且绝不返回部分输出。

use std::collections::{HashMap, HashSet};

use crate::delta::apply_delta;
use crate::gitobj::hash_object;
use crate::models::{Budget, Candidate, CandidateKind, ResolveStatus, Resolution, Step};
use crate::oid::{ObjType, Oid};

#[derive(Clone, Debug)]
pub enum ResolveError {
    /// 缺少 base：参数为缺失的 ref oid 或 ofs 偏移描述。
    MissingBase(String),
    /// 候选自身损坏（CRC / size / delta 指令错误）。
    Corrupt(String),
    /// 环：给出链上候选 id。
    Cycle(Vec<i64>),
    /// 预算耗尽（可重试），给出原因。
    Paused(String),
    /// 深度超限（可重试/需更大预算）。
    Depth(usize),
}

pub struct Graph<'a> {
    pub candidates: &'a HashMap<i64, Candidate>,
    /// (pack source id, offset) -> candidate id，用于 ofs-delta。
    pub by_pack_offset: HashMap<(i64, u64), i64>,
    /// claimed oid -> 候选 id 列表（rank_candidates_for_oid 排序）。
    pub by_oid: HashMap<Oid, Vec<i64>>,
}

impl<'a> Graph<'a> {
    pub fn build(candidates: &'a HashMap<i64, Candidate>) -> Graph<'a> {
        let mut by_pack_offset = HashMap::new();
        let mut by_oid: HashMap<Oid, Vec<i64>> = HashMap::new();
        for (id, c) in candidates.iter() {
            if c.kind == CandidateKind::PackEntry {
                if let Some(off) = c.pack_offset {
                    by_pack_offset.insert((c.source_id, off), *id);
                }
            }
            if let Some(oid) = c.claimed_oid {
                by_oid.entry(oid).or_default().push(*id);
            }
        }
        Graph {
            candidates,
            by_pack_offset,
            by_oid,
        }
    }
}

/// 对某个 oid 的候选按确定性规则排序（与导入顺序无关）。
/// pinned（分析分支固定）最先；随后完整且 actual 命中 > 完整但不命中 >
/// delta/损坏；再按 (kind, source_id, offset, id) 稳定排序。
pub fn rank_candidates_for_oid(graph: &Graph, oid: Oid, pins: &HashMap<Oid, i64>) -> Vec<i64> {
    let mut ids: Vec<i64> = graph
        .by_oid
        .get(&oid)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    ids.sort_by(|&a, &b| {
        let ca = &graph.candidates[&a];
        let cb = &graph.candidates[&b];
        let rank = |c: &Candidate| -> i32 {
            let full = !matches!(c.obj_type, ObjType::OfsDelta | ObjType::RefDelta);
            let actual_hit = c.actual_oid == Some(oid);
            match (full && c.parse_ok, actual_hit) {
                (true, true) => 0,
                (true, false) => 1,
                (false, _) => 2,
            }
        };
        let pinned = |id: i64| pins.get(&oid) == Some(&id);
        pinned(b)
            .cmp(&pinned(a))
            .then(rank(ca).cmp(&rank(cb)))
            .then(kind_rank(ca).cmp(&kind_rank(cb)))
            .then(ca.source_id.cmp(&cb.source_id))
            .then(offset_of(ca).cmp(&offset_of(cb)))
            .then(a.cmp(&b))
    });
    ids
}

fn kind_rank(c: &Candidate) -> u8 {
    match c.kind {
        CandidateKind::Loose => 0,
        CandidateKind::PackEntry => 1,
    }
}

fn offset_of(c: &Candidate) -> i64 {
    c.pack_offset.map(|v| v as i64).unwrap_or(-1)
}

#[derive(Clone, Debug)]
pub struct ResolvedNode {
    pub status: ResolveStatus,
    pub actual_oid: Option<Oid>,
    pub out_type: Option<ObjType>,
    pub output: Option<Vec<u8>>,
    pub out_len: u64,
    pub chain_len: usize,
    pub steps: Vec<Step>,
    pub error: Option<String>,
    pub blocked_chain: Vec<i64>,
    /// 本候选最终产出的字节（resolved 时等于 out_len，用于预算累计；
    /// 同一次运行中通过 charged 集合保证只计一次）。
    pub spent: u64,
}

struct Solver<'a> {
    graph: &'a Graph<'a>,
    budget: Budget,
    /// 全局累计已展开字节（含本次调用前的历史值）。
    global_spent: u64,
    pins: &'a HashMap<Oid, i64>,
    stack: Vec<i64>,
    /// 本次运行已计费的候选，避免 base 被复用而重复计费。
    charged: HashSet<i64>,
}

/// 解析入口：返回最终节点状态。
/// - `global_spent`：本次运行前的历史累计已展开字节；
/// - `precharged`：调用前已 resolved 的候选 id，其输出计入历史累计、不再重复计费。
pub fn resolve_candidate(
    graph: &Graph,
    id: i64,
    budget: Budget,
    global_spent: u64,
    pins: &HashMap<Oid, i64>,
    precharged: &HashSet<i64>,
) -> ResolvedNode {
    let mut solver = Solver {
        graph,
        budget,
        global_spent,
        pins,
        stack: Vec::new(),
        charged: precharged.clone(),
    };
    let mut on_stack: HashSet<i64> = HashSet::new();
    let mut cache: HashMap<i64, ResolvedNode> = HashMap::new();
    solver.solve(id, &mut on_stack, &mut cache)
}

impl<'a> Solver<'a> {
    fn solve(
        &mut self,
        id: i64,
        on_stack: &mut HashSet<i64>,
        cache: &mut HashMap<i64, ResolvedNode>,
    ) -> ResolvedNode {
        if let Some(n) = cache.get(&id) {
            return n.clone();
        }
        let c = match self.graph.candidates.get(&id) {
            Some(c) => c,
            None => {
                return self.terminal_error(id, "候选已不存在（源文件可能被删除）");
            }
        };

        if on_stack.contains(&id) {
            // 找到从第一次出现处开始的环。
            let start = self.stack.iter().position(|&x| x == id).unwrap_or(0);
            let mut cyc: Vec<i64> = self.stack[start..].to_vec();
            cyc.push(id);
            return self.cycle_node(c, cyc);
        }

        // 候选自身解析错误（zlib / size 欺骗 / 坏 CRC 由引擎标记）。
        if !c.parse_ok {
            return self.corrupt_node(
                c,
                c.parse_error
                    .clone()
                    .unwrap_or_else(|| "候选解析失败".to_string()),
            );
        }
        if c.crc_ok == Some(false) {
            return self.corrupt_node(c, format!("条目 CRC32 校验失败 {:08x}", c.entry_crc32.unwrap_or(0)));
        }

        let is_delta = matches!(c.obj_type, ObjType::OfsDelta | ObjType::RefDelta);
        if !is_delta {
            return self.full_node(c);
        }

        // 深度检查（不含本节点时已有 chain_len 个祖先）。
        if self.stack.len() as u64 >= self.budget.max_depth {
            return self.paused_node(
                c,
                format!("delta 深度达到预算上限 {}", self.budget.max_depth),
                self.stack.clone(),
            );
        }

        // 定位 base 候选。
        let base_id = match self.find_base(c) {
            Ok(v) => v,
            Err(ResolveError::MissingBase(desc)) => {
                let mut chain = self.stack.clone();
                chain.push(id);
                return self.blocked_node(c, format!("缺少外部 base：{desc}"), chain);
            }
            Err(other) => return self.from_error(c, other),
        };

        on_stack.insert(id);
        self.stack.push(id);
        let base_node = self.solve(base_id, on_stack, cache);
        self.stack.pop();
        on_stack.remove(&id);

        // base 非成功：传播状态并保留阻塞链。
        if base_node.status != ResolveStatus::Resolved {
            return self.propagate(c, &base_node);
        }
        let base_content = base_node.output.clone().unwrap_or_default();
        let base_type = base_node.out_type.unwrap_or(ObjType::Blob);

        // 预算预检：单对象比例 + 绝对上限 + 全局总量。
        let declared = c.declared_size;
        if declared > self.budget.per_object_cap {
            return self.paused_node(
                c,
                format!("声明目标大小 {declared} 超过单对象上限 {}", self.budget.per_object_cap),
                self.chain_with(id),
            );
        }
        let ratio = self.budget.per_object_ratio.max(1);
        let ratio_limit = (base_content.len() as u64)
            .checked_mul(ratio)
            .unwrap_or(u64::MAX)
            .max(4096);
        if declared > ratio_limit {
            return self.paused_node(
                c,
                format!(
                    "声明目标 {declared} 超过单对象比例 {}×base({})",
                    self.budget.per_object_ratio,
                    base_content.len()
                ),
                self.chain_with(id),
            );
        }
        if self.global_spent.saturating_add(declared) > self.budget.total_budget {
            return self.paused_node(
                c,
                format!(
                    "总展开预算 {} 将被突破（已用 {}，本步需 {declared}）",
                    self.budget.total_budget, self.global_spent
                ),
                self.chain_with(id),
            );
        }

        // 应用 delta。
        let applied = match apply_delta(&base_content, &c.payload) {
            Ok(v) => v,
            Err(e) => return self.corrupt_node(c, format!("delta 指令错误：{e}")),
        };
        let out_len = applied.output.len() as u64;

        // 预算实扣（只有完整成功才计）；同一候选在本次运行只计一次。
        if self.charged.insert(id) {
            self.global_spent = self.global_spent.saturating_add(out_len);
        }

        let oid = Oid(hash_object(base_type, &applied.output));
        // 构造本步取证记录。
        let instr_start = applied.header_len as u64;
        let instr_end = c.payload.len() as u64;
        let instr_json = serde_json::to_string(
            &applied
                .instructions
                .iter()
                .map(|i| serde_json::json!({
                    "kind": i.kind,
                    "op": [i.op_range.0, i.op_range.1],
                    "data": [i.data_range.0, i.data_range.1],
                    "detail": i.detail,
                }))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_string());
        let step = Step {
            step: base_node.chain_len + 1,
            base_candidate_id: Some(base_id),
            base_oid: base_node.actual_oid,
            instr_start,
            instr_end,
            input_len: base_content.len() as u64,
            output_len: out_len,
            check_ok: true,
            detail: format!(
                "{} -> {} 字节，类型 {}，重新计算 oid {}",
                base_content.len(),
                out_len,
                base_type.name(),
                oid.short()
            ),
            instructions_json: instr_json,
        };

        // oid 与 index 声称不一致时记录为证据，但不改变“成功还原”事实，
        // 由引擎在 claimed_oid 不匹配时标记冲突（重复 oid / 伪造内容）。
        let mut steps = base_node.steps.clone();
        steps.push(step);

        let node = ResolvedNode {
            status: ResolveStatus::Resolved,
            actual_oid: Some(oid),
            out_type: Some(base_type),
            output: Some(applied.output),
            out_len,
            chain_len: base_node.chain_len + 1,
            steps,
            error: None,
            blocked_chain: Vec::new(),
            spent: out_len,
        };
        cache.insert(id, node.clone());
        node
    }

    fn chain_with(&self, id: i64) -> Vec<i64> {
        let mut v = self.stack.clone();
        v.push(id);
        v
    }

    fn find_base(&self, c: &Candidate) -> Result<i64, ResolveError> {
        match c.obj_type {
            ObjType::OfsDelta => {
                let target = c.ofs_base_offset.ok_or_else(|| {
                    ResolveError::Corrupt("ofs-delta 缺少 base offset".to_string())
                })?;
                // ofs base 必须在同一 pack 内，且严格位于本条目之前。
                match self.graph.by_pack_offset.get(&(c.source_id, target)) {
                    Some(&bid) => {
                        if Some(target) >= c.pack_offset {
                            return Err(ResolveError::Corrupt(format!(
                                "ofs-delta base 偏移 {target} 不在本条目之前（非法/成环）"
                            )));
                        }
                        Ok(bid)
                    }
                    None => Err(ResolveError::MissingBase(format!(
                        "同 pack 偏移 {target} 没有对象（越界）"
                    ))),
                }
            }
            ObjType::RefDelta => {
                let oid = c.ref_base_oid.ok_or_else(|| {
                    ResolveError::Corrupt("ref-delta 缺少 base oid".to_string())
                })?;
                // ref base：同包优先，再全局。
                let ranked = rank_candidates_for_oid(self.graph, oid, self.pins);
                let same_pack = ranked
                    .iter()
                    .copied()
                    .find(|&id| self.graph.candidates[&id].source_id == c.source_id);
                let chosen = same_pack.or_else(|| ranked.first().copied());
                chosen.ok_or_else(|| ResolveError::MissingBase(format!("oid {}", oid.short())))
            }
            _ => Err(ResolveError::Corrupt("非 delta 没有 base".to_string())),
        }
    }

    fn from_error(&self, c: &Candidate, e: ResolveError) -> ResolvedNode {
        match e {
            ResolveError::Corrupt(msg) => self.corrupt_node(c, msg),
            ResolveError::MissingBase(msg) => {
                let mut chain = self.stack.clone();
                chain.push(c.id_field());
                self.blocked_node(c, format!("缺少外部 base：{msg}"), chain)
            }
            ResolveError::Cycle(cyc) => self.cycle_node(c, cyc),
            ResolveError::Paused(msg) => self.paused_node(c, msg, self.chain_with(c.id_field())),
            ResolveError::Depth(d) => self.paused_node(
                c,
                format!("delta 深度达到预算上限 {d}"),
                self.chain_with(c.id_field()),
            ),
        }
    }

    fn propagate(&self, c: &Candidate, base: &ResolvedNode) -> ResolvedNode {
        // base 的阻塞/环链以 base 起点结束；把当前 delta 候选接到链首，
        // 形成“当前对象 -> ... -> 阻塞点”的完整阻塞链。
        let mut chain = vec![c.id_field()];
        chain.extend(base.blocked_chain.iter().copied());
        ResolvedNode {
            status: base.status,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: base.chain_len + 1,
            steps: Vec::new(),
            error: base.error.clone(),
            blocked_chain: chain,
            spent: base.spent,
        }
    }

    fn full_node(&self, c: &Candidate) -> ResolvedNode {
        let ty = c.obj_type;
        let oid = Oid(hash_object(ty, &c.payload));
        ResolvedNode {
            status: ResolveStatus::Resolved,
            actual_oid: Some(oid),
            out_type: Some(ty),
            output: Some(c.payload.clone()),
            out_len: c.payload.len() as u64,
            chain_len: 0,
            steps: Vec::new(),
            error: None,
            blocked_chain: Vec::new(),
            spent: c.payload.len() as u64,
        }
    }

    fn corrupt_node(&self, c: &Candidate, msg: String) -> ResolvedNode {
        ResolvedNode {
            status: ResolveStatus::Error,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: self.stack.len(),
            steps: Vec::new(),
            error: Some(msg),
            blocked_chain: self.chain_with(c.id_field()),
            spent: 0,
        }
    }

    fn blocked_node(&self, c: &Candidate, msg: String, chain: Vec<i64>) -> ResolvedNode {
        let _ = c;
        ResolvedNode {
            status: ResolveStatus::Blocked,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: self.stack.len(),
            steps: Vec::new(),
            error: Some(msg),
            blocked_chain: chain,
            spent: 0,
        }
    }

    fn paused_node(&self, c: &Candidate, msg: String, chain: Vec<i64>) -> ResolvedNode {
        let _ = c;
        ResolvedNode {
            status: ResolveStatus::Paused,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: self.stack.len(),
            steps: Vec::new(),
            error: Some(msg),
            blocked_chain: chain,
            spent: 0,
        }
    }

    fn cycle_node(&self, c: &Candidate, cyc: Vec<i64>) -> ResolvedNode {
        let _ = c;
        ResolvedNode {
            status: ResolveStatus::Cycle,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: self.stack.len(),
            steps: Vec::new(),
            error: Some(format!("delta 形成环：{}", chain_str(&cyc))),
            blocked_chain: cyc,
            spent: 0,
        }
    }

    fn terminal_error(&self, _id: i64, msg: &str) -> ResolvedNode {
        ResolvedNode {
            status: ResolveStatus::Error,
            actual_oid: None,
            out_type: None,
            output: None,
            out_len: 0,
            chain_len: 0,
            steps: Vec::new(),
            error: Some(msg.to_string()),
            blocked_chain: Vec::new(),
            spent: 0,
        }
    }
}

fn chain_str(ids: &[i64]) -> String {
    ids.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

impl Candidate {
    fn id_field(&self) -> i64 {
        self.id
    }
}

/// 未使用的导入占位（DeltaInstr 供测试/外部检查）。
pub fn _instr_marker(_i: &crate::delta::DeltaInstr) {}
