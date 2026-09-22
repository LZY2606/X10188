use std::collections::{BTreeMap, BTreeSet};

use rusqlite::params;
use serde::Serialize;

use crate::delta;
use crate::git;
use crate::oid::Oid;
use crate::types::{status, Budget, ObjKind};

/// 内存中的一个候选对象（解析期）。
#[derive(Clone)]
pub struct Node {
    pub id: i64,
    pub source_id: i64,
    pub etype: String,
    pub kind: Option<String>,
    pub declared_size: i64,
    pub claim_oid: Option<String>,
    pub base_ofs: Option<i64>,
    pub base_ofs_cand: Option<i64>,
    pub base_ref_oid: Option<String>,
    pub payload: Vec<u8>,
    pub parse_error: Option<String>,
    pub parse_error_code: Option<String>,
    pub crc_ok: Option<i64>,
    pub status: String,
    pub pack_offset: Option<i64>,
    pub ord: i64,
}

/// 解析结果。
#[derive(Clone)]
pub struct Outcome {
    pub status: String,
    pub kind: Option<ObjKind>,
    pub content: Vec<u8>,
    pub oid: Option<Oid>,
    pub depth: u32,
    pub steps: Vec<crate::types::DeltaStepRec>,
    /// 阻塞链（自底向上，含自身）。
    pub blocking: Vec<BlockPoint>,
    pub error_code: Option<String>,
    pub error_msg: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockPoint {
    pub cand: i64,
    pub oid: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RunStats {
    pub run_id: i64,
    pub touched: usize,
    pub resolved: usize,
    pub bad: usize,
    pub missing_base: usize,
    pub paused: usize,
    pub depth_limit: usize,
    /// true 表示所有可解析对象均已到终态（没有 paused/depth_limit）。
    pub complete: bool,
    pub budget_bytes_spent: u64,
}

pub struct Resolver<'a> {
    pub tx: &'a rusqlite::Transaction<'a>,
    pub nodes: BTreeMap<i64, Node>,
    /// (source_id, pack_offset) -> cand id
    pub by_ofs: BTreeMap<(i64, i64), i64>,
    /// claim_oid -> 候选 id 列表（确定性排序：resolved 优先、ord 小优先）
    pub by_oid: BTreeMap<String, Vec<i64>>,
    pub budget: Budget,
    pub spent: u64,
    pub run_id: i64,
    /// 固定的冲突来源：source_id -> 优先级（分析分支）
    pub pinned_source: Option<i64>,
    pub stats: RunStats,
    /// 本次运行已还原的完整内容（cand id -> (kind, content, oid, steps)）
    pub content_cache: BTreeMap<i64, (ObjKind, Vec<u8>, Oid, Vec<crate::types::DeltaStepRec>)>,
    /// 本次运行已经计过费的完整对象（顶层去重）
    pub charged: BTreeSet<i64>,
    /// 当前正在解析的顶层根候选（run 对每个顶层 id 压入）
    pub root_stack: Vec<i64>,
}

fn load_nodes(tx: &rusqlite::Transaction) -> BTreeMap<i64, Node> {
    let mut map = BTreeMap::new();
    let mut stmt = tx
        .prepare(
            "SELECT id, source_id, etype, kind, declared_size, claim_oid, base_ofs,
                    base_ofs_cand, base_ref_oid, payload, parse_error, parse_error_code,
                    crc_ok, status, pack_offset, ord
             FROM candidates",
        )
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    while let Some(r) = rows.next().unwrap() {
        let id: i64 = r.get(0).unwrap();
        let n = Node {
            id,
            source_id: r.get(1).unwrap(),
            etype: r.get(2).unwrap(),
            kind: r.get(3).unwrap(),
            declared_size: r.get(4).unwrap(),
            claim_oid: r.get(5).unwrap(),
            base_ofs: r.get(6).unwrap(),
            base_ofs_cand: r.get(7).unwrap(),
            base_ref_oid: r.get(8).unwrap(),
            payload: r.get::<_, Option<Vec<u8>>>(9).unwrap().unwrap_or_default(),
            parse_error: r.get(10).unwrap(),
            parse_error_code: r.get(11).unwrap(),
            crc_ok: r.get(12).unwrap(),
            status: r.get(13).unwrap(),
            pack_offset: r.get(14).unwrap(),
            ord: r.get(15).unwrap(),
        };
        map.insert(id, n);
    }
    map
}

impl<'a> Resolver<'a> {
    pub fn new(
        tx: &'a rusqlite::Transaction<'a>,
        budget: Budget,
        pinned_source: Option<i64>,
    ) -> Self {
        let nodes = load_nodes(tx);
        let mut by_ofs = BTreeMap::new();
        let mut by_oid: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for n in nodes.values() {
            if let (Some(sid), Some(off)) = (Some(n.source_id), n.pack_offset) {
                by_ofs.insert((sid, off), n.id);
            }
            if let Some(o) = &n.claim_oid {
                by_oid.entry(o.clone()).or_default().push(n.id);
            }
        }
        for v in by_oid.values_mut() {
            // 稳定排序：ord（与导入顺序无关的确定性键，入库时随偏移递增）
            v.sort_by_key(|id| nodes[id].ord);
        }
        tx.execute(
            "INSERT INTO runs(scope, budget_json, finished, complete)
             VALUES ('full', ?1, 1, 0)",
            params![serde_json::to_string(&budget).unwrap_or_default()],
        )
        .ok();
        let run_id = tx.last_insert_rowid();
        // 已还原对象按内容大小计入已用预算（恢复时预算语义连续）。
        let spent: u64 = tx
            .query_row(
                "SELECT COALESCE(SUM(length(resolved_content)),0) FROM candidates WHERE status='resolved'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u64;
        let charged: BTreeSet<i64> = tx
            .prepare("SELECT id FROM candidates WHERE status='resolved'")
            .into_iter()
            .flat_map(|mut st| {
                st.query_map([], |r| r.get::<_, i64>(0))
                    .into_iter()
                    .flat_map(|rows| rows.flatten())
                    .collect::<Vec<_>>()
            })
            .collect();
        Resolver {
            tx,
            nodes,
            by_ofs,
            by_oid,
            budget,
            spent,
            run_id,
            pinned_source,
            stats: RunStats {
                run_id,
                ..Default::default()
            },
            content_cache: BTreeMap::new(),
            charged,
            root_stack: Vec::new(),
        }
    }

    /// 给定 ref oid，选择 base 候选。优先：固定来源 > 已 resolved 且 oid 自证 > 其它。
    fn pick_ref_candidate(&self, oid: &str) -> Option<i64> {
        let ids = self.by_oid.get(oid)?;
        // 固定冲突来源
        if let Some(pin) = self.pinned_source {
            for &id in ids {
                if self.nodes[&id].source_id == pin {
                    return Some(id);
                }
            }
        }
        // 已 resolved 且 oid 自证一致
        let mut resolved: Vec<i64> = ids
            .iter()
            .copied()
            .filter(|id| self.nodes[id].status == status::RESOLVED)
            .collect();
        if !resolved.is_empty() {
            resolved.sort_by_key(|id| self.rank_key(*id));
            return Some(resolved[0]);
        }
        // 否则返回排序最靠前的一个（会在 DFS 中继续解析它）
        ids.iter().copied().min_by_key(|id| self.rank_key(*id))
    }

    /// 确定性排序键：(非解析错误优先, ord)。
    fn rank_key(&self, id: i64) -> (i64, i64) {
        let n = &self.nodes[&id];
        let has_err = if n.parse_error.is_some() { 1 } else { 0 };
        (has_err, n.ord)
    }

    /// 同一 oid 的候选数量（冲突/重复证据）。
    pub fn ambiguity_count(&self, oid: &str) -> usize {
        self.by_oid.get(oid).map(|v| v.len()).unwrap_or(0)
    }

    fn bad(&self, code: &str, msg: String, blocking: Vec<BlockPoint>, depth: u32) -> Outcome {
        Outcome {
            status: status::BAD.to_string(),
            kind: None,
            content: Vec::new(),
            oid: None,
            depth,
            steps: Vec::new(),
            blocking,
            error_code: Some(code.to_string()),
            error_msg: Some(msg),
        }
    }

    /// DFS 还原单个候选。stack 用于环检测。
    pub fn resolve(
        &mut self,
        id: i64,
        depth: u32,
        stack: &mut Vec<i64>,
        budget_snapshot: u64,
    ) -> Outcome {
        let node = match self.nodes.get(&id) {
            Some(n) => n.clone(),
            None => {
                return self.bad(
                    "missing_candidate",
                    format!("候选 #{} 不存在", id),
                    vec![BlockPoint {
                        cand: id,
                        oid: None,
                        reason: "候选不存在".to_string(),
                    }],
                    depth,
                );
            }
        };

        // 已到完整终态：直接用缓存（resolved 终态不重复计费）
        if node.status == status::RESOLVED {
            return self.load_cached(id, depth, &node);
        }

        // 环检测
        if stack.contains(&id) {
            let chain = stack
                .iter()
                .map(|cid| BlockPoint {
                    cand: *cid,
                    oid: self.nodes[cid].claim_oid.clone(),
                    reason: format!("环：#{} 重复出现在 delta 链", cid),
                })
                .collect();
            return self.bad("delta_cycle", format!("delta 链形成环，涉及 {:?}", stack), chain, depth);
        }

        // 解析级硬错误（zlib / size spoof / bad crc）→ 隔离
        if let Some(msg) = &node.parse_error {
            let code = node.parse_error_code.clone().unwrap_or_else(|| "parse".to_string());
            return self.bad(
                &code,
                msg.clone(),
                vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: msg.clone(),
                }],
                depth,
            );
        }
        if node.crc_ok == Some(0) {
            return self.bad(
                "crc_mismatch",
                "index CRC32 与压缩数据不符".to_string(),
                vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: "CRC32 不匹配".to_string(),
                }],
                depth,
            );
        }

        // 非 delta 基对象
        if node.etype != "ofs-delta" && node.etype != "ref-delta" {
            return self.resolve_base(&node, depth);
        }

        // 深度预算
        if depth >= self.budget.max_depth {
            return Outcome {
                status: status::DEPTH_LIMIT.to_string(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: format!("delta 深度达到预算上限 {}", self.budget.max_depth),
                }],
                error_code: Some("depth_limit".to_string()),
                error_msg: Some(format!("深度上限 {} 已达", self.budget.max_depth)),
            };
        }

        // 解析 base
        stack.push(id);
        let (base_id, _base_missing) = self.locate_base(&node);
        let base_outcome = match base_id {
            Some(bid) => Some(self.resolve(bid, depth + 1, stack, budget_snapshot)),
            None => None,
        };
        stack.pop();

        if base_id.is_none() {
            let reason = match (node.etype.as_str(), node.base_ref_oid.clone(), node.base_ofs) {
                ("ref-delta", Some(oid), _) => format!("缺少外部 base：ref-delta 指向 {}", oid),
                ("ofs-delta", _, Some(off)) => format!("缺少 base：ofs-delta 指向偏移 {}", off),
                _ => "缺少 base".to_string(),
            };
            return Outcome {
                status: status::MISSING_BASE.to_string(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason,
                }],
                error_code: Some("missing_base".to_string()),
                error_msg: None,
            };
        }

        let base = base_outcome.unwrap();
        if base.status != status::RESOLVED {
            // 传播阻塞：子对象继承 base 的阻塞链 + 自身
            let mut chain = base.blocking.clone();
            chain.push(BlockPoint {
                cand: id,
                oid: node.claim_oid.clone(),
                reason: format!("依赖未还原的 base #{}", base_id.unwrap()),
            });
            return Outcome {
                status: base.status.clone(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: chain,
                error_code: base.error_code.clone(),
                error_msg: base.error_msg.clone(),
            };
        }

        // 预算：单对象比例（中间展开相对声明结果大小）
        let target_declared = self.declared_target_len(&node.payload).unwrap_or(node.declared_size as u64);
        let max_single = (target_declared.max(1) * self.budget.ratio_millis) / 1000;
        if base.content.len() as u64 > max_single {
            return Outcome {
                status: status::PAUSED.to_string(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: format!(
                        "base 展开 {} 字节超过单对象比例预算（声明 {} × {:.1}）",
                        base.content.len(),
                        target_declared,
                        self.budget.ratio_millis as f64 / 1000.0
                    ),
                }],
                error_code: Some("ratio_budget".to_string()),
                error_msg: Some("单对象比例预算耗尽，可放开后重试".to_string()),
            };
        }
        // 总展开字节预算：以“当前 delta 目标声明大小”作为本对象计费量，仅对根对象去重计费。
        let root_id = self.root_stack.last().copied().unwrap_or(id);
        let charge = target_declared;
        let projected = self.spent
            + if self.charged.contains(&root_id) { 0 } else { charge };
        if projected > self.budget.total_bytes {
            return Outcome {
                status: status::PAUSED.to_string(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: format!(
                        "总展开字节预算 {} 已用尽（已用 {}，本对象需 {}）",
                        self.budget.total_bytes, self.spent, charge
                    ),
                }],
                error_code: Some("total_budget".to_string()),
                error_msg: Some("总展开预算耗尽，可提高后重试".to_string()),
            };
        }
        let _ = root_id;

        // 应用 delta
        let applied = match delta::apply_delta(&base.content, &node.payload) {
            Ok(a) => a,
            Err(e) => {
                return self.bad(
                    e.code(),
                    e.to_string(),
                    vec![
                        BlockPoint {
                            cand: base_id.unwrap(),
                            oid: base.oid.map(|o| o.hex()),
                            reason: "base".to_string(),
                        },
                        BlockPoint {
                            cand: id,
                            oid: node.claim_oid.clone(),
                            reason: e.to_string(),
                        },
                    ],
                    depth,
                );
            }
        };

        let kind = base.kind.unwrap(); // delta 不改变类型
        let out = applied.out.clone();
        let computed = git::git_object_id(kind, &out);
        let step = delta::build_step(base_id.unwrap(), base.oid, &base.content, &applied);
        let mut steps = base.steps.clone();
        steps.push(step);

        Outcome {
            status: status::RESOLVED.to_string(),
            kind: Some(kind),
            content: out,
            oid: Some(computed),
            depth,
            steps,
            blocking: Vec::new(),
            error_code: None,
            error_msg: None,
        }
    }

    fn declared_target_len(&self, delta_payload: &[u8]) -> Option<u64> {
        let mut pos = 0usize;
        let _ = delta::read_varint(delta_payload, &mut pos).ok()?;
        delta::read_varint(delta_payload, &mut pos).ok()
    }

    /// 定位 delta 的 base 候选。返回 (cand_id, missing)。
    fn locate_base(&self, node: &Node) -> (Option<i64>, bool) {
        if node.etype == "ofs-delta" {
            if let Some(off) = node.base_ofs {
                // 同一 pack 内：source_id + offset
                if let Some(cid) = self.by_ofs.get(&(node.source_id, off)) {
                    return (Some(*cid), false);
                }
                // 记录的候选 id（备用）
                if let Some(cid) = node.base_ofs_cand {
                    return (Some(cid), false);
                }
                return (None, true);
            }
            return (None, true);
        }
        // ref-delta：跨包 / 跨 loose
        if let Some(oid) = &node.base_ref_oid {
            if let Some(cid) = self.pick_ref_candidate(oid) {
                return (Some(cid), false);
            }
            return (None, true);
        }
        (None, true)
    }

    fn resolve_base(&self, node: &Node, depth: u32) -> Outcome {
        let kind = match node.kind.as_deref().and_then(|w| ObjKind::from_word(w.as_bytes())) {
            Some(k) => k,
            None => {
                return self.bad(
                    "unknown_type",
                    "基对象缺少合法类型".to_string(),
                    vec![BlockPoint {
                        cand: node.id,
                        oid: node.claim_oid.clone(),
                        reason: "类型未知".to_string(),
                    }],
                    depth,
                );
            }
        };
        // 声明大小与真实负载一致性（解压阶段已校验，这里二次取证）
        if node.declared_size as usize != node.payload.len() {
            return self.bad(
                "size_spoof",
                crate::error::PError::SizeSpoof {
                    declared: node.declared_size as u64,
                    actual: node.payload.len() as u64,
                }
                .to_string(),
                vec![BlockPoint {
                    cand: node.id,
                    oid: node.claim_oid.clone(),
                    reason: "声明大小与负载不一致".to_string(),
                }],
                depth,
            );
        }
        let computed = git::git_object_id(kind, &node.payload);

        // 若有 claim oid（index 给出），必须一致，否则隔离
        if let Some(claim) = &node.claim_oid {
            if *claim != computed.hex() {
                return self.bad(
                    "oid_mismatch",
                    format!(
                        "重算 git oid {} 与 index 声称 {} 不符（内容损坏或大小欺骗）",
                        computed.hex(),
                        claim
                    ),
                    vec![BlockPoint {
                        cand: node.id,
                        oid: Some(claim.clone()),
                        reason: format!("实际重算为 {}", computed.hex()),
                    }],
                    depth,
                );
            }
        }

        Outcome {
            status: status::RESOLVED.to_string(),
            kind: Some(kind),
            content: node.payload.clone(),
            oid: Some(computed),
            depth,
            steps: Vec::new(),
            blocking: Vec::new(),
            error_code: None,
            error_msg: None,
        }
    }

    fn load_cached(&self, id: i64, depth: u32, node: &Node) -> Outcome {
        if let Some((kind, content, oid, steps)) = self.content_cache.get(&id) {
            return Outcome {
                status: status::RESOLVED.to_string(),
                kind: Some(*kind),
                content: content.clone(),
                oid: Some(*oid),
                depth,
                steps: steps.clone(),
                blocking: Vec::new(),
                error_code: None,
                error_msg: None,
            };
        }
        // 从 DB 读已持久化的还原内容（上一轮分析产物）
        let row: Option<(String, Vec<u8>, String)> = self
            .tx
            .query_row(
                "SELECT COALESCE(resolved_kind, kind), COALESCE(resolved_content, payload), COALESCE(resolved_oid, claim_oid)
                 FROM candidates WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        match row {
            Some((kw, content, oidhex)) => {
                let kind = ObjKind::from_word(kw.as_bytes()).unwrap_or(ObjKind::Blob);
                Outcome {
                    status: status::RESOLVED.to_string(),
                    kind: Some(kind),
                    content,
                    oid: Oid::from_hex(&oidhex).ok(),
                    depth,
                    steps: Vec::new(),
                    blocking: Vec::new(),
                    error_code: None,
                    error_msg: None,
                }
            }
            None => Outcome {
                status: status::BAD.to_string(),
                kind: None,
                content: Vec::new(),
                oid: None,
                depth,
                steps: Vec::new(),
                blocking: vec![BlockPoint {
                    cand: id,
                    oid: node.claim_oid.clone(),
                    reason: "标记 resolved 但缺少还原内容".to_string(),
                }],
                error_code: Some("stale_resolved".to_string()),
                error_msg: None,
            },
        }
    }
}

/// 运行结果报告（顶层入口）。
impl<'a> Resolver<'a> {
    /// 对外暴露的边重建（供补入 base 前刷新 NULL ref 边）。
    pub fn rebuild_edges_public(&self, _ids: &[i64]) {
        let all: Vec<i64> = self.nodes.keys().copied().collect();
        self.rebuild_edges(&all);
    }

    /// 全量（或给定候选集合）分析。targets=None 表示全部候选。
    pub fn run(&mut self, targets: Option<Vec<i64>>) -> RunStats {
        let ids: Vec<i64> = match targets {
            Some(t) => t,
            None => self.nodes.keys().copied().collect(),
        };

        for &id in &ids {
            if self.stats.complete == false {
                // 占位，complete 最后再统一判定
            }
            let mut stack: Vec<i64> = Vec::new();
            self.root_stack.push(id);
            let snap = self.spent;
            let outcome = self.resolve(id, 0, &mut stack, snap);
            self.root_stack.pop();
            self.persist_outcome(id, &outcome);
            if outcome.status == status::RESOLVED {
                if !self.charged.contains(&id) {
                    self.spent = self.spent.saturating_add(outcome.content.len() as u64);
                    self.charged.insert(id);
                }
                if let (Some(k), Some(o)) = (outcome.kind, outcome.oid) {
                    self.content_cache
                        .insert(id, (k, outcome.content.clone(), o, outcome.steps.clone()));
                }
            }
            self.stats.touched += 1;
            match outcome.status.as_str() {
                status::RESOLVED => self.stats.resolved += 1,
                status::BAD => self.stats.bad += 1,
                status::MISSING_BASE => self.stats.missing_base += 1,
                status::PAUSED => self.stats.paused += 1,
                status::DEPTH_LIMIT => self.stats.depth_limit += 1,
                _ => {}
            }
        }

        // 重建边表（仅针对本批候选），供 DAG 展示
        self.rebuild_edges(&ids);

        // 计算“是否完整”：不存在暂停/深度受限对象即视为本轮完整
        let incomplete: i64 = self
            .tx
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE status IN ('paused','depth_limit')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        self.stats.complete = incomplete == 0;
        self.stats.budget_bytes_spent = self.spent;

        self.tx
            .execute(
                "UPDATE runs SET finished=1, complete=?1 WHERE id=?2",
                params![self.stats.complete as i64, self.run_id],
            )
            .ok();

        self.stats.clone()
    }

    fn persist_outcome(&self, id: i64, o: &Outcome) {
        let (resolved_kind, resolved_oid, resolved_size, content): (
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<Vec<u8>>,
        ) = if o.status == status::RESOLVED {
            (
                o.kind.map(|k| k.word().to_string()),
                o.oid.map(|x| x.hex()),
                Some(o.content.len() as i64),
                Some(o.content.clone()),
            )
        } else {
            (None, None, None, None)
        };
        let chain_json = serde_json::to_string(&o.blocking).unwrap_or_else(|_| "[]".to_string());
        self.tx
            .execute(
                "UPDATE candidates SET
                    status=?1,
                    resolved_kind=?2,
                    resolved_oid=?3,
                    resolved_size=?4,
                    resolved_content=?5,
                    chain_depth=?6,
                    blocking_chain=?7,
                    runtime_error_code=?8,
                    runtime_error=?9,
                    run_id=?10
                 WHERE id=?11",
                params![
                    o.status,
                    resolved_kind,
                    resolved_oid,
                    resolved_size,
                    content,
                    o.depth as i64,
                    chain_json,
                    o.error_code,
                    o.error_msg,
                    self.run_id,
                    id
                ],
            )
            .ok();

        // delta 步骤（删除旧记录重写，保证局部重算后证据是最新的）
        self.tx
            .execute("DELETE FROM delta_steps WHERE cand_id=?1", params![id])
            .ok();
        for (i, step) in o.steps.iter().enumerate() {
            self.tx
                .execute(
                    "INSERT INTO delta_steps(
                        cand_id, step, base_cand, base_oid, declared_base_len, declared_result_len,
                        input_len, output_len, op_count, summary, input_ok, output_ok, ops_json
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                    params![
                        id,
                        i as i64,
                        step.base_cand,
                        step.base_oid.map(|o| o.hex()),
                        step.declared_base_len as i64,
                        step.declared_result_len as i64,
                        step.input_len as i64,
                        step.output_len as i64,
                        step.op_count as i64,
                        step.summary,
                        step.input_matches_declared as i64,
                        step.output_matches_declared as i64,
                        serde_json::to_string(&step.ops).unwrap_or_else(|_| "[]".to_string())
                    ],
                )
                .ok();
        }
    }

    fn rebuild_edges(&self, ids: &[i64]) {
        for &id in ids {
            self.tx.execute("DELETE FROM edges WHERE from_cand=?1", params![id]).ok();
            let n = match self.nodes.get(&id) {
                Some(n) => n,
                None => continue,
            };
            if n.etype == "ofs-delta" || n.etype == "ref-delta" {
                let (to, kind, ref_oid) = {
                    let (bid, _missing) = self.locate_base(n);
                    if n.etype == "ofs-delta" {
                        (bid, "ofs", None::<String>)
                    } else {
                        (bid, "ref", n.base_ref_oid.clone())
                    }
                };
                self.tx
                    .execute(
                        "INSERT INTO edges(from_cand, to_cand, kind, ref_oid) VALUES (?1,?2,?3,?4)",
                        params![id, to, kind, ref_oid],
                    )
                    .ok();
            }
        }
    }
}

/// 计算补入 base 后需要局部重算的候选集合：
/// 从 seed（新/变化候选）出发，沿 edges 反向（谁依赖了这些 oid / ofs）扩展到闭包。
pub fn affected_subgraph(tx: &rusqlite::Transaction, seeds: &[i64]) -> Vec<i64> {
    let mut affected: BTreeSet<i64> = seeds.iter().copied().collect();
    // 反复把“to_cand 在集合内”的 from_cand 加入
    loop {
        let before = affected.len();
        let mut added: Vec<i64> = Vec::new();
        {
            let mut stmt = tx
                .prepare("SELECT from_cand, to_cand, kind, ref_oid FROM edges")
                .unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                let from: i64 = r.get(0).unwrap();
                let to: Option<i64> = r.get(1).unwrap();
                let kind: String = r.get(2).unwrap();
                let ref_oid: Option<String> = r.get(3).unwrap();
                if affected.contains(&from) {
                    continue;
                }
                let depends = match kind.as_str() {
                    "ofs" => to.map(|t| affected.contains(&t)).unwrap_or(false),
                    "ref" => {
                        // 也可能此前 base 缺失（to 为 NULL）：按 ref_oid 是否被某个新 seed 满足
                        if let Some(t) = to {
                            affected.contains(&t)
                        } else if let Some(ro) = &ref_oid {
                            seed_satisfies_oid(tx, seeds, ro)
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if depends {
                    added.push(from);
                }
            }
        }
        for a in added {
            affected.insert(a);
        }
        if affected.len() == before {
            break;
        }
    }
    affected.into_iter().collect()
}

fn seed_satisfies_oid(tx: &rusqlite::Transaction, seeds: &[i64], oid: &str) -> bool {
    for &s in seeds {
        let ok: bool = tx
            .query_row(
                "SELECT 1 FROM candidates WHERE id=?1 AND COALESCE(resolved_oid, claim_oid)=?2",
                params![s, oid],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}
