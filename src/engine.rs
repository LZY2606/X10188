use std::collections::HashMap;
use std::rc::Rc;

use crate::delta;
use crate::model::*;
use crate::oid::{self, Oid};

/// 参与解析的候选对象（来自 pack 条目或 loose object）
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: i64,
    pub source_id: i64,
    pub source_name: String,
    pub source_sha1: String,
    pub pack_offset: Option<u64>,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub packed_len: u64,
    pub base_dist: Option<u64>,
    pub base_oid: Option<Oid>,
    pub oid_hint: Option<Oid>,
    pub data: Vec<u8>,
    pub evidence: Vec<String>,
}

impl Candidate {
    pub fn desc(&self) -> String {
        match self.pack_offset {
            Some(off) => format!("{}@{}", self.source_name, off),
            None => format!("{}(loose)", self.source_name),
        }
    }
}

#[derive(Clone)]
pub struct Outcome {
    pub res: Resolution,
    pub content: Option<Vec<u8>>,
    pub rtype: Option<ObjType>,
}

impl Outcome {
    fn error(msg: String) -> Self {
        let mut res = Resolution::empty(Status::Error);
        res.error = Some(msg);
        Self { res, content: None, rtype: None }
    }
}

const MAX_INSTR_RECORDED: usize = 4096;
/// 递归硬上限，防止极端预算设置导致栈溢出
const HARD_DEPTH_CAP: u32 = 256;

pub struct Engine {
    cands: Vec<Candidate>,
    pins: HashMap<String, i64>,
    budget: Budget,
    spent: u64,
    memo: HashMap<usize, Rc<Outcome>>,
    visiting: Vec<usize>,
    order: Vec<usize>,
    by_pack_off: HashMap<(i64, u64), usize>,
}

impl Engine {
    pub fn new(cands: Vec<Candidate>, pins: HashMap<String, i64>, budget: Budget) -> Self {
        let mut order: Vec<usize> = (0..cands.len()).collect();
        // 确定性顺序：仅依赖内容属性（源名、源摘要、偏移），与导入顺序无关
        order.sort_by(|&a, &b| {
            let ca = &cands[a];
            let cb = &cands[b];
            (
                &ca.source_name,
                &ca.source_sha1,
                ca.pack_offset.unwrap_or(0),
                ca.id,
            )
                .cmp(&(
                    &cb.source_name,
                    &cb.source_sha1,
                    cb.pack_offset.unwrap_or(0),
                    cb.id,
                ))
        });
        let mut by_pack_off = HashMap::new();
        for (i, c) in cands.iter().enumerate() {
            if let Some(off) = c.pack_offset {
                by_pack_off.insert((c.source_id, off), i);
            }
        }
        Self {
            cands,
            pins,
            budget,
            spent: 0,
            memo: HashMap::new(),
            visiting: Vec::new(),
            order,
            by_pack_off,
        }
    }

    /// 用缓存中的有效结果做种子（增量重算）
    pub fn seed(&mut self, idx: usize, outcome: Outcome) {
        self.memo.insert(idx, Rc::new(outcome));
    }

    pub fn candidate(&self, idx: usize) -> &Candidate {
        &self.cands[idx]
    }

    pub fn len(&self) -> usize {
        self.cands.len()
    }

    fn known_oid(&self, i: usize) -> Option<Oid> {
        if let Some(o) = self.memo.get(&i) {
            if let Some(h) = &o.res.oid {
                if let Some(oid) = oid::from_hex(h) {
                    return Some(oid);
                }
            }
        }
        self.cands[i].oid_hint
    }

    fn terminal_count(&self) -> usize {
        self.memo
            .values()
            .filter(|o| matches!(o.res.status, Status::Resolved | Status::Error | Status::Paused))
            .count()
    }

    pub fn run(mut self) -> Vec<Option<Outcome>> {
        loop {
            let before = self.terminal_count();
            let order = self.order.clone();
            for i in order {
                self.resolve_one(i);
            }
            // Blocked 结果可能因新解析出的 oid 而解锁，清除后重试
            self.memo.retain(|_, o| o.res.status != Status::Blocked);
            if self.terminal_count() == before {
                break;
            }
        }
        // 最后一遍，固化 Blocked 结果
        let order = self.order.clone();
        for i in order {
            self.resolve_one(i);
        }
        let mut out: Vec<Option<Outcome>> = Vec::with_capacity(self.cands.len());
        for i in 0..self.cands.len() {
            out.push(self.memo.get(&i).map(|o| (**o).clone()));
        }
        out
    }

    fn resolve_one(&mut self, i: usize) -> Rc<Outcome> {
        if let Some(o) = self.memo.get(&i) {
            return o.clone();
        }
        if let Some(pos) = self.visiting.iter().position(|&x| x == i) {
            let cycle: Vec<usize> = self.visiting[pos..].to_vec();
            let desc = cycle
                .iter()
                .map(|&c| format!("#{} {}", self.cands[c].id, self.cands[c].desc()))
                .collect::<Vec<_>>()
                .join(" -> ");
            let oc = Rc::new(Outcome::error(format!("检测到 delta 环: {desc}")));
            for &m in &cycle {
                self.memo.insert(m, oc.clone());
            }
            return oc;
        }
        self.visiting.push(i);
        let oc = self.compute(i);
        self.visiting.pop();
        self.memo.insert(i, oc.clone());
        oc
    }

    fn compute(&mut self, i: usize) -> Rc<Outcome> {
        let c = self.cands[i].clone();
        if !c.evidence.is_empty() {
            // 隔离坏对象：记录证据，不参与后续解析
            let mut oc = Outcome::error(format!("对象被隔离，证据: {}", c.evidence.join("；")));
            if !c.obj_type.is_delta() {
                oc.res.oid = Some(oid::to_hex(&oid::hash_object(c.obj_type, &c.data)));
                oc.rtype = Some(c.obj_type);
            }
            return Rc::new(oc);
        }
        match c.obj_type {
            ObjType::OfsDelta => {
                let dist = c.base_dist.unwrap_or(0);
                let my_off = c.pack_offset.unwrap_or(0);
                match my_off.checked_sub(dist) {
                    Some(base_off) => match self.by_pack_off.get(&(c.source_id, base_off)) {
                        Some(&j) => {
                            let desc = format!("ofs -{} (偏移 {})", dist, base_off);
                            self.with_base(i, j, desc, None)
                        }
                        None => {
                            let mut res = Resolution::empty(Status::Blocked);
                            res.blockers.push(Blocker {
                                candidate_id: None,
                                desc: c.desc(),
                                reason: format!(
                                    "ofs-delta 基点偏移 {} 处无对象（距离 {}）",
                                    base_off, dist
                                ),
                            });
                            Rc::new(Outcome { res, content: None, rtype: None })
                        }
                    },
                    None => {
                        let mut res = Resolution::empty(Status::Blocked);
                        res.blockers.push(Blocker {
                            candidate_id: None,
                            desc: c.desc(),
                            reason: format!("ofs 距离越界: 距离 {} 超出自身偏移 {}", dist, my_off),
                        });
                        Rc::new(Outcome { res, content: None, rtype: None })
                    }
                }
            }
            ObjType::RefDelta => {
                let base_oid = c.base_oid.unwrap_or([0u8; 20]);
                let base_hex = oid::to_hex(&base_oid);
                let mut matches: Vec<usize> = (0..self.cands.len())
                    .filter(|&j| self.known_oid(j) == Some(base_oid))
                    .collect();
                if matches.is_empty() {
                    let mut res = Resolution::empty(Status::Blocked);
                    res.blockers.push(Blocker {
                        candidate_id: None,
                        desc: c.desc(),
                        reason: format!("缺失 base: 无任何候选提供 oid {}", base_hex),
                    });
                    res.chain_base_oids.push(base_hex.clone());
                    res.used_ref = true;
                    return Rc::new(Outcome { res, content: None, rtype: None });
                }
                let pins = self.pins.clone();
                matches.sort_by(|&a, &b| {
                    let ca = &self.cands[a];
                    let cb = &self.cands[b];
                    let pa = pins.get(&base_hex) == Some(&ca.source_id);
                    let pb = pins.get(&base_hex) == Some(&cb.source_id);
                    pb.cmp(&pa).then(
                        (&ca.source_name, &ca.source_sha1, ca.pack_offset.unwrap_or(0), ca.id)
                            .cmp(&(&cb.source_name, &cb.source_sha1, cb.pack_offset.unwrap_or(0), cb.id)),
                    )
                });
                let j = matches[0];
                let desc = format!("ref {}", base_hex);
                self.with_base(i, j, desc, Some(base_hex))
            }
            full => {
                let oid = oid::hash_object(full, &c.data);
                let mut res = Resolution::empty(Status::Resolved);
                res.oid = Some(oid::to_hex(&oid));
                res.expanded_bytes = c.data.len() as u64;
                if let Some(hint) = c.oid_hint {
                    if hint != oid {
                        res.error = Some(format!(
                            "oid 与提示不符: 计算得 {}，提示 {}",
                            oid::to_hex(&oid),
                            oid::to_hex(&hint)
                        ));
                    }
                }
                Rc::new(Outcome {
                    res,
                    content: Some(c.data.clone()),
                    rtype: Some(full),
                })
            }
        }
    }

    fn with_base(
        &mut self,
        i: usize,
        j: usize,
        base_desc: String,
        ref_oid: Option<String>,
    ) -> Rc<Outcome> {
        let base = self.resolve_one(j);
        let c = self.cands[i].clone();
        let base_id = self.cands[j].id;
        match base.res.status {
            Status::Resolved => {}
            Status::Paused => {
                let mut res = Resolution::empty(Status::Paused);
                res.error = Some(format!(
                    "基点 #{} 因预算暂停: {}",
                    base_id,
                    base.res.error.clone().unwrap_or_default()
                ));
                res.blockers.push(Blocker {
                    candidate_id: Some(base_id),
                    desc: base_desc.clone(),
                    reason: "基点解析被预算暂停".to_string(),
                });
                res.blockers.extend(base.res.blockers.clone());
                res.used_ref = ref_oid.is_some() || base.res.used_ref;
                if let Some(h) = &ref_oid {
                    res.chain_base_oids.push(h.clone());
                }
                res.chain_base_oids.extend(base.res.chain_base_oids.clone());
                return Rc::new(Outcome { res, content: None, rtype: None });
            }
            _ => {
                let mut res = Resolution::empty(Status::Blocked);
                res.blockers.push(Blocker {
                    candidate_id: Some(base_id),
                    desc: base_desc.clone(),
                    reason: base
                        .res
                        .error
                        .clone()
                        .unwrap_or_else(|| format!("基点状态 {:?}", base.res.status)),
                });
                res.blockers.extend(base.res.blockers.clone());
                res.used_ref = ref_oid.is_some() || base.res.used_ref;
                if let Some(h) = &ref_oid {
                    res.chain_base_oids.push(h.clone());
                }
                res.chain_base_oids.extend(base.res.chain_base_oids.clone());
                return Rc::new(Outcome { res, content: None, rtype: None });
            }
        }
        // 预算检查：深度
        let depth = base.res.steps.len() as u32 + 1;
        if depth > self.budget.max_depth || depth > HARD_DEPTH_CAP {
            let mut res = Resolution::empty(Status::Paused);
            res.error = Some(format!(
                "delta 深度 {} 超过预算上限 {}",
                depth, self.budget.max_depth
            ));
            res.used_ref = ref_oid.is_some() || base.res.used_ref;
            return Rc::new(Outcome { res, content: None, rtype: None });
        }
        let base_content = base.content.clone().unwrap_or_default();
        let rtype = base.rtype.unwrap_or(ObjType::Blob);
        match delta::apply_delta(&base_content, &c.data) {
            Err(e) => Rc::new(Outcome::error(format!("delta 应用失败: {e}"))),
            Ok(applied) => {
                let out_len = applied.output.len() as u64;
                // 预算检查：单对象展开比例
                let ratio = out_len as f64 / c.packed_len.max(1) as f64;
                if ratio > self.budget.max_ratio {
                    let mut res = Resolution::empty(Status::Paused);
                    res.error = Some(format!(
                        "单对象展开比例 {:.1} 超过预算上限 {:.1}",
                        ratio, self.budget.max_ratio
                    ));
                    res.used_ref = ref_oid.is_some() || base.res.used_ref;
                    return Rc::new(Outcome { res, content: None, rtype: None });
                }
                // 预算检查：总展开字节
                if self.spent + out_len > self.budget.max_total_bytes {
                    let mut res = Resolution::empty(Status::Paused);
                    res.error = Some(format!(
                        "总展开字节预算耗尽: 已用 {}，本对象需 {}",
                        self.spent, out_len
                    ));
                    res.used_ref = ref_oid.is_some() || base.res.used_ref;
                    return Rc::new(Outcome { res, content: None, rtype: None });
                }
                self.spent += out_len;
                let oid = oid::hash_object(rtype, &applied.output);
                let checksum_ok = c.oid_hint.map(|h| h == oid);
                let truncated = applied.instructions.len() > MAX_INSTR_RECORDED;
                let instructions = if truncated {
                    applied.instructions[..MAX_INSTR_RECORDED].to_vec()
                } else {
                    applied.instructions.clone()
                };
                let data_range = c
                    .pack_offset
                    .map(|_| (0u64, c.data.len() as u64))
                    .unwrap_or((0, c.data.len() as u64));
                let step = DeltaStep {
                    seq: base.res.steps.len() as u32,
                    base: base_desc,
                    delta_range: data_range,
                    instructions,
                    instructions_truncated: truncated,
                    input_len: base_content.len() as u64,
                    output_len: out_len,
                    checksum_ok,
                };
                let mut res = Resolution::empty(Status::Resolved);
                res.oid = Some(oid::to_hex(&oid));
                res.steps = base.res.steps.clone();
                res.steps.push(step);
                res.expanded_bytes = base.res.expanded_bytes + out_len;
                res.deps = base.res.deps.clone();
                res.deps.insert(0, base_id);
                res.used_ref = ref_oid.is_some() || base.res.used_ref;
                res.chain_base_oids = base.res.chain_base_oids.clone();
                if let Some(h) = ref_oid {
                    res.chain_base_oids.push(h);
                }
                Rc::new(Outcome {
                    res,
                    content: Some(applied.output),
                    rtype: Some(rtype),
                })
            }
        }
    }
}
