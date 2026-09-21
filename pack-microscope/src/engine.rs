use crate::delta::{apply_delta, delta_headers, DeltaError};
use crate::git::{git_object_id, ObjType};
use crate::store::{branch_id, get_budget, list_candidates, list_branches, Budget};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Clone, Debug)]
struct Node {
    ckey: String,
    source_id: i64,
    source_kind: String,
    oid: Option<String>,
    obj_type: String,
    offset: Option<i64>,
    ofs_distance: Option<i64>,
    ref_base: Option<String>,
    content: Option<Vec<u8>>,
    declared_size: i64,
    actual_size: i64,
    crc_ok: Option<bool>,
    parse_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepRecord {
    pub ordinal: i64,
    pub ckey: String,
    pub delta_kind: String,
    pub base_ckey: String,
    pub base_oid: Option<String>,
    pub input_len: i64,
    pub output_len: i64,
    pub instruction_start: i64,
    pub instruction_end: i64,
    pub copies: i64,
    pub inserts: i64,
    pub check_ok: bool,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChainLink {
    pub ckey: String,
    pub oid: Option<String>,
    pub obj_type: String,
    pub role: String,
    pub status: String,
}

#[derive(Clone, Debug)]
enum Outcome {
    Resolved {
        typ: ObjType,
        content: Vec<u8>,
        oid: String,
        oid_matches: Option<bool>,
        depth: i64,
        charged: i64,
        steps: Vec<StepRecord>,
        chain: Vec<ChainLink>,
    },
    Error {
        reason: String,
        code: String,
        evidence: Option<String>,
        steps: Vec<StepRecord>,
        chain: Vec<ChainLink>,
    },
    Blocked {
        reason: String,
        code: String,
        evidence: Option<String>,
        steps: Vec<StepRecord>,
        chain: Vec<ChainLink>,
        need_oid: Option<String>,
        need_offset: Option<i64>,
    },
    Suspended {
        reason: String,
        code: String,
        evidence: Option<String>,
        steps: Vec<StepRecord>,
        chain: Vec<ChainLink>,
        need_bytes: i64,
        depth: i64,
        partial_output_len: i64,
    },
}

struct Engine {
    nodes: BTreeMap<String, Node>,
    by_offset: HashMap<(i64, i64), String>,
    by_oid: BTreeMap<String, Vec<String>>,
    pins: HashMap<String, String>,
    budget: Budget,
    used: i64,
    cache: HashMap<String, Outcome>,
    relink: Vec<(String, String)>,
    current_selected: HashMap<String, String>,
    charged_nodes: HashSet<String>,
}

pub struct RunReport {
    pub branch_id: i64,
    pub evaluated: usize,
    pub resolved: usize,
    pub errors: usize,
    pub blocked: usize,
    pub suspended: usize,
    pub used_bytes: i64,
}

pub fn run_branch(
    conn: &Connection,
    branch_name: &str,
    only: Option<&[String]>,
) -> rusqlite::Result<RunReport> {
    let branch = branch_id(conn, branch_name)?;
    let budget = get_budget(conn, branch)?;
    let rows = list_candidates(conn)?;
    let pins = load_pins(conn, branch)?;
    let mut eng = Engine {
        nodes: BTreeMap::new(),
        by_offset: HashMap::new(),
        by_oid: BTreeMap::new(),
        pins,
        used: budget.used_bytes,
        budget: budget.clone(),
        cache: HashMap::new(),
        relink: Vec::new(),
        current_selected: HashMap::new(),
        charged_nodes: HashSet::new(),
    };
    for r in rows {
        let key = r.ckey.clone();
        if let Some(off) = r.offset {
            eng.by_offset.insert((r.source_id, off), key.clone());
        }
        if let Some(oid) = &r.oid {
            eng.by_oid
                .entry(oid.clone())
                .or_default()
                .push(key.clone());
        }
        eng.nodes.insert(
            key,
            Node {
                ckey: r.ckey,
                source_id: r.source_id,
                source_kind: r.source_kind,
                oid: r.oid,
                obj_type: r.obj_type,
                offset: r.offset,
                ofs_distance: r.ofs_distance,
                ref_base: r.ref_base,
                content: r.content,
                declared_size: r.declared_size,
                actual_size: r.actual_size.unwrap_or(0),
                crc_ok: r.crc_ok,
                parse_error: r.parse_error,
            },
        );
    }
    for v in eng.by_oid.values_mut() {
        v.sort_by(|a, b| candidate_rank(&eng.nodes, a, b));
    }
    let targets: Vec<String> = match only {
        Some(keys) => keys.iter().filter(|k| eng.nodes.contains_key(k.as_str())).cloned().collect(),
        None => eng.nodes.keys().cloned().collect(),
    };
    if only.is_some() {
        let mut old_charged: i64 = 0;
        for k in &targets {
            old_charged += conn
                .query_row(
                    "SELECT COALESCE(charged_bytes,0) FROM resolved WHERE branch_id=? AND ckey=?",
                    params![branch, k],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0);
        }
        eng.used = (eng.used - old_charged).max(0);
    }
    let mut report = RunReport {
        branch_id: branch,
        evaluated: 0,
        resolved: 0,
        errors: 0,
        blocked: 0,
        suspended: 0,
        used_bytes: budget.used_bytes,
    };
    let mut results: Vec<(String, Outcome)> = Vec::new();
    let mut evaluated_now: HashSet<String> = HashSet::new();
    for key in &targets {
        if let Some(out) = eng.cache.get(key) {
            results.push((key.clone(), out.clone()));
            evaluated_now.insert(key.clone());
            continue;
        }
        let mut stack = HashSet::new();
        let out = eng.resolve(key, 0, &mut stack);
        evaluated_now.insert(key.clone());
        results.push((key.clone(), out));
    }
    for (key, out) in &results {
        if evaluated_now.contains(key) {
            report.evaluated += 1;
            match out {
                Outcome::Resolved { .. } => report.resolved += 1,
                Outcome::Error { .. } => report.errors += 1,
                Outcome::Blocked { .. } => report.blocked += 1,
                Outcome::Suspended { .. } => report.suspended += 1,
            }
            persist_outcome(conn, branch, &eng.nodes[key], out, &mut report)?;
        }
    }
    let now_keys: Vec<String> = evaluated_now.iter().cloned().collect();
    persist_relink(conn, branch, &eng.relink, &now_keys)?;
    conn.execute(
        "UPDATE budgets SET used_bytes=?1 WHERE branch_id=?2",
        params![eng.used, branch],
    )?;
    report.used_bytes = eng.used;
    Ok(report)
}

fn load_pins(conn: &Connection, branch: i64) -> rusqlite::Result<HashMap<String, String>> {
    let mut stmt = conn.prepare("SELECT oid, ckey FROM pins WHERE branch_id=?")?;
    let rows = stmt.query_map(params![branch], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut map = HashMap::new();
    for r in rows {
        let (oid, ckey) = r?;
        map.insert(oid, ckey);
    }
    Ok(map)
}

fn candidate_rank(nodes: &BTreeMap<String, Node>, a: &str, b: &str) -> std::cmp::Ordering {
    let na = &nodes[a];
    let nb = &nodes[b];
    let rank = |n: &Node| -> u8 {
        if n.parse_error.is_some() || n.crc_ok == Some(false) {
            9
        } else if n.source_kind == "loose" {
            0
        } else if n.obj_type != "ofs-delta" && n.obj_type != "ref-delta" {
            1
        } else {
            2
        }
    };
    rank(na)
        .cmp(&rank(nb))
        .then_with(|| na.source_id.cmp(&nb.source_id))
        .then_with(|| na.offset.unwrap_or(-1).cmp(&nb.offset.unwrap_or(-1)))
        .then_with(|| na.ckey.cmp(&nb.ckey))
}

impl Engine {
    fn node_chain_link(&self, key: &str, role: &str, status: &str) -> ChainLink {
        let n = &self.nodes[key];
        ChainLink {
            ckey: key.to_string(),
            oid: n.oid.clone(),
            obj_type: n.obj_type.clone(),
            role: role.to_string(),
            status: status.to_string(),
        }
    }

    fn charge(&mut self, ckey: &str, size: i64) {
        if self.charged_nodes.insert(ckey.to_string()) {
            self.used += size;
        }
    }

    fn chain_declared_size(
        &self,
        key: &str,
        seen: &mut HashSet<String>,
        depth: i64,
    ) -> Result<(i64, i64), String> {
        if !seen.insert(key.to_string()) {
            return Err("cycle".into());
        }
        let n = &self.nodes[key];
        if depth + 1 > self.budget.max_depth {
            return Err("depth".into());
        }
        if !ObjType::named(&n.obj_type).map(|t| t.is_delta()).unwrap_or(false) {
            let size = n.actual_size.max(n.declared_size.max(0));
            return Ok((size, depth.max(1)));
        }
        let base_key = if n.obj_type == "ofs-delta" {
            let dist = n.ofs_distance.unwrap_or(0);
            let base_off = n.offset.unwrap_or(0) - dist;
            let key2 = self.by_offset.get(&(n.source_id, base_off)).cloned();
            match key2 {
                Some(k) => k,
                None => return Err("missing_ofs".into()),
            }
        } else {
            let want = match &n.ref_base {
                Some(w) => w,
                None => return Err("missing_ref".into()),
            };
            match self.pins.get(want).cloned().or_else(|| {
                self.by_oid.get(want).and_then(|v| v.first().cloned())
            }) {
                Some(k) => k,
                None => return Err("missing_ref".into()),
            }
        };
        let (base_total, base_depth) = self.chain_declared_size(&base_key, seen, depth + 1)?;
        let payload = match &n.content {
            Some(p) => p,
            None => return Ok((base_total, base_depth)),
        };
        let (_bs, result_size, _he) = delta_headers(payload).map_err(|_| "bad_delta_header".to_string())?;
        Ok((base_total + result_size as i64, base_depth.max(depth + 2)))
    }

    fn resolve(&mut self, key: &str, depth: i64, stack: &mut HashSet<String>) -> Outcome {
        if let Some(out) = self.cache.get(key) {
            return out.clone();
        }
        if stack.contains(key) {
            let chain: Vec<ChainLink> = stack
                .iter()
                .chain(std::iter::once(&key.to_string()))
                .map(|k| self.node_chain_link(k, "cycle", "error"))
                .collect();
            return Outcome::Error {
                reason: format!("delta 链形成环，回到 {}", key),
                code: "cycle".into(),
                evidence: Some(serde_json::json!({"cycle_member": key}).to_string()),
                steps: vec![],
                chain,
            };
        }
        stack.insert(key.to_string());
        let outcome = self.resolve_inner(key, depth, stack);
        stack.remove(key);
        let is_cycle = matches!(
            &outcome,
            Outcome::Error { code, .. } if code == "cycle"
        );
        if !is_cycle {
            self.cache.insert(key.to_string(), outcome.clone());
        }
        outcome
    }

    fn resolve_inner(&mut self, key: &str, depth: i64, stack: &mut HashSet<String>) -> Outcome {
        let n = self.nodes[key].clone();
        if let Some(err) = &n.parse_error {
            return Outcome::Error {
                reason: format!("候选对象本身损坏，已隔离: {}", err),
                code: "corrupt_candidate".into(),
                evidence: Some(serde_json::json!({"ckey": key}).to_string()),
                steps: vec![],
                chain: vec![self.node_chain_link(key, "self", "error")],
            };
        }
        if n.crc_ok == Some(false) {
            return Outcome::Error {
                reason: "idx CRC32 校验失败，候选对象已隔离".into(),
                code: "crc_mismatch".into(),
                evidence: Some(serde_json::json!({"ckey": key}).to_string()),
                steps: vec![],
                chain: vec![self.node_chain_link(key, "self", "error")],
            };
        }
        if depth == 0 {
            let mut seen = HashSet::new();
            match self.chain_declared_size(key, &mut seen, 0) {
                Ok((total, _max_depth)) => {
                    let single_cap =
                        (self.budget.total_bytes as f64 * self.budget.single_ratio) as i64;
                    if total > single_cap {
                        return Outcome::Suspended {
                            reason: format!(
                                "该对象整条 delta 链需展开 {} 字节，超过单对象比例上限 {}",
                                total, single_cap
                            ),
                            code: "single_object_limit".into(),
                            evidence: Some(
                                serde_json::json!({"need": total, "cap": single_cap}).to_string(),
                            ),
                            steps: vec![],
                            chain: vec![self.node_chain_link(key, "root", "suspended")],
                            need_bytes: total,
                            depth: 1,
                            partial_output_len: 0,
                        };
                    }
                }
                Err(e) if e == "depth" => {
                    return Outcome::Suspended {
                        reason: format!(
                            "delta 链深度超过预算上限 {}",
                            self.budget.max_depth
                        ),
                        code: "depth_limit".into(),
                        evidence: None,
                        steps: vec![],
                        chain: vec![self.node_chain_link(key, "root", "suspended")],
                        need_bytes: 0,
                        depth: self.budget.max_depth + 1,
                        partial_output_len: 0,
                    };
                }
                Err(_) => {}
            }
        }
        let typ = match ObjType::named(&n.obj_type) {
            Some(t) => t,
            None => {
                return Outcome::Error {
                    reason: format!("未知对象类型 {}", n.obj_type),
                    code: "unknown_type".into(),
                    evidence: None,
                    steps: vec![],
                    chain: vec![self.node_chain_link(key, "self", "error")],
                }
            }
        };
        if !typ.is_delta() {
            self.resolve_leaf(key, &n, typ, depth)
        } else {
            self.resolve_delta(key, &n, typ, depth, stack)
        }
    }

    fn leaf_charge(&self, size: i64, depth: i64) -> Result<(), Outcome> {
        if depth + 1 > self.budget.max_depth {
            return Err(Outcome::Suspended {
                reason: format!("delta 深度 {} 超过预算上限 {}", depth + 1, self.budget.max_depth),
                code: "depth_limit".into(),
                evidence: None,
                steps: vec![],
                chain: vec![],
                need_bytes: 0,
                depth: depth + 1,
                partial_output_len: 0,
            });
        }
        let single_cap = (self.budget.total_bytes as f64 * self.budget.single_ratio) as i64;
        if size > single_cap {
            return Err(Outcome::Suspended {
                reason: format!(
                    "单对象需要 {} 字节，超过单对象预算上限 {}（total={}, ratio={}）",
                    size, single_cap, self.budget.total_bytes, self.budget.single_ratio
                ),
                code: "single_object_limit".into(),
                evidence: Some(serde_json::json!({"need": size, "cap": single_cap}).to_string()),
                steps: vec![],
                chain: vec![],
                need_bytes: size,
                depth: depth + 1,
                partial_output_len: 0,
            });
        }
        if self.used.saturating_add(size) > self.budget.total_bytes {
            return Err(Outcome::Suspended {
                reason: format!(
                    "总展开字节 {}+{} 超过预算 {}（可重试的中间状态）",
                    self.used, size, self.budget.total_bytes
                ),
                code: "total_budget".into(),
                evidence: Some(
                    serde_json::json!({"used": self.used, "need": size, "budget": self.budget.total_bytes})
                        .to_string(),
                ),
                steps: vec![],
                chain: vec![],
                need_bytes: size,
                depth: depth + 1,
                partial_output_len: 0,
            });
        }
        Ok(())
    }

    fn resolve_leaf(&mut self, key: &str, n: &Node, typ: ObjType, depth: i64) -> Outcome {
        let content = match &n.content {
            Some(c) => c.clone(),
            None => {
                return Outcome::Error {
                    reason: "非 delta 候选缺少已解压内容".into(),
                    code: "missing_content".into(),
                    evidence: None,
                    steps: vec![],
                    chain: vec![self.node_chain_link(key, "self", "error")],
                }
            }
        };
        if let Err(suspended) = self.leaf_charge(content.len() as i64, depth) {
            return suspended;
        }
        let computed = git_object_id(typ.base_type().unwrap(), &content);
        let computed_hex = hex::encode(computed);
        let oid_matches = n.oid.as_ref().map(|declared| declared == &computed_hex);
        if let Some(false) = oid_matches {
            return Outcome::Error {
                reason: format!(
                    "重算 object id {} 与候选声明 oid {} 不一致",
                    computed_hex,
                    n.oid.as_ref().unwrap()
                ),
                code: "oid_mismatch".into(),
                evidence: Some(
                    serde_json::json!({"declared": n.oid, "computed": computed_hex}).to_string(),
                ),
                steps: vec![],
                chain: vec![self.node_chain_link(key, "self", "error")],
            };
        }
        let charged = content.len() as i64;
        self.charge(&n.ckey, charged);
        Outcome::Resolved {
            typ,
            content,
            oid: computed_hex,
            oid_matches,
            depth,
            charged,
            steps: vec![],
            chain: vec![self.node_chain_link(key, "leaf", "resolved")],
        }
    }

    fn choose_ofs_base(&self, n: &Node) -> Result<String, Outcome> {
        let dist = n.ofs_distance.unwrap_or(0);
        let off = n.offset.unwrap_or(0);
        let base_off = off - dist;
        if base_off < 12 {
            return Err(Outcome::Error {
                reason: format!("ofs-delta 距离 {} 越界（base offset {}）", dist, base_off),
                code: "ofs_out_of_range".into(),
                evidence: Some(serde_json::json!({"distance": dist, "base_offset": base_off}).to_string()),
                steps: vec![],
                chain: vec![self.node_chain_link(&n.ckey, "self", "error")],
            });
        }
        if let Some(key) = self.by_offset.get(&(n.source_id, base_off)) {
            Ok(key.clone())
        } else {
            Err(Outcome::Blocked {
                reason: format!("ofs-delta 指向的 base offset {} 在本包中不存在（可能是 thin pack 缺外部 base）", base_off),
                code: "missing_ofs_base".into(),
                evidence: Some(serde_json::json!({"distance": dist, "base_offset": base_off}).to_string()),
                steps: vec![],
                chain: vec![self.node_chain_link(&n.ckey, "delta", "blocked")],
                need_oid: None,
                need_offset: Some(base_off),
            })
        }
    }

    fn choose_ref_base(&mut self, n: &Node) -> Result<String, Outcome> {
        let want = match &n.ref_base {
            Some(o) => o.clone(),
            None => {
                return Err(Outcome::Error {
                    reason: "ref-delta 缺少 base oid".into(),
                    code: "missing_ref".into(),
                    evidence: None,
                    steps: vec![],
                    chain: vec![self.node_chain_link(&n.ckey, "self", "error")],
                })
            }
        };
        let candidates = match self.by_oid.get(&want) {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                return Err(Outcome::Blocked {
                    reason: format!("ref-delta 需要的外部 base {} 尚未导入", want),
                    code: "missing_ref_base".into(),
                    evidence: Some(serde_json::json!({"need_oid": want}).to_string()),
                    steps: vec![],
                    chain: vec![self.node_chain_link(&n.ckey, "delta", "blocked")],
                    need_oid: Some(want),
                    need_offset: None,
                })
            }
        };
        let chosen = if let Some(pinned) = self.pins.get(&want) {
            if candidates.iter().any(|c| c == pinned) {
                pinned.clone()
            } else {
                candidates[0].clone()
            }
        } else {
            candidates[0].clone()
        };
        self.current_selected.insert(want.clone(), chosen.clone());
        Ok(chosen)
    }

    fn resolve_delta(&mut self, key: &str, n: &Node, typ: ObjType, depth: i64, stack: &mut HashSet<String>) -> Outcome {
        if depth + 1 > self.budget.max_depth {
            return Outcome::Suspended {
                reason: format!("delta 深度 {} 超过预算上限 {}", depth + 1, self.budget.max_depth),
                code: "depth_limit".into(),
                evidence: None,
                steps: vec![],
                chain: vec![self.node_chain_link(key, "delta", "suspended")],
                need_bytes: 0,
                depth: depth + 1,
                partial_output_len: 0,
            };
        }
        let base_key = match typ {
            ObjType::OfsDelta => match self.choose_ofs_base(n) {
                Ok(k) => k,
                Err(o) => return o,
            },
            ObjType::RefDelta => match self.choose_ref_base(n) {
                Ok(k) => k,
                Err(outcome) => {
                    if let Some(want) = &n.ref_base {
                        self.relink
                            .push((key.to_string(), format!("want-oid:{}", want)));
                    }
                    return outcome;
                }
            },
            _ => unreachable!(),
        };
        self.relink.push((key.to_string(), base_key.clone()));
        let delta_bytes = match &n.content {
            Some(c) => c.clone(),
            None => {
                return Outcome::Error {
                    reason: "delta 候选缺少已解压的 delta 指令负载".into(),
                    code: "missing_delta".into(),
                    evidence: None,
                    steps: vec![],
                    chain: vec![self.node_chain_link(key, "delta", "error")],
                }
            }
        };
        let (base_declared, result_declared, header_end) = match delta_headers(&delta_bytes) {
            Ok(v) => v,
            Err(e) => {
                return Outcome::Error {
                    reason: format!("delta 头部解析失败: {:?}", e),
                    code: "delta_header".into(),
                    evidence: Some(serde_json::json!({"error": format!("{:?}", e)}).to_string()),
                    steps: vec![],
                    chain: vec![self.node_chain_link(key, "delta", "error")],
                }
            }
        };
        let base_out = if stack.contains(&base_key) {
            let mut chain = vec![self.node_chain_link(key, "delta", "error")];
            chain.push(self.node_chain_link(&base_key, "base", "error"));
            return Outcome::Error {
                reason: format!("delta 链形成环：{} -> {}", key, base_key),
                code: "cycle".into(),
                evidence: Some(serde_json::json!({"from": key, "to": base_key}).to_string()),
                steps: vec![],
                chain,
            };
        } else {
            self.resolve(&base_key, depth + 1, stack)
        };
        let (base_typ, base_content, base_oid, base_depth, _base_charged, _base_steps, mut chain) = match base_out {
            Outcome::Resolved {
                typ,
                content,
                oid,
                depth: bd,
                charged,
                steps,
                chain: c,
                ..
            } => (typ, content, oid, bd, charged, steps, c),
            Outcome::Error { reason, code, evidence, steps, chain: c } => {
                return Outcome::Blocked {
                    reason: format!("base 不可用，无法还原 delta: {}", reason),
                    code: format!("base_error:{}", code),
                    evidence,
                    steps,
                    chain: c,
                    need_oid: None,
                    need_offset: None,
                }
            }
            Outcome::Blocked { reason, code, evidence, steps, chain: c, need_oid, need_offset } => {
                return Outcome::Blocked {
                    reason: format!("base 未就绪: {}", reason),
                    code: format!("base_blocked:{}", code),
                    evidence,
                    steps,
                    chain: c,
                    need_oid,
                    need_offset,
                }
            }
            Outcome::Suspended { reason, code, evidence, steps, chain: c, need_bytes, depth: sd, partial_output_len } => {
                return Outcome::Suspended {
                    reason: format!("base 还原暂停: {}", reason),
                    code: format!("base_suspended:{}", code),
                    evidence,
                    steps,
                    chain: c,
                    need_bytes,
                    depth: sd,
                    partial_output_len,
                }
            }
        };
        if base_declared != base_content.len() as u64 {
            return Outcome::Error {
                reason: format!(
                    "delta 基大小欺骗：声明 {}，实际 base 长度 {}",
                    base_declared,
                    base_content.len()
                ),
                code: "delta_base_size_spoof".into(),
                evidence: Some(
                    serde_json::json!({"declared": base_declared, "actual": base_content.len()}).to_string(),
                ),
                steps: vec![],
                chain,
            };
        }
        let single_cap = (self.budget.total_bytes as f64 * self.budget.single_ratio) as i64;
        if result_declared as i64 > single_cap {
            return Outcome::Suspended {
                reason: format!(
                    "delta 结果声明 {} 字节，超过单对象预算 {}",
                    result_declared, single_cap
                ),
                code: "single_object_limit".into(),
                evidence: Some(serde_json::json!({"need": result_declared, "cap": single_cap}).to_string()),
                steps: vec![],
                chain,
                need_bytes: result_declared as i64,
                depth: depth + 1,
                partial_output_len: 0,
            };
        }
        if self.used.saturating_add(result_declared as i64) > self.budget.total_bytes {
            return Outcome::Suspended {
                reason: format!(
                    "应用 delta 还需 {} 字节，累计将超过总预算 {}（可重试的中间状态，不输出部分对象）",
                    result_declared, self.budget.total_bytes
                ),
                code: "total_budget".into(),
                evidence: Some(serde_json::json!({
                    "used": self.used, "need": result_declared, "budget": self.budget.total_bytes
                }).to_string()),
                steps: vec![],
                chain,
                need_bytes: result_declared as i64,
                depth: depth + 1,
                partial_output_len: 0,
            };
        }
        let (out_content, trace) = match apply_delta(&base_content, &delta_bytes) {
            Ok(v) => v,
            Err(e) => {
                return Outcome::Error {
                    reason: format!("delta 指令执行失败: {}", delta_err_text(&e)),
                    code: "delta_apply".into(),
                    evidence: Some(delta_err_evidence(&e)),
                    steps: vec![],
                    chain,
                }
            }
        };
        let check_ok = out_content.len() as u64 == result_declared;
        let step = StepRecord {
            ordinal: 0,
            ckey: key.to_string(),
            delta_kind: typ.type_name().to_string(),
            base_ckey: base_key.clone(),
            base_oid: Some(base_oid.clone()),
            input_len: trace.input_len as i64,
            output_len: trace.output_len as i64,
            instruction_start: trace.instruction_range.0 as i64 + header_end as i64,
            instruction_end: trace.instruction_range.1 as i64 + header_end as i64,
            copies: trace.copies as i64,
            inserts: trace.inserts as i64,
            check_ok,
            evidence: Some(serde_json::to_string(&trace).unwrap_or_default()),
        };
        self.charge(&n.ckey, out_content.len() as i64);
        let computed = git_object_id(base_typ.base_type().unwrap(), &out_content);
        let computed_hex = hex::encode(computed);
        let oid_matches = n.oid.as_ref().map(|d| d == &computed_hex);
        if let Some(false) = oid_matches {
            chain.push(self.node_chain_link(key, "delta", "error"));
            return Outcome::Error {
                reason: format!("delta 链还原对象的重算 id {} 与声明 oid {} 不一致", computed_hex, n.oid.as_ref().unwrap()),
                code: "oid_mismatch".into(),
                evidence: Some(serde_json::json!({"declared": n.oid, "computed": computed_hex}).to_string()),
                steps: vec![step],
                chain,
            };
        }
        chain.push(ChainLink {
            ckey: key.to_string(),
            oid: Some(computed_hex.clone()),
            obj_type: base_typ.type_name().to_string(),
            role: "delta".into(),
            status: "resolved".into(),
        });
        Outcome::Resolved {
            typ: base_typ,
            content: out_content,
            oid: computed_hex,
            oid_matches,
            depth: base_depth.max(depth + 1),
            charged: result_declared as i64,
            steps: vec![step],
            chain,
        }
    }
}

fn delta_err_text(e: &DeltaError) -> String {
    match e {
        DeltaError::Truncated => "delta 数据被截断".into(),
        DeltaError::BaseSizeMismatch { declared, actual } => {
            format!("基大小不匹配：声明 {}，实际 {}", declared, actual)
        }
        DeltaError::ResultSizeMismatch { declared, actual } => {
            format!("结果大小不匹配：声明 {}，实际 {}", declared, actual)
        }
        DeltaError::CopyOutOfRange { src_off, len, base_len } => format!(
            "copy 越界：src_off={}, len={}, base_len={}",
            src_off, len, base_len
        ),
        DeltaError::InsertOutOfRange { offset, len, remain } => format!(
            "insert 越界：offset={}, len={}, remain={}",
            offset, len, remain
        ),
        DeltaError::ReservedOpcode(op, at) => format!("offset {} 处保留 opcode 0x{:02x}", at, op),
        DeltaError::BadTrailer => "delta 尾部异常".into(),
        DeltaError::BadHeader(m) => format!("delta 头部错误: {}", m),
    }
}

fn delta_err_evidence(e: &DeltaError) -> String {
    serde_json::to_value(e)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "{}".into())
}

fn persist_outcome(
    conn: &Connection,
    branch: i64,
    n: &Node,
    out: &Outcome,
    _report: &mut RunReport,
) -> rusqlite::Result<()> {
    let (new_status, new_oid, new_type, new_len, new_reason, new_evidence): (
        &str,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    ) = match out {
        Outcome::Resolved { oid, typ, content, oid_matches, .. } => (
            "resolved",
            Some(oid.clone()),
            Some(typ.type_name().to_string()),
            Some(content.len() as i64),
            None,
            oid_matches.map(|v| v.to_string()),
        ),
        Outcome::Error { reason, evidence, .. } => {
            ("error", n.oid.clone(), Some(n.obj_type.clone()), None, Some(reason.clone()), evidence.clone())
        }
        Outcome::Blocked { reason, evidence, .. } => {
            ("blocked", n.oid.clone(), Some(n.obj_type.clone()), None, Some(reason.clone()), evidence.clone())
        }
        Outcome::Suspended { reason, evidence, .. } => {
            ("suspended", n.oid.clone(), Some(n.obj_type.clone()), None, Some(reason.clone()), evidence.clone())
        }
    };
    let unchanged = conn
        .query_row(
            "SELECT status, oid, obj_type, COALESCE(content_len,-1), COALESCE(reason,''), COALESCE(evidence,'')
             FROM resolved WHERE branch_id=? AND ckey=?",
            params![branch, n.ckey],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .map(|(st, oid, ty, len, reason, ev)| {
            st == new_status
                && oid == new_oid
                && ty == new_type
                && Some(len) == new_len
                && reason.as_str() == new_reason.as_deref().unwrap_or("")
                && ev.as_str() == new_evidence.as_deref().unwrap_or("")
        })
        .unwrap_or(false);
    if unchanged {
        return Ok(());
    }
    conn.execute("DELETE FROM steps WHERE branch_id=? AND ckey=?", params![branch, n.ckey])?;
    match out {
        Outcome::Resolved {
            typ,
            content,
            oid,
            oid_matches,
            depth,
            charged,
            steps,
            chain,
        } => {
            conn.execute(
                "INSERT INTO resolved(branch_id, ckey, oid, status, obj_type, content, content_len,
                     depth, charged_bytes, reason, evidence, base_ckey, chain_json, updated_at)
                 VALUES(?1,?2,?3,'resolved',?4,?5,?6,?7,?8,NULL,?9,?10,?11,?12)
                 ON CONFLICT(branch_id, ckey) DO UPDATE SET
                   oid=excluded.oid, status='resolved', obj_type=excluded.obj_type,
                   content=excluded.content, content_len=excluded.content_len, depth=excluded.depth,
                   charged_bytes=excluded.charged_bytes, reason=NULL, evidence=excluded.evidence,
                   base_ckey=excluded.base_ckey, chain_json=excluded.chain_json, updated_at=excluded.updated_at",
                params![
                    branch,
                    n.ckey,
                    oid,
                    typ.type_name(),
                    content,
                    content.len() as i64,
                    depth,
                    charged,
                    oid_matches.map(|v| v.to_string()),
                    steps.first().map(|s| s.base_ckey.clone()),
                    serde_json::to_string(chain).unwrap_or_default(),
                    crate::store::now_ms(),
                ],
            )?;
            for s in steps {
                insert_step(conn, branch, s)?;
            }
        }
        Outcome::Error {
            reason,
            code,
            evidence,
            steps,
            chain,
        } => {
            conn.execute(
                "INSERT INTO resolved(branch_id, ckey, oid, status, obj_type, content, content_len,
                     depth, charged_bytes, reason, evidence, base_ckey, chain_json, updated_at)
                 VALUES(?1,?2,?3,'error',?4,NULL,NULL,NULL,0,?5,?6,?7,?8,?9)
                 ON CONFLICT(branch_id, ckey) DO UPDATE SET
                   oid=excluded.oid, status='error', obj_type=excluded.obj_type,
                   content=NULL, content_len=NULL, depth=NULL, charged_bytes=0,
                   reason=excluded.reason, evidence=excluded.evidence,
                   base_ckey=excluded.base_ckey, chain_json=excluded.chain_json, updated_at=excluded.updated_at",
                params![
                    branch,
                    n.ckey,
                    n.oid,
                    n.obj_type,
                    format!("{}: {}", code, reason),
                    evidence,
                    steps.first().map(|s| s.base_ckey.clone()),
                    serde_json::to_string(chain).unwrap_or_default(),
                    crate::store::now_ms(),
                ],
            )?;
            for s in steps {
                insert_step(conn, branch, s)?;
            }
        }
        Outcome::Blocked {
            reason,
            code,
            evidence,
            steps,
            chain,
            need_oid,
            need_offset,
        } => {
            let mut ev = serde_json::json!({"code": code});
            if let Some(o) = need_oid {
                ev["need_oid"] = serde_json::json!(o);
            }
            if let Some(off) = need_offset {
                ev["need_offset"] = serde_json::json!(off);
            }
            if let Some(e) = evidence {
                ev["detail"] = serde_json::json!(e);
            }
            conn.execute(
                "INSERT INTO resolved(branch_id, ckey, oid, status, obj_type, content, content_len,
                     depth, charged_bytes, reason, evidence, base_ckey, chain_json, updated_at)
                 VALUES(?1,?2,?3,'blocked',?4,NULL,NULL,NULL,0,?5,?6,?7,?8,?9)
                 ON CONFLICT(branch_id, ckey) DO UPDATE SET
                   oid=excluded.oid, status='blocked', obj_type=excluded.obj_type,
                   content=NULL, content_len=NULL, depth=NULL, charged_bytes=0,
                   reason=excluded.reason, evidence=excluded.evidence,
                   base_ckey=excluded.base_ckey, chain_json=excluded.chain_json, updated_at=excluded.updated_at",
                params![
                    branch,
                    n.ckey,
                    n.oid,
                    n.obj_type,
                    reason,
                    ev.to_string(),
                    steps.first().map(|s| s.base_ckey.clone()),
                    serde_json::to_string(chain).unwrap_or_default(),
                    crate::store::now_ms(),
                ],
            )?;
            for s in steps {
                insert_step(conn, branch, s)?;
            }
        }
        Outcome::Suspended {
            reason,
            code,
            evidence,
            steps,
            chain,
            need_bytes,
            depth,
            partial_output_len,
        } => {
            let ev = serde_json::json!({
                "code": code,
                "need_bytes": need_bytes,
                "depth": depth,
                "partial_output_len": partial_output_len,
                "retryable": true,
                "detail": evidence,
            });
            conn.execute(
                "INSERT INTO resolved(branch_id, ckey, oid, status, obj_type, content, content_len,
                     depth, charged_bytes, reason, evidence, base_ckey, chain_json, updated_at)
                 VALUES(?1,?2,?3,'suspended',?4,NULL,NULL,?5,0,?6,?7,?8,?9,?10)
                 ON CONFLICT(branch_id, ckey) DO UPDATE SET
                   oid=excluded.oid, status='suspended', obj_type=excluded.obj_type,
                   content=NULL, content_len=NULL, depth=excluded.depth, charged_bytes=0,
                   reason=excluded.reason, evidence=excluded.evidence,
                   base_ckey=excluded.base_ckey, chain_json=excluded.chain_json, updated_at=excluded.updated_at",
                params![
                    branch,
                    n.ckey,
                    n.oid,
                    n.obj_type,
                    depth,
                    reason,
                    ev.to_string(),
                    steps.first().map(|s| s.base_ckey.clone()),
                    serde_json::to_string(chain).unwrap_or_default(),
                    crate::store::now_ms(),
                ],
            )?;
            for s in steps {
                insert_step(conn, branch, s)?;
            }
        }
    }
    Ok(())
}

fn insert_step(conn: &Connection, branch: i64, s: &StepRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO steps(branch_id, ordinal, ckey, delta_kind, base_ckey, base_oid,
             input_len, output_len, instruction_start, instruction_end, copies, inserts, check_ok, evidence)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            branch,
            s.ordinal,
            s.ckey,
            s.delta_kind,
            s.base_ckey,
            s.base_oid,
            s.input_len,
            s.output_len,
            s.instruction_start,
            s.instruction_end,
            s.copies,
            s.inserts,
            s.check_ok as i64,
            s.evidence,
        ],
    )?;
    Ok(())
}

fn persist_relink(
    conn: &Connection,
    branch: i64,
    relink: &[(String, String)],
    targets: &[String],
) -> rusqlite::Result<()> {
    let target_set: HashSet<&str> = targets.iter().map(|s| s.as_str()).collect();
    for (ckey, _) in relink {
        if target_set.contains(ckey.as_str()) {
            conn.execute(
                "DELETE FROM relink WHERE branch_id=? AND ckey=?",
                params![branch, ckey],
            )?;
        }
    }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (ckey, base) in relink {
        if !target_set.contains(ckey.as_str()) {
            continue;
        }
        if seen.insert((ckey.clone(), base.clone())) {
            conn.execute(
                "INSERT OR IGNORE INTO relink(branch_id, ckey, base_ckey) VALUES(?1,?2,?3)",
                params![branch, ckey, base],
            )?;
        }
    }
    Ok(())
}

pub fn recompute_affected(
    conn: &Connection,
    branch_name: &str,
    seeds: &[String],
) -> rusqlite::Result<RunReport> {
    let branch = branch_id(conn, branch_name)?;
    let seed_set: HashSet<String> = seeds.iter().cloned().collect();
    let mut reverse: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT ckey, base_ckey FROM relink WHERE branch_id=?",
    )?;
    let edges = stmt.query_map(params![branch], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    for edge in edges {
        let (ckey, base) = edge?;
        reverse.entry(base).or_default().push(ckey);
    }
    let mut expanded: Vec<String> = seed_set.into_iter().collect();
    for seed in seeds {
        let oid: Option<String> = conn
            .query_row(
                "SELECT oid FROM candidates WHERE ckey=?",
                params![seed],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(oid) = oid {
            expanded.push(format!("want-oid:{}", oid));
        }
    }
    let mut affected: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = expanded;
    while let Some(k) = queue.pop() {
        if affected.insert(k.clone()) {
            if let Some(deps) = reverse.get(&k) {
                for d in deps {
                    if !affected.contains(d) {
                        queue.push(d.clone());
                    }
                }
            }
        }
    }
    let keys: Vec<String> = affected.into_iter().collect();
    run_branch(conn, branch_name, Some(&keys))
}

pub fn rerun_all_branches(
    conn: &Connection,
    seeds: Option<&[String]>,
) -> rusqlite::Result<Vec<(String, RunReport)>> {
    let branches = list_branches(conn)?;
    let mut out = Vec::new();
    for (_, name) in branches {
        let report = match seeds {
            Some(s) => recompute_affected(conn, &name, s)?,
            None => run_branch(conn, &name, None)?,
        };
        out.push((name, report));
    }
    Ok(out)
}
