use crate::db::{meta_get, meta_set};
use crate::git::{oid_hex, ObjType};
use crate::{delta, index as idxmod, loose as loosemod, pack as packmod};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const KIND_ENTRY: &str = "entry";
pub const KIND_LOOSE: &str = "loose";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NodeKind {
    Entry,
    Loose,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Entry => KIND_ENTRY,
            NodeKind::Loose => KIND_LOOSE,
        }
    }
    pub fn parse(s: &str) -> Option<NodeKind> {
        match s {
            KIND_ENTRY => Some(NodeKind::Entry),
            KIND_LOOSE => Some(NodeKind::Loose),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeRef {
    pub kind: NodeKind,
    pub id: i64,
}

impl NodeRef {
    fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.id)
    }
    fn parse_key(s: &str) -> Option<NodeRef> {
        let (k, id) = s.split_once(':')?;
        Some(NodeRef {
            kind: NodeKind::parse(k)?,
            id: id.parse().ok()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Budgets {
    pub max_depth: i64,
    pub max_total_bytes: i64,
    pub max_ratio: f64,
}

pub fn load_budgets(conn: &Connection) -> Budgets {
    conn.query_row(
        "SELECT max_depth, max_total_bytes, max_ratio FROM budgets WHERE id=1",
        [],
        |r| {
            Ok(Budgets {
                max_depth: r.get(0)?,
                max_total_bytes: r.get(1)?,
                max_ratio: r.get(2)?,
            })
        },
    )
    .expect("budgets 行存在")
}

pub fn save_budgets(conn: &Connection, b: &Budgets) {
    conn.execute(
        "UPDATE budgets SET max_depth=?1, max_total_bytes=?2, max_ratio=?3 WHERE id=1",
        params![b.max_depth, b.max_total_bytes, b.max_ratio],
    )
    .unwrap();
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChainItem {
    pub desc: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
struct Node {
    nref: NodeRef,
    desc: String,
    otype: ObjType,
    raw: Vec<u8>,
    base_entry: Option<i64>,
    base_oid: Option<String>,
    parse_error: Option<String>,
    sort_key: String,
    source_id: i64,
}

enum RStatus {
    Resolved(String),
    Blocked,
    Paused,
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub halted: bool,
    pub spent_bytes: u64,
}

struct ResolvedData {
    oid: String,
    otype: String,
    content: Vec<u8>,
    depth: i64,
}

struct Ctx<'c> {
    conn: &'c Connection,
    budgets: Budgets,
    spent: u64,
    run_id: i64,
    nodes: HashMap<NodeRef, Node>,
    status: HashMap<NodeRef, RStatus>,
    chains: HashMap<NodeRef, Vec<ChainItem>>,
    cache: HashMap<NodeRef, ResolvedData>,
    by_oid: HashMap<String, Vec<NodeRef>>,
    pins: HashMap<String, NodeRef>,
    stack: Vec<NodeRef>,
    attempted: HashSet<NodeRef>,
    new_oids: HashSet<String>,
    halt: bool,
    stats: Stats,
}

fn load_nodes(conn: &Connection) -> HashMap<NodeRef, Node> {
    let mut nodes = HashMap::new();
    let mut by_offset: HashMap<(i64, i64), i64> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT e.id, e.pack_id, e.idx, e.offset, e.otype, COALESCE(e.raw, x''),
                        e.base_offset, e.base_oid, e.parse_error, s.path, p.source_id
                 FROM entries e
                 JOIN packs p ON p.id = e.pack_id
                 JOIN sources s ON s.id = p.source_id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, i64>(10)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, pack_id, idx, offset, otype, raw, base_offset, base_oid, perr, path, source_id) =
                row.unwrap();
            by_offset.insert((pack_id, offset), id);
            let nref = NodeRef {
                kind: NodeKind::Entry,
                id,
            };
            nodes.insert(
                nref,
                Node {
                    nref,
                    desc: format!("{path} #{idx} @{offset}"),
                    otype: ObjType::from_name(&otype).unwrap_or(ObjType::Blob),
                    raw,
                    base_entry: None,
                    base_oid,
                    parse_error: perr,
                    sort_key: format!("{path}|E|{offset:016x}|{id}"),
                    source_id,
                },
            );
            let _ = (base_offset,);
        }
    }
    for n in nodes.values_mut() {
        if n.otype == ObjType::OfsDelta {
            let pack_id: i64 = conn
                .query_row(
                    "SELECT pack_id FROM entries WHERE id=?1",
                    [n.nref.id],
                    |r| r.get(0),
                )
                .unwrap();
            let base_offset: Option<i64> = conn
                .query_row(
                    "SELECT base_offset FROM entries WHERE id=?1",
                    [n.nref.id],
                    |r| r.get(0),
                )
                .unwrap();
            if let Some(bo) = base_offset {
                n.base_entry = by_offset.get(&(pack_id, bo)).copied();
                if n.base_entry.is_none() && n.parse_error.is_none() {
                    n.parse_error = Some(format!(
                        "ofs-delta 指向偏移 {bo}，但该 pack 中没有对应入口（ofs 距离越界/损坏）"
                    ));
                }
            }
        }
    }
    {
        let mut stmt = conn
            .prepare(
                "SELECT l.id, COALESCE(l.otype,'blob'), COALESCE(l.content, x''),
                        l.error, s.path, l.source_id
                 FROM loose_t l JOIN sources s ON s.id = l.source_id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, otype, content, error, path, source_id) = row.unwrap();
            let nref = NodeRef {
                kind: NodeKind::Loose,
                id,
            };
            nodes.insert(
                nref,
                Node {
                    nref,
                    desc: format!("{path} (loose)"),
                    otype: ObjType::from_name(&otype).unwrap_or(ObjType::Blob),
                    raw: content,
                    base_entry: None,
                    base_oid: None,
                    parse_error: error,
                    sort_key: format!("{path}|L|{id:016x}"),
                    source_id,
                },
            );
        }
    }
    nodes
}

impl<'c> Ctx<'c> {
    fn new(conn: &'c Connection, run_id: i64) -> Ctx<'c> {
        let nodes = load_nodes(conn);
        let mut status = HashMap::new();
        let mut cache = HashMap::new();
        let mut by_oid: HashMap<String, Vec<NodeRef>> = HashMap::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT node_kind, node_id, oid, otype, content, depth, status
                     FROM resolutions",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<Vec<u8>>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                })
                .unwrap();
            for row in rows {
                let (kind_s, id, oid, otype, content, depth, st) = row.unwrap();
                let kind = NodeKind::parse(&kind_s).unwrap();
                let nref = NodeRef { kind, id };
                match st.as_str() {
                    "resolved" => {
                        let oid = oid.unwrap();
                        status.insert(nref, RStatus::Resolved(oid.clone()));
                        cache.insert(
                            nref,
                            ResolvedData {
                                oid: oid.clone(),
                                otype: otype.unwrap_or_default(),
                                content: content.unwrap_or_default(),
                                depth,
                            },
                        );
                        by_oid.entry(oid).or_default().push(nref);
                    }
                    "blocked" => status.insert(nref, RStatus::Blocked),
                    _ => status.insert(nref, RStatus::Paused),
                };
            }
        }
        for v in by_oid.values_mut() {
            let nodes = &nodes;
            v.sort_by(|a, b| {
                nodes
                    .get(a)
                    .map(|n| n.sort_key.as_str())
                    .cmp(&nodes.get(b).map(|n| n.sort_key.as_str()))
            });
            v.dedup();
        }
        let mut pins = HashMap::new();
        let branch = active_branch(conn);
        {
            let mut stmt = conn
                .prepare("SELECT oid, node_kind, node_id FROM pins WHERE branch_id=?1")
                .unwrap();
            let rows = stmt
                .query_map(params![branch], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .unwrap();
            for row in rows {
                let (oid, kind_s, id) = row.unwrap();
                if let Some(kind) = NodeKind::parse(&kind_s) {
                    pins.insert(oid, NodeRef { kind, id });
                }
            }
        }
        let spent: u64 = meta_get(conn, "spent_bytes")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ctx {
            conn,
            budgets: load_budgets(conn),
            spent,
            run_id,
            nodes,
            status,
            chains: HashMap::new(),
            cache,
            by_oid,
            pins,
            stack: Vec::new(),
            attempted: HashSet::new(),
            new_oids: HashSet::new(),
            halt: false,
            stats: Stats::default(),
        }
    }

    fn desc_of(&self, n: NodeRef) -> String {
        self.nodes.get(&n).map(|x| x.desc.clone()).unwrap_or(n.key())
    }

    fn write_resolved(
        &mut self,
        nref: NodeRef,
        oid: &str,
        otype: &str,
        content: Vec<u8>,
        depth: i64,
        steps: Vec<StepRow>,
        uses: Vec<NodeRef>,
    ) {
        self.conn
            .execute(
                "INSERT INTO resolutions(node_kind,node_id,oid,status,otype,size,content,depth,
                    block_reason,blocking_chain,pause_state,run_id)
                 VALUES(?1,?2,?3,'resolved',?4,?5,?6,?7,NULL,NULL,NULL,?8)
                 ON CONFLICT(node_kind,node_id) DO UPDATE SET
                    oid=excluded.oid,status='resolved',otype=excluded.otype,size=excluded.size,
                    content=excluded.content,depth=excluded.depth,
                    block_reason=NULL,blocking_chain=NULL,pause_state=NULL,run_id=excluded.run_id",
                params![
                    nref.kind.as_str(),
                    nref.id,
                    oid,
                    otype,
                    content.len() as i64,
                    content,
                    depth,
                    self.run_id
                ],
            )
            .unwrap();
        self.clear_owner_rows(nref);
        for (i, s) in steps.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT INTO steps(owner_kind,owner_id,seq,base_desc,instr_offset,instr_len,
                        input_len,output_len,result_oid,ok,note)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10)",
                    params![
                        nref.kind.as_str(),
                        nref.id,
                        i as i64 + 1,
                        s.base_desc,
                        s.instr_offset as i64,
                        s.instr_len as i64,
                        s.input_len as i64,
                        s.output_len as i64,
                        s.result_oid,
                        s.note
                    ],
                )
                .unwrap();
        }
        for u in uses {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO uses(owner_kind,owner_id,used_kind,used_id)
                     VALUES(?1,?2,?3,?4)",
                    params![nref.kind.as_str(), nref.id, u.kind.as_str(), u.id],
                )
                .unwrap();
        }
        self.status.insert(nref, RStatus::Resolved(oid.to_string()));
        self.cache.insert(
            nref,
            ResolvedData {
                oid: oid.to_string(),
                otype: otype.to_string(),
                content,
                depth,
            },
        );
        let list = self.by_oid.entry(oid.to_string()).or_default();
        if !list.contains(&nref) {
            list.push(nref);
            list.sort_by(|a, b| {
                self.nodes
                    .get(a)
                    .map(|n| n.sort_key.as_str())
                    .cmp(&self.nodes.get(b).map(|n| n.sort_key.as_str()))
            });
        }
        self.new_oids.insert(oid.to_string());
        self.stats.resolved += 1;
    }

    fn clear_owner_rows(&self, nref: NodeRef) {
        self.conn
            .execute(
                "DELETE FROM steps WHERE owner_kind=?1 AND owner_id=?2",
                params![nref.kind.as_str(), nref.id],
            )
            .unwrap();
        self.conn
            .execute(
                "DELETE FROM uses WHERE owner_kind=?1 AND owner_id=?2",
                params![nref.kind.as_str(), nref.id],
            )
            .unwrap();
        self.conn
            .execute(
                "DELETE FROM needs WHERE owner_kind=?1 AND owner_id=?2",
                params![nref.kind.as_str(), nref.id],
            )
            .unwrap();
    }

    struct StepRow {
        base_desc: String,
        instr_offset: usize,
        instr_len: usize,
        input_len: usize,
        output_len: usize,
        result_oid: String,
        note: Option<String>,
    }

    fn mark_blocked(
        &mut self,
        nref: NodeRef,
        reason: &str,
        chain: &[ChainItem],
        needs: &[String],
    ) {
        self.clear_owner_rows(nref);
        for need in needs {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO needs(owner_kind,owner_id,need_oid) VALUES(?1,?2,?3)",
                    params![nref.kind.as_str(), nref.id, need],
                )
                .unwrap();
        }
        let chain_json = serde_json::to_string(chain).unwrap();
        self.conn
            .execute(
                "INSERT INTO resolutions(node_kind,node_id,oid,status,otype,size,content,depth,
                    block_reason,blocking_chain,pause_state,run_id)
                 VALUES(?1,?2,NULL,'blocked',NULL,NULL,NULL,0,?3,?4,NULL,?5)
                 ON CONFLICT(node_kind,node_id) DO UPDATE SET
                    oid=NULL,status='blocked',otype=NULL,size=NULL,content=NULL,depth=0,
                    block_reason=excluded.block_reason,
                    blocking_chain=excluded.blocking_chain,
                    pause_state=NULL,run_id=excluded.run_id",
                params![nref.kind.as_str(), nref.id, reason, chain_json, self.run_id],
            )
            .unwrap();
        self.status.insert(nref, RStatus::Blocked);
        self.chains.insert(nref, chain.to_vec());
        self.stats.blocked += 1;
    }

    fn mark_paused(&mut self, nref: NodeRef, reason: &str, state: serde_json::Value) {
        self.conn
            .execute(
                "INSERT INTO resolutions(node_kind,node_id,oid,status,otype,size,content,depth,
                    block_reason,blocking_chain,pause_state,run_id)
                 VALUES(?1,?2,NULL,'paused',NULL,NULL,NULL,0,?3,NULL,?4,?5)
                 ON CONFLICT(node_kind,node_id) DO UPDATE SET
                    oid=NULL,status='paused',otype=NULL,size=NULL,content=NULL,depth=0,
                    block_reason=excluded.block_reason,blocking_chain=NULL,
                    pause_state=excluded.pause_state,run_id=excluded.run_id",
                params![
                    nref.kind.as_str(),
                    nref.id,
                    reason,
                    state.to_string(),
                    self.run_id
                ],
            )
            .unwrap();
        self.status.insert(nref, RStatus::Paused);
        self.stats.paused += 1;
    }

    fn get_resolved(&mut self, nref: NodeRef) -> Option<ResolvedData> {
        if let Some(d) = self.cache.get(&nref) {
            return Some(ResolvedData {
                oid: d.oid.clone(),
                otype: d.otype.clone(),
                content: d.content.clone(),
                depth: d.depth,
            });
        }
        let row = self
            .conn
            .query_row(
                "SELECT oid,otype,content,depth FROM resolutions
                 WHERE node_kind=?1 AND node_id=?2 AND status='resolved'",
                params![nref.kind.as_str(), nref.id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .ok()?;
        Some(ResolvedData {
            oid: row.0,
            otype: row.1,
            content: row.2,
            depth: row.3,
        })
    }

    fn choose_candidate(&self, oid: &str) -> Option<NodeRef> {
        let list = self.by_oid.get(oid)?;
        if list.is_empty() {
            return None;
        }
        if let Some(pinned) = self.pins.get(oid) {
            if list.contains(pinned) {
                return Some(*pinned);
            }
        }
        list.first().copied()
    }

    fn chain_from(&self, nref: NodeRef, own: ChainItem) -> Vec<ChainItem> {
        let mut chain = self.chains.get(&nref).cloned().unwrap_or_default();
        chain.insert(0, own);
        chain
    }

    fn resolve(&mut self, nref: NodeRef) -> Result<String, ()> {
        if let Some(RStatus::Resolved(oid)) = self.status.get(&nref) {
            return Ok(oid.clone());
        }
        if let Some(pos) = self.stack.iter().position(|x| *x == nref) {
            let cyc: Vec<NodeRef> = self.stack[pos..].to_vec();
            let chain: Vec<ChainItem> = cyc
                .iter()
                .map(|m| ChainItem {
                    desc: self.desc_of(*m),
                    reason: "处于 delta 环中".into(),
                })
                .collect();
            for m in &cyc {
                self.mark_blocked(*m, "delta 形成环，无法选择 base", &chain, &[]);
            }
            return Err(());
        }
        if self.halt {
            self.mark_paused(
                nref,
                "总展开字节预算已耗尽，等待提高预算后恢复",
                serde_json::json!({"reason":"total_bytes"}),
            );
            return Err(());
        }
        let node = match self.nodes.get(&nref).cloned() {
            Some(n) => n,
            None => return Err(()),
        };
        if let Some(err) = &node.parse_error {
            let chain = vec![ChainItem {
                desc: node.desc.clone(),
                reason: err.clone(),
            }];
            self.mark_blocked(nref, &format!("解析失败: {err}"), &chain, &[]);
            return Err(());
        }
        self.stack.push(nref);
        let result = self.resolve_inner(nref, &node);
        self.stack.pop();
        result
    }

    fn resolve_inner(&mut self, nref: NodeRef, node: &Node) -> Result<String, ()> {
        if !node.otype.is_delta() {
            let type_name = node.otype.name();
            let oid = oid_hex(type_name, &node.raw);
            let content = node.raw.clone();
            self.write_resolved(nref, &oid, type_name, content, 0, vec![], vec![]);
            return Ok(oid);
        }
        let (base_ref, base_desc) = if node.otype == ObjType::OfsDelta {
            match node.base_entry {
                Some(id) => {
                    let r = NodeRef {
                        kind: NodeKind::Entry,
                        id,
                    };
                    (r, format!("ofs -> {}", self.desc_of(r)))
                }
                None => {
                    let chain = vec![ChainItem {
                        desc: node.desc.clone(),
                        reason: "ofs-delta 找不到对应入口".into(),
                    }];
                    self.mark_blocked(nref, "ofs 距离越界或 base 入口缺失", &chain, &[]);
                    return Err(());
                }
            }
        } else {
            let need = node.base_oid.clone().unwrap();
            match self.choose_candidate(&need) {
                Some(r) => (
                    r,
                    format!("ref {} -> {}", need, self.desc_of(r)),
                ),
                None => {
                    let chain = vec![ChainItem {
                        desc: node.desc.clone(),
                        reason: format!("缺少外部 base {need}"),
                    }];
                    self.mark_blocked(
                        nref,
                        &format!("缺少外部 base {need}"),
                        &chain,
                        &[need.clone()],
                    );
                    return Err(());
                }
            }
        };
        if self.resolve(base_ref).is_err() {
            match self.status.get(&base_ref) {
                Some(RStatus::Paused) => {
                    self.mark_paused(
                        nref,
                        "等待 base 还原（base 当前处于暂停状态）",
                        serde_json::json!({"reason":"base_paused","base":base_ref.key()}),
                    );
                }
                _ => {
                    let chain = self.chain_from(
                        base_ref,
                        ChainItem {
                            desc: node.desc.clone(),
                            reason: "依赖的 base 未还原".into(),
                        },
                    );
                    self.mark_blocked(nref, "依赖链阻塞: base 未还原", &chain, &[]);
                }
            }
            return Err(());
        }
        let base = self.get_resolved(base_ref).unwrap();
        let depth = base.depth + 1;
        if depth > self.budgets.max_depth {
            self.mark_paused(
                nref,
                &format!("delta 深度 {depth} 超过预算 {}（可重试的中间状态）", self.budgets.max_depth),
                serde_json::json!({"reason":"depth","depth":depth}),
            );
            return Err(());
        }
        let meta = match delta::read_header(&node.raw) {
            Ok(m) => m,
            Err(e) => {
                let chain = vec![ChainItem {
                    desc: node.desc.clone(),
                    reason: format!("delta 头损坏: {e}"),
                }];
                self.mark_blocked(nref, &format!("delta 头损坏: {e}"), &chain, &[]);
                return Err(());
            }
        };
        if meta.src_size as usize != base.content.len() {
            let chain = vec![ChainItem {
                desc: node.desc.clone(),
                reason: format!(
                    "delta 声明源大小 {} 与 base 长度 {} 不符",
                    meta.src_size,
                    base.content.len()
                ),
            }];
            self.mark_blocked(nref, "delta 源大小与 base 不符", &chain, &[]);
            return Err(());
        }
        if base.content.len() > 0
            && meta.tgt_size as f64 > self.budgets.max_ratio * base.content.len() as f64
        {
            self.mark_paused(
                nref,
                &format!(
                    "单对象膨胀比例 {} 超过预算 {}（疑似解压炸弹/伪造大小）",
                    meta.tgt_size as f64 / base.content.len() as f64,
                    self.budgets.max_ratio
                ),
                serde_json::json!({"reason":"ratio","tgt":meta.tgt_size,"base_len":base.content.len()}),
            );
            return Err(());
        }
        if self.spent.saturating_add(meta.tgt_size) > self.budgets.max_total_bytes as u64 {
            self.halt = true;
            self.mark_paused(
                nref,
                "总展开字节预算将被突破，暂停（提高预算后可恢复，不输出部分对象）",
                serde_json::json!({"reason":"total_bytes","need":meta.tgt_size,"spent":self.spent}),
            );
            return Err(());
        }
        match delta::apply(&base.content, &node.raw) {
            Ok((out, applied_meta)) => {
                let out_len = out.len();
                let in_len = base.content.len();
                self.spent += out_len as u64;
                let oid = oid_hex(&base.otype, &out);
                let step = StepRow {
                    base_desc,
                    instr_offset: applied_meta.instr_start,
                    instr_len: applied_meta.instr_end - applied_meta.instr_start,
                    input_len: in_len,
                    output_len: out_len,
                    result_oid: oid.clone(),
                    note: Some(format!("{} 条指令", applied_meta.ops)),
                };
                self.write_resolved(
                    nref,
                    &oid,
                    &base.otype,
                    out,
                    depth,
                    vec![step],
                    vec![base_ref],
                );
                Ok(oid)
            }
            Err(e) => {
                let chain = vec![ChainItem {
                    desc: node.desc.clone(),
                    reason: format!("delta 应用失败: {e}"),
                }];
                self.mark_blocked(nref, &format!("delta 应用失败: {e}"), &chain, &[]);
                Err(())
            }
        }
    }
}
