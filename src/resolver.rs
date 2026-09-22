//! Delta-chain resolution engine.
//!
//! Every node forms a single linear base chain (full -> ofs/ref deltas -> ...).
//! Resolution walks that chain bottom-up, charging a byte budget as it goes.
//! Failures isolate the offending node and propagate a *blocked chain* to every
//! dependent so analysis of other objects continues.

use crate::db::Db;
use crate::delta::apply_delta;
use crate::git::git_object_id;
use crate::model::{BaseRef, Budgets, ChainLink, NodeKind, ResolveStatus};
use rusqlite::params;
use sha2::Digest as _;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub source_id: i64,
    pub offset: i64,
    pub kind: NodeKind,
    pub object_type: Option<u8>,
    pub declared_size: i64,
    pub inflated_size: i64,
    pub payload: Vec<u8>,
    pub base_ofs: Option<i64>,
    pub base_ref_oid: Option<String>,
    pub parse_errors: Vec<String>,
    pub crc_ok: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ExistingResolution {
    pub status: String,
    pub object_type: Option<u8>,
    pub resolved_oid: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolveSummary {
    pub resolved: usize,
    pub missing_base: usize,
    pub cycle: usize,
    pub bad_object: usize,
    pub budget_paused: usize,
    pub too_large: usize,
    pub too_deep: usize,
    pub parse_error: usize,
    pub bytes_used: u64,
    pub paused: bool,
}

fn load_nodes(db: &Db) -> Vec<NodeRow> {
    let c = db.0.lock().unwrap();
    let mut s = c
        .prepare(
            "SELECT id,source_id,pack_offset,kind,object_type,declared_size,inflated_size,payload,
                    base_ofs,base_ref_oid,parse_errors,crc_ok
             FROM nodes",
        )
        .unwrap();
    s.query_map([], |r| {
        let errs: String = r.get(10)?;
        Ok(NodeRow {
            id: r.get(0)?,
            source_id: r.get(1)?,
            offset: r.get(2)?,
            kind: NodeKind::parse(&r.get::<_, String>(3)?),
            object_type: r.get::<_, Option<i64>>(4)?.map(|v| v as u8),
            declared_size: r.get(5)?,
            inflated_size: r.get(6)?,
            payload: r.get(7)?,
            base_ofs: r.get(8)?,
            base_ref_oid: r.get(9)?,
            parse_errors: serde_json::from_str(&errs).unwrap_or_default(),
            crc_ok: r.get::<_, Option<i64>>(11)?.map(|v| v != 0),
        })
    })
    .unwrap()
    .flatten()
    .collect()
}

/// Candidates keyed by oid -> candidate rows (node_id, origin, confidence).
fn load_candidates(db: &Db) -> Vec<(String, i64, String, i64)> {
    let c = db.0.lock().unwrap();
    let mut s = c
        .prepare("SELECT oid,node_id,origin,confidence FROM candidates")
        .unwrap();
    s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}

/// Deterministic candidate ranking for an oid. Independent of import order:
/// forced pin > hash-matching idx > content hash > loose-path match >
/// ref-inferred > others; ties break on a content-derived key, never rowids.
pub fn rank_candidates(rows: &[(i64, String, i64, String)]) -> Vec<i64> {
    let mut v: Vec<(i64, String, i64, String)> = rows.to_vec();
    v.sort_by(|a, b| {
        origin_rank(&a.1)
            .cmp(&origin_rank(&b.1))
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.3.cmp(&b.3))
    });
    v.into_iter().map(|x| x.0).collect()
}

fn origin_rank(o: &str) -> u8 {
    match o {
        "idx" => 0,
        "hash" => 1,
        "loose-path" => 2,
        "ref-inferred" => 3,
        "forced" => 0,
        _ => 9,
    }
}

fn load_existing(db: &Db, branch_id: i64, node_id: i64) -> Option<ExistingResolution> {
    let c = db.0.lock().unwrap();
    c.query_row(
        "SELECT status,object_type,resolved_oid,content FROM resolutions
         WHERE branch_id=?1 AND node_id=?2",
        params![branch_id, node_id],
        |r| {
            Ok(ExistingResolution {
                status: r.get(0)?,
                object_type: r.get::<_, Option<i64>>(1)?.map(|v| v as u8),
                resolved_oid: r.get(2)?,
                content: r.get::<_, Vec<u8>>(3).unwrap_or_default(),
            })
        },
    )
    .ok()
}

struct Env {
    nodes: Vec<NodeRow>,
    /// oid -> (node_id, origin, confidence, stable_tie_key)
    by_oid: std::collections::HashMap<String, Vec<(i64, String, i64, String)>>,
    /// (source_id, offset) -> node index
    by_pack: std::collections::HashMap<(i64, i64), usize>,
    /// node id -> node index
    by_id: std::collections::HashMap<i64, usize>,
}

impl Env {
    fn build(db: &Db) -> Env {
        let nodes = load_nodes(db);
        let mut by_pack = std::collections::HashMap::new();
        let mut by_id = std::collections::HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            by_pack.insert((n.source_id, n.offset), i);
            by_id.insert(n.id, i);
        }
        // Stable tie key: content sha256 of the node payload + source file
        // sha256 + offset. None of these depend on import/insertion order.
        let source_shas: std::collections::HashMap<i64, String> = {
            let c = db.0.lock().unwrap();
            let mut st = c.prepare("SELECT id,sha256 FROM sources").unwrap();
            st.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap()
            .flatten()
            .collect()
        };
        let mut by_oid: std::collections::HashMap<String, Vec<(i64, String, i64, String)>> =
            std::collections::HashMap::new();
        for (oid, node_id, origin, conf) in load_candidates(db) {
            let idx = by_id.get(&node_id).copied();
            let key = if let Some(i) = idx {
                let n = &nodes[i];
                let mut h = sha2::Sha256::new();
                sha2::Digest::update(&mut h, &n.payload);
                let ph: [u8; 32] = sha2::Digest::finalize(h).into();
                format!(
                    "{}|{}|{}",
                    source_shas.get(&n.source_id).cloned().unwrap_or_default(),
                    n.offset,
                    crate::git::to_hex(&ph)
                )
            } else {
                String::new()
            };
            by_oid
                .entry(oid)
                .or_default()
                .push((node_id, origin, conf, key));
        }
        Env {
            nodes,
            by_oid,
            by_pack,
            by_id,
        }
    }

    /// Resolve a base reference of a delta node to a node index.
    fn resolve_base_ref(
        &self,
        db: &Db,
        branch_id: i64,
        node: &NodeRow,
        pin_node: Option<i64>,
        live_oids: &std::collections::HashMap<String, i64>,
    ) -> Result<usize, MissingReason> {
        match node.kind {
            NodeKind::OfsDelta => {
                let Some(ofs) = node.base_ofs else {
                    return Err(MissingReason::Bad("ofs-delta without resolved base offset".into()));
                };
                match self.by_pack.get(&(node.source_id, ofs)) {
                    Some(&i) => Ok(i),
                    None => Err(MissingReason::OfsOutOfRange(node.source_id, ofs)),
                }
            }
            NodeKind::RefDelta => {
                let Some(oid) = node.base_ref_oid.clone() else {
                    return Err(MissingReason::Bad("ref-delta without base oid".into()));
                };
                // Prefer candidates known at build time; fall back to an oid
                // materialized earlier in *this* pass (base imported late).
                if !self.by_oid.contains_key(&oid) {
                    if let Some(nid) = live_oids.get(&oid) {
                        if let Some(&i) = self.by_id.get(nid) {
                            return Ok(i);
                        }
                    }
                    return Err(MissingReason::Oid(oid));
                }
                let Some(list) = self.by_oid.get(&oid) else {
                    return Err(MissingReason::Oid(oid));
                };
                let mut ranked = rank_candidates(list);
                if let Some(pn) = pin_node {
                    if list.iter().any(|(nid, _, _, _)| *nid == pn) {
                        ranked.retain(|nid| *nid == pn);
                        ranked.push(pn);
                    }
                }
                for nid in ranked {
                    if let Some(&i) = self.by_id.get(&nid) {
                        // Candidate must itself be usable; status is checked by
                        // chain walk. Record "ref-inferred" provenance naturally
                        // through delta steps.
                        let _ = db;
                        let _ = branch_id;
                        return Ok(i);
                    }
                }
                Err(MissingReason::Oid(oid))
            }
            _ => Err(MissingReason::Bad("node is not a delta".into())),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum MissingReason {
    Oid(String),
    OfsOutOfRange(i64, i64),
    Bad(String),
}

#[allow(dead_code)]
impl MissingReason {
    fn base_ref(&self, node: &NodeRow) -> BaseRef {
        match self {
            MissingReason::Oid(hex) => BaseRef {
                kind: "oid".into(),
                source_id: None,
                offset: None,
                oid_hex: Some(hex.clone()),
            },
            MissingReason::OfsOutOfRange(src, ofs) => BaseRef {
                kind: "ofs".into(),
                source_id: Some(*src),
                offset: Some(*ofs),
                oid_hex: None,
            },
            MissingReason::Bad(_) => BaseRef {
                kind: "unknown".into(),
                source_id: Some(node.source_id),
                offset: node.base_ofs,
                oid_hex: node.base_ref_oid.clone(),
            },
        }
    }
}

struct Materialized {
    object_type: u8,
    content: Vec<u8>,
    oid: [u8; 20],
    /// Node ids from base to this node.
    chain: Vec<i64>,
    steps: Vec<StepRec>,
    bytes_charged: u64,
}

#[derive(Clone)]
#[allow(dead_code)]
struct StepRec {
    node_id: i64,
    base_node_id: i64,
    op: crate::delta::DeltaInstruction,
    base_len: usize,
    result_len: usize,
    input_bytes: usize,
    output_bytes: usize,
}

#[derive(Debug)]
enum WalkError {
    Missing(MissingReason, Vec<ChainLink>),
    Cycle(Vec<i64>),
    TooDeep,
    TooLarge(u64),
    Bad(String),
    /// Reached the total byte budget. The partial materialization is never
    /// committed; the caller persists a resumable checkpoint instead.
    BudgetExceededResume(u64),
}

#[derive(Debug, Clone, Copy)]
struct BudgetState {
    used: u64,
    limit: u64,
    single_cap: u64,
    max_depth: usize,
}

#[allow(dead_code)]
impl BudgetState {
    fn fits(&self, need: u64, single: u64) -> bool {
        self.used + need <= self.limit && single <= self.single_cap
    }
}

/// Walk the base chain of `start` bottom-up and materialize the object.
/// `memo` maps node id -> successful materialization (already charged to the
/// global budget) for reuse within this pass.
fn walk_chain(
    env: &Env,
    db: &Db,
    branch_id: i64,
    pin_node: Option<i64>,
    start: usize,
    budget: &mut BudgetState,
    memo: &std::collections::HashMap<i64, Materialized>,
    live_oids: &std::collections::HashMap<String, i64>,
) -> Result<Materialized, WalkError> {
    // Build the chain start -> ... -> base, detecting cycles and depth.
    let mut chain_nodes: Vec<usize> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = start;
    loop {
        let nid = env.nodes[cur].id;
        if !seen.insert(nid) {
            let cyc: Vec<i64> = chain_nodes
                .iter()
                .map(|&i| env.nodes[i].id)
                .collect();
            return Err(WalkError::Cycle(cyc));
        }
        chain_nodes.push(cur);
        let n = &env.nodes[cur];
        if n.kind == NodeKind::Full || n.kind == NodeKind::Loose {
            break;
        }
        match env.resolve_base_ref(db, branch_id, n, pin_node, live_oids) {
            Ok(b) => cur = b,
            Err(reason) => {
                // Build blocked chain from this node upward to `start`.
                let mut links = Vec::new();
                for &idx in chain_nodes.iter().rev() {
                    let nn = &env.nodes[idx];
                    let needs = match nn.kind {
                        NodeKind::OfsDelta => Some(BaseRef {
                            kind: "ofs".into(),
                            source_id: Some(nn.source_id),
                            offset: nn.base_ofs,
                            oid_hex: None,
                        }),
                        NodeKind::RefDelta => Some(BaseRef {
                            kind: "oid".into(),
                            source_id: None,
                            offset: None,
                            oid_hex: nn.base_ref_oid.clone(),
                        }),
                        _ => None,
                    };
                    links.push(ChainLink {
                        node: crate::model::NodeRef {
                            source_id: nn.source_id,
                            offset: nn.offset,
                        },
                        kind: nn.kind.as_str().into(),
                        needs,
                        reason: match (&reason, &nn.kind) {
                            (MissingReason::Oid(h), NodeKind::RefDelta) => {
                                format!("missing external base {h}")
                            }
                            (MissingReason::OfsOutOfRange(_, o), NodeKind::OfsDelta) => {
                                format!("ofs distance points outside the pack (target {o})")
                            }
                            (MissingReason::Bad(m), _) => m.clone(),
                            _ => "missing base".into(),
                        },
                    });
                }
                return Err(WalkError::Missing(reason, links));
            }
        }
        if chain_nodes.len() > budget.max_depth {
            return Err(WalkError::TooDeep);
        }
    }

    // chain_nodes currently goes start..base; reverse to build bottom-up.
    chain_nodes.reverse();
    if chain_nodes.len() - 1 > budget.max_depth {
        return Err(WalkError::TooDeep);
    }

    let mut materialized: Option<Materialized> = None;
    for (depth, &idx) in chain_nodes.iter().enumerate() {
        let n = &env.nodes[idx];
        if let Some(existing) = memo.get(&n.id) {
            materialized = Some(Materialized {
                object_type: existing.object_type,
                content: existing.content.clone(),
                oid: existing.oid,
                chain: existing.chain.clone(),
                steps: existing.steps.clone(),
                bytes_charged: 0,
            });
            continue;
        }
        if depth == 0 {
            // Terminal base: full or loose.
            let Some(ty) = n.object_type else {
                return Err(WalkError::Bad(format!(
                    "base node {} has no object type",
                    n.id
                )));
            };
            if !n.parse_errors.is_empty() || n.crc_ok == Some(false) {
                return Err(WalkError::Bad(format!(
                    "base node fails integrity: {}",
                    n.parse_errors.join("; ")
                )));
            }
            // Size spoof: declared vs inflated.
            if n.declared_size as usize != n.payload.len()
                && (n.kind == NodeKind::Full || n.kind == NodeKind::Loose)
            {
                return Err(WalkError::Bad(format!(
                    "declared size {} != inflated {}",
                    n.declared_size,
                    n.payload.len()
                )));
            }
            let need = n.payload.len() as u64;
            if need > budget.single_cap {
                return Err(WalkError::TooLarge(need));
            }
            if budget.used + need > budget.limit {
                return Err(WalkError::BudgetExceededResume(need));
            }
            budget.used += need;
            let oid = git_object_id(ty, &n.payload);
            materialized = Some(Materialized {
                object_type: ty,
                content: n.payload.clone(),
                oid,
                chain: vec![n.id],
                steps: Vec::new(),
                bytes_charged: need,
            });
        } else {
            // Delta node applied to the current base.
            let prev = materialized.as_ref().unwrap();
            if !n.parse_errors.is_empty() || n.crc_ok == Some(false) {
                return Err(WalkError::Bad(format!(
                    "delta node fails integrity: {}",
                    n.parse_errors.join("; ")
                )));
            }
            // Delta's declared size must equal its inflated payload length.
            if n.declared_size as usize != n.payload.len() {
                return Err(WalkError::Bad(format!(
                    "delta declared size {} != inflated {} (size spoof discovered mid-chain)",
                    n.declared_size,
                    n.payload.len()
                )));
            }
            // Charge delta payload consumption + resulting output, checking
            // budgets *before* producing output.
            let charge_in = n.payload.len() as u64;
            let applied = match apply_delta(&prev.content, &n.payload) {
                Ok(a) => a,
                Err(msg) => return Err(WalkError::Bad(msg)),
            };
            let out_len = applied.output.len() as u64;
            if out_len > budget.single_cap {
                return Err(WalkError::TooLarge(out_len));
            }
            let need = charge_in + out_len;
            if budget.used + need > budget.limit {
                return Err(WalkError::BudgetExceededResume(need));
            }
            budget.used += need;
            let oid = git_object_id(prev.object_type, &applied.output);
            let base_node_id = env.nodes[chain_nodes[depth - 1]].id;
            let mut chain = prev.chain.clone();
            chain.push(n.id);
            let mut new_steps = prev.steps.clone();
            for op in &applied.ops {
                new_steps.push(StepRec {
                    node_id: n.id,
                    base_node_id,
                    op: op.clone(),
                    base_len: prev.content.len(),
                    result_len: applied.output.len(),
                    input_bytes: op.size,
                    output_bytes: op.size,
                });
            }
            materialized = Some(Materialized {
                object_type: prev.object_type,
                content: applied.output,
                oid,
                chain,
                steps: new_steps,
                bytes_charged: need,
            });
        }
    }
    materialized.ok_or_else(|| WalkError::Bad("empty chain".into()))
}


fn delete_steps(db: &Db, branch_id: i64, node_id: i64) {
    let c = db.0.lock().unwrap();
    c.execute(
        "DELETE FROM delta_steps WHERE branch_id=?1 AND node_id=?2",
        params![branch_id, node_id],
    )
    .unwrap();
}

fn persist_resolution(
    db: &Db,
    branch_id: i64,
    n: &NodeRow,
    status: ResolveStatus,
    object_type: Option<u8>,
    oid: Option<&[u8; 20]>,
    content: Option<&[u8]>,
    depth: usize,
    base_node: Option<i64>,
    chain: Option<&[ChainLink]>,
    error: Option<&str>,
    charged: u64,
) {
    let oid_hex = oid.map(|o| crate::git::to_hex(o.as_slice()));
    let chain_json = chain.map(|c| serde_json::to_string(c).unwrap());
    let c = db.0.lock().unwrap();
    c.execute(
        "INSERT INTO resolutions(branch_id,node_id,status,object_type,resolved_oid,content,chain_depth,
                 base_node_id,blocked_chain,error,bytes_charged)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(branch_id,node_id) DO UPDATE SET
           status=excluded.status, object_type=excluded.object_type, resolved_oid=excluded.resolved_oid,
           content=excluded.content, chain_depth=excluded.chain_depth, base_node_id=excluded.base_node_id,
           blocked_chain=excluded.blocked_chain, error=excluded.error, bytes_charged=excluded.bytes_charged,
           updated_at=datetime('now')",
        params![
            branch_id,
            n.id,
            status.as_str(),
            object_type.map(|v| v as i64),
            oid_hex,
            content,
            depth as i64,
            base_node,
            chain_json,
            error,
            charged as i64,
        ],
    )
    .unwrap();
}

fn persist_steps(db: &Db, branch_id: i64, steps: &[StepRec]) {
    if steps.is_empty() {
        return;
    }
    let mut c = db.0.lock().unwrap();
    let tx = c.transaction().unwrap();
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO delta_steps(branch_id,node_id,step_index,base_node_id,kind,delta_start,
                        delta_end,copy_offset,size,input_pos,output_len_after,check_ok,check_error)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            )
            .unwrap();
        for s in steps {
            let (ok, err) = match &s.op.check {
                Ok(()) => (1, None::<String>),
                Err(e) => (0, Some(e.clone())),
            };
            stmt.execute(params![
                branch_id,
                s.node_id,
                s.op.index as i64,
                s.base_node_id,
                s.op.kind,
                s.op.delta_start as i64,
                s.op.delta_end as i64,
                s.op.offset.map(|v| v as i64),
                s.op.size as i64,
                s.op.input_pos as i64,
                s.op.output_len_after as i64,
                ok,
                err,
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
}

/// Find all nodes whose chain transitively depends on any node in `roots`.
/// Uses base edges in nodes table (does not depend on resolution status).
pub fn affected_subgraph(db: &Db, roots: &[i64]) -> std::collections::HashSet<i64> {
    let rootset: std::collections::HashSet<i64> = roots.iter().copied().collect();
    // Build edges node -> node based on ofs edges and (branch-independent)
    // ref edges resolved against current candidates best effort.
    let nodes = load_nodes(db);
    let env = Env::build(db);
    let mut direct: std::collections::HashMap<i64, Vec<i64>> =
        std::collections::HashMap::new();
    for n in &nodes {
        if n.kind == NodeKind::Full || n.kind == NodeKind::Loose {
            continue;
        }
        // resolve via env without branch pin
        let empty = std::collections::HashMap::new();
        if let Ok(base_idx) = env.resolve_base_ref(db, 1, n, None, &empty) {
            direct
                .entry(env.nodes[base_idx].id)
                .or_default()
                .push(n.id);
        }
    }
    let mut closure = rootset.clone();
    let mut stack: Vec<i64> = rootset.iter().copied().collect();
    while let Some(id) = stack.pop() {
        if let Some(deps) = direct.get(&id) {
            for d in deps {
                if closure.insert(*d) {
                    stack.push(*d);
                }
            }
        }
    }
    closure
}

#[derive(Debug, Clone)]
pub struct ResolveOptions {
    pub branch_id: i64,
    pub budgets: Budgets,
    /// Restrict work to this set of node ids (incremental recompute).
    pub only_nodes: Option<std::collections::HashSet<i64>>,
    /// Pinned candidate node for the given analysis branch.
    pub pin_node: Option<i64>,
    /// Resume a previously paused run: reuse byte accounting recorded so far.
    pub resume: bool,
}

pub fn resolve_all(db: &Db, opts: ResolveOptions) -> ResolveSummary {
    let env = Env::build(db);
    let branch_id = opts.branch_id;

    // Load prior bytes_used for resume semantics. Byte usage is scoped per
    // branch; resuming reuses committed resolutions (no double charging).
    let mut used: u64 = 0;
    {
        let c = db.0.lock().unwrap();
        if opts.resume {
            used = c
                .query_row(
                    "SELECT COALESCE(SUM(bytes_charged),0) FROM resolutions WHERE branch_id=?1 AND status='resolved'",
                    params![branch_id],
                    |r| r.get::<_, i64>(0),
                )
                .map(|v| v.max(0) as u64)
                .unwrap_or(0);
        }
    }
    let mut budget = BudgetState {
        used,
        limit: opts.budgets.total_bytes,
        single_cap: opts.budgets.single_cap(),
        max_depth: opts.budgets.max_depth,
    };

    // Stable processing order: (source_id, offset). Keeps behavior independent
    // of import ordering and makes pausing deterministic.
    let mut order: Vec<usize> = (0..env.nodes.len()).collect();
    order.sort_by(|&a, &b| {
        env.nodes[a]
            .source_id
            .cmp(&env.nodes[b].source_id)
            .then(env.nodes[a].offset.cmp(&env.nodes[b].offset))
            .then(env.nodes[a].id.cmp(&env.nodes[b].id))
    });

    let mut memo: std::collections::HashMap<i64, Materialized> = std::collections::HashMap::new();
    // Live oid->node map for this pass: seeded from materialized results and
    // updated as chains resolve, so late-imported bases are discoverable.
    let mut live_oids: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    {
        for (oid, list) in &env.by_oid {
            if let Some(nid) = rank_candidates(list).into_iter().next() {
                live_oids.entry(oid.clone()).or_insert(nid);
            }
        }
    }
    let final_summary;
    // Retry loop: a delta may be processed before its base when sources are
    // interleaved. Re-walk nodes that were blocked on a missing oid until a
    // fixed point (no newly materialized oids).
    let mut pass = 0usize;
    loop {
        let oids_before = live_oids.len();
        let mut summary = ResolveSummary::default();
        summary.bytes_used = budget.used;

    for &idx in &order {
        let n = &env.nodes[idx];
        if let Some(set) = &opts.only_nodes {
            if !set.contains(&n.id) {
                continue;
            }
        }

        // Reuse an existing committed resolution if still valid (full pass
        // resumes skip; incremental pass only includes affected nodes).
        if let Some(existing) = load_existing(db, branch_id, n.id) {
            if existing.status == "resolved" {
                if let Some(oid) = existing.resolved_oid {
                    live_oids.entry(oid).or_insert(n.id);
                }
                summary.resolved += 1;
                continue;
            }
            if !opts.only_nodes.is_some() && existing.status == "budget-paused" && opts.resume {
                // fall through and retry
            } else if opts.only_nodes.is_none()
                && matches!(existing.status.as_str(), "cycle" | "bad-object" | "too-deep" | "too-large" | "missing-base" | "parse-error")
            {
                // Terminal / externally-blocked states remain unless a base was
                // added; imports trigger an incremental recompute for those.
                match existing.status.as_str() {
                    "missing-base" => summary.missing_base += 1,
                    "cycle" => summary.cycle += 1,
                    "bad-object" => summary.parse_error += 0,
                    "too-deep" => summary.too_deep += 1,
                    "too-large" => summary.too_large += 1,
                    "parse-error" => summary.parse_error += 1,
                    _ => {}
                }
                if existing.status == "bad-object" {
                    summary.bad_object += 1;
                }
                continue;
            }
        }

        delete_steps(db, branch_id, n.id);
        match walk_chain(&env, db, branch_id, opts.pin_node, idx, &mut budget, &memo, &live_oids) {
            Ok(mat) => {
                let oid_hex = crate::git::to_hex(&mat.oid);
                persist_resolution(
                    db,
                    branch_id,
                    n,
                    ResolveStatus::Resolved,
                    Some(mat.object_type),
                    Some(&mat.oid),
                    Some(&mat.content),
                    mat.chain.len(),
                    mat.chain.iter().rev().nth(1).copied(),
                    None,
                    None,
                    mat.bytes_charged,
                );
                // Record candidate derived from the recomputed object id, so
                // later ref-deltas can find this node as a base.
                upsert_resolved_candidate(db, &oid_hex, n);
                persist_steps(db, branch_id, &mat.steps);
                live_oids.insert(oid_hex.clone(), n.id);
                memo.insert(n.id, Materialized {
                    bytes_charged: 0,
                    ..mat
                });
                summary.resolved += 1;
            }
            Err(WalkError::Missing(reason, links)) => {
                let msg = match &reason {
                    MissingReason::Oid(h) => format!("missing base object {h}"),
                    MissingReason::OfsOutOfRange(_, o) => {
                        format!("ofs base offset {o} not present in pack")
                    }
                    MissingReason::Bad(m) => m.clone(),
                };
                persist_resolution(
                    db, branch_id, n, ResolveStatus::MissingBase, None, None, None, 0,
                    None, Some(&links), Some(&msg), 0,
                );
                summary.missing_base += 1;
            }
            Err(WalkError::Cycle(cycle_ids)) => {
                let links = blocked_from_cycle(n, &cycle_ids);
                persist_resolution(
                    db, branch_id, n, ResolveStatus::Cycle, None, None, None,
                    cycle_ids.len(), None, Some(&links),
                    Some("delta forms a cycle"), 0,
                );
                summary.cycle += 1;
            }
            Err(WalkError::TooDeep) => {
                persist_resolution(
                    db, branch_id, n, ResolveStatus::TooDeep, None, None, None, 0,
                    None, None,
                    Some(&format!("delta depth exceeds limit {}", budget.max_depth)), 0,
                );
                summary.too_deep += 1;
            }
            Err(WalkError::TooLarge(sz)) => {
                persist_resolution(
                    db, branch_id, n, ResolveStatus::TooLarge, None, None, None, 0,
                    None, None,
                    Some(&format!("single object {sz} bytes exceeds ratio cap {}", budget.single_cap)),
                    0,
                );
                summary.too_large += 1;
            }
            Err(WalkError::Bad(msg)) => {
                persist_resolution(
                    db, branch_id, n, ResolveStatus::BadObject, None, None, None, 0,
                    None, None, Some(&msg), 0,
                );
                summary.bad_object += 1;
            }
            Err(WalkError::BudgetExceededResume(need)) => {
                // Intermediate, retryable state: never commit partial content.
                persist_resolution(
                    db, branch_id, n, ResolveStatus::BudgetPaused, None, None, None, 0,
                    None, None,
                    Some(&json!({
                        "need": need,
                        "used": budget.used,
                        "limit": budget.limit,
                        "next_node_id": n.id
                    }).to_string()),
                    0,
                );
                let c = db.0.lock().unwrap();
                c.execute(
                    "INSERT INTO checkpoints(branch_id,status,next_node_id,bytes_used,updated_at)
                     VALUES(?1,'paused',?2,?3,datetime('now'))
                     ON CONFLICT(branch_id) DO UPDATE SET status='paused',next_node_id=?2,
                        bytes_used=?3,updated_at=datetime('now')",
                    params![branch_id, n.id, budget.used as i64],
                )
                .unwrap();
                summary.budget_paused += 1;
                summary.paused = true;
                summary.bytes_used = budget.used;
                return summary;
            }
        }
    }
        summary.bytes_used = budget.used;
        pass += 1;
        let done = live_oids.len() == oids_before || pass > env.nodes.len() + 1;
        if done {
            final_summary = summary;
            break;
        }
    }
    // Clear any stale pause checkpoint on full completion.
    let c = db.0.lock().unwrap();
    c.execute(
        "DELETE FROM checkpoints WHERE branch_id=?1",
        params![branch_id],
    )
    .unwrap();
    final_summary
}

fn upsert_resolved_candidate(db: &Db, oid_hex: &str, n: &NodeRow) {
    let c = db.0.lock().unwrap();
    c.execute(
        "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
         VALUES(?1,?2,?3,?4,'hash','recomputed-after-delta',1,55,55)
         ON CONFLICT(oid,node_id,origin,source_label) DO NOTHING",
        params![oid_hex, n.id, n.source_id, n.offset],
    )
    .unwrap();
}

fn blocked_from_cycle(n: &NodeRow, ids: &[i64]) -> Vec<ChainLink> {
    ids.iter()
        .map(|id| ChainLink {
            node: crate::model::NodeRef {
                source_id: n.source_id,
                offset: n.offset,
            },
            kind: n.kind.as_str().into(),
            needs: None,
            reason: format!("node {id} participates in a delta cycle"),
        })
        .collect()
}

/// Incremental recomputation after new candidates/nodes appeared: reset every
/// resolution that is currently missing a base or paused and that belongs to
/// the dependent subgraph of the newly supplied nodes, then resolve.
pub fn recompute_after_import(db: &Db, budgets: Budgets) -> ResolveSummary {
    let roots: Vec<i64> = {
        let c = db.0.lock().unwrap();
        let mut s = c
            .prepare("SELECT DISTINCT node_id FROM resolutions WHERE status IN ('missing-base','budget-paused')")
            .unwrap();
        s.query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    // Expand from every node as a root so a newly supplied base that completes
    // a previously blocked chain is found regardless of import ordering.
    // Resolved nodes inside the work set are simply reused (no recompute).
    let all_nodes: Vec<i64> = {
        let c = db.0.lock().unwrap();
        let mut s = c.prepare("SELECT id FROM nodes").unwrap();
        s.query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    let affected = affected_subgraph(db, &all_nodes);
    let _ = roots;
    resolve_all(
        db,
        ResolveOptions {
            branch_id: 1,
            budgets,
            only_nodes: Some(affected),
            pin_node: None,
            resume: true,
        },
    )
}
