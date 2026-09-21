//! Delta-DAG resolution with budgets, isolation and retryable pauses.

use std::collections::HashMap;

use rusqlite::params;
use serde::Serialize;

use crate::analyze::blocking::blocking_chain;
use crate::analyze::graph::{CandidateNode, Graph};
use crate::git::delta::{apply_delta, DeltaCommand};
use crate::git::{git_oid, GitType};
use crate::store::{now_ts, Budget, Store, DEFAULT_BRANCH};

/// Final state of one analysis run.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub run_id: i64,
    pub status: String,
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub depth_used: u32,
    pub bytes_used: u64,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    Resolved,
    Failed,
    Paused,
}

#[derive(Clone)]
struct ResolvedNode {
    oid: String,
    candidate_id: i64,
    kind: GitType,
    content: Vec<u8>,
    depth: u32,
    oid_ok: bool,
}

struct DeltaStepRec {
    oid: String,
    step: u32,
    child_candidate_id: i64,
    base_candidate_id: Option<i64>,
    base_oid: Option<String>,
    commands: Vec<DeltaCommand>,
    input_len: u64,
    output_len: u64,
    verify: String,
}

struct RunAcc {
    state: HashMap<i64, NodeState>,
    resolved: HashMap<i64, ResolvedNode>,
    /// computed oid -> candidate id of a resolved object, so chains that
    /// reach an object through different candidate nodes share the result.
    resolved_by_oid: HashMap<String, i64>,
    reason: HashMap<i64, String>,
    steps: Vec<DeltaStepRec>,
    evidence: Vec<(Option<String>, String)>,
    bytes_used: u64,
    depth_used: u32,
    paused: bool,
}

impl RunAcc {
    fn new() -> Self {
        RunAcc {
            state: HashMap::new(),
            resolved: HashMap::new(),
            resolved_by_oid: HashMap::new(),
            reason: HashMap::new(),
            steps: Vec::new(),
            evidence: Vec::new(),
            bytes_used: 0,
            depth_used: 0,
            paused: false,
        }
    }
}

/// Run analysis for a branch. `resume_run_id` references a previous paused
/// run; a fresh run row is always created with the new budget.
pub fn analyze_branch(
    store: &Store,
    branch: &str,
    budget: Budget,
    resume_run_id: Option<i64>,
) -> anyhow::Result<RunSummary> {
    {
        let conn = store.db.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO branches(name, created_at) VALUES (?1, ?2)",
            params![branch, now_ts()],
        )?;
    }
    let graph = store.load_graph(branch)?;
    let mut acc = RunAcc::new();
    let mut messages: Vec<String> = Vec::new();
    if let Some(prev) = resume_run_id {
        messages.push(format!("resuming after paused run #{prev} with fresh budget"));
    }

    // Root set: one candidate per oid bucket (pinned choice wins), plus
    // every oid-less delta node (ofs-deltas that are not named by an idx).
    // Resolved targets dedupe by computed oid when a chain reaches one.
    let mut roots: Vec<i64> = graph
        .by_oid
        .values()
        .filter_map(|bucket| bucket.first().copied())
        .collect();
    for (id, node) in graph.nodes.iter() {
        if node.oid.is_empty() && !roots.contains(id) {
            roots.push(*id);
        }
    }
    roots.sort_by_key(|id| {
        let n = &graph.nodes[id];
        (n.source_id, n.offset, n.id)
    });
    // Process bases before deltas; the resolver memoizes, so this just makes
    // budget pausing deterministic and independent of import order.
    roots.sort_by_key(|id| {
        let n = &graph.nodes[id];
        let is_delta = matches!(n.kind_name.as_str(), "ofs-delta" | "ref-delta");
        (is_delta, n.source_id, n.offset, n.id)
    });

    for root in &roots {
        let mut stack: Vec<i64> = Vec::new();
        resolve_node(
            store,
            &graph,
            &mut acc,
            *root,
            &mut stack,
            budget,
            0,
            branch,
        );
        if acc.paused {
            break;
        }
    }

    let status = if acc.paused {
        "paused"
    } else if acc.state.values().any(|s| *s == NodeState::Failed) {
        "failed"
    } else {
        "complete"
    };

    let run_id = flush_run(store, branch, budget, &acc, status, &messages)?;

    let resolved = acc.resolved.len();
    let blocked = acc.state.values().filter(|s| **s == NodeState::Failed).count();
    let paused_count = acc.state.values().filter(|s| **s == NodeState::Paused).count();
    Ok(RunSummary {
        run_id,
        status: status.to_string(),
        resolved,
        blocked,
        paused: paused_count,
        depth_used: acc.depth_used,
        bytes_used: acc.bytes_used,
        messages,
    })
}

fn mark(
    acc: &mut RunAcc,
    id: i64,
    state: NodeState,
    reason: String,
    oid: Option<String>,
) {
    acc.state.insert(id, state);
    acc.reason.insert(id, reason.clone());
    acc.evidence.push((oid, reason));
}

fn resolve_node(
    store: &Store,
    graph: &Graph,
    acc: &mut RunAcc,
    id: i64,
    stack: &mut Vec<i64>,
    budget: Budget,
    depth: u32,
    branch: &str,
) {
    if let Some(state) = acc.state.get(&id).copied() {
        if state == NodeState::Paused {
            acc.paused = true;
        }
        return;
    }
    if stack.contains(&id) {
        let cycle: Vec<String> = stack
            .iter()
            .chain(std::iter::once(&id))
            .map(|cid| describe(graph, *cid))
            .collect();
        for cid in stack.iter().chain(std::iter::once(&id)) {
            if !acc.state.contains_key(cid) {
                mark(
                    acc,
                    *cid,
                    NodeState::Failed,
                    format!("delta cycle: {}", cycle.join(" -> ")),
                    graph.nodes.get(cid).and_then(|n| oid_of(n)),
                );
            }
        }
        return;
    }

    let node = match graph.nodes.get(&id) {
        Some(n) => n.clone(),
        None => return,
    };

    // Precondition: parse-level corruption (bad CRC, spoofed inflated size,
    // bad header, unparseable entry) isolates this object permanently.
    if let Some(err) = &node.parse_error {
        mark(
            acc,
            id,
            NodeState::Failed,
            format!("{}: {err}", describe(graph, id)),
            oid_of(&node),
        );
        return;
    }

    // Depth budget is a retryable pause, not corruption.
    if depth >= budget.max_depth {
        acc.paused = true;
        mark(
            acc,
            id,
            NodeState::Paused,
            format!(
                "{}: depth budget exhausted at depth {depth}",
                describe(graph, id)
            ),
            oid_of(&node),
        );
        return;
    }

    // Pre-inflate budget checks for base objects. The inflated length is
    // already known from the import scan (pack header / loose envelope), so
    // a pause or ratio failure is decided *before* spending any bytes.
    let looks_like_base = matches!(
        node.kind_name.as_str(),
        "commit" | "tree" | "blob" | "tag"
    );
    if looks_like_base {
        if node.inflate_size as u64 > budget.max_single_bytes {
            mark(
                acc,
                id,
                NodeState::Failed,
                format!(
                    "single object {} bytes exceeds per-object ratio cap {}",
                    node.inflate_size, budget.max_single_bytes
                ),
                oid_of(&node),
            );
            return;
        }
        if acc.bytes_used + node.inflate_size as u64 > budget.max_expand_bytes {
            acc.paused = true;
            mark(
                acc,
                id,
                NodeState::Paused,
                format!(
                    "total expansion budget {} exhausted (need {} more) before inflation",
                    budget.max_expand_bytes, node.inflate_size
                ),
                oid_of(&node),
            );
            return;
        }
    }

    let (kind, payload) = match store.candidate_payload(&node) {
        Ok(v) => v,
        Err(e) => {
            mark(acc, id, NodeState::Failed, format!("inflate failure: {e}"), oid_of(&node));
            return;
        }
    };

    // Base objects: verify oid, charge their size to the expansion budget.
    if kind.is_base() {
        if acc.bytes_used + payload.len() as u64 > budget.max_expand_bytes {
            acc.paused = true;
            mark(
                acc,
                id,
                NodeState::Paused,
                format!(
                    "total expansion budget {} exhausted at {} bytes",
                    budget.max_expand_bytes, acc.bytes_used
                ),
                oid_of(&node),
            );
            return;
        }
        if payload.len() as u64 > budget.max_single_bytes {
            mark(
                acc,
                id,
                NodeState::Failed,
                format!(
                    "single object {} bytes exceeds per-object ratio cap {}",
                    payload.len(),
                    budget.max_single_bytes
                ),
                oid_of(&node),
            );
            return;
        }
        let computed = git_oid(kind, &payload);
        let oid_ok = node.oid.is_empty() || node.oid == computed;
        let oid = if node.oid.is_empty() { computed.clone() } else { node.oid.clone() };
        if !oid_ok {
            acc.evidence.push((
                Some(oid.clone()),
                format!(
                    "oid mismatch for {}: candidate claims {oid}, content is {computed}",
                    describe(graph, id)
                ),
            ));
        }
        acc.bytes_used += payload.len() as u64;
        acc.depth_used = acc.depth_used.max(depth);
        acc.state.insert(id, NodeState::Resolved);
        acc.resolved_by_oid.entry(oid.clone()).or_insert(id);
        acc.resolved.insert(
            id,
            ResolvedNode {
                oid,
                candidate_id: id,
                kind,
                content: payload,
                depth,
                oid_ok,
            },
        );
        return;
    }

    // Resolve the base first (ofs inside same pack, ref by oid anywhere).
    stack.push(id);
    let mut base_node = match resolve_base(graph, &node) {
        Ok(b) => Some(b),
        Err(reason) => {
            // A ref-delta base may already have been reconstructed through a
            // different candidate node (e.g. reached via an ofs chain).
            let via_oid = node
                .base_ref
                .as_ref()
                .and_then(|oid| acc.resolved_by_oid.get(oid).copied());
            match via_oid {
                Some(b) => Some(b),
                None => {
                    stack.pop();
                    mark(acc, id, NodeState::Failed, reason, oid_of(&node));
                    return;
                }
            }
        }
    };
    let base_node = base_node.unwrap();
    // If the nominal base node is unresolved but the same oid was produced
    // by another candidate, adopt that resolved node instead.
    let base_node = match (acc.state.get(&base_node).copied(), &node.base_ref) {
        (Some(NodeState::Resolved), _) => base_node,
        (_, Some(oid)) => acc.resolved_by_oid.get(oid).copied().unwrap_or(base_node),
        _ => base_node,
    };
    resolve_node(store, graph, acc, base_node, stack, budget, depth + 1, branch);
    stack.pop();

    match acc.state.get(&base_node).copied() {
        Some(NodeState::Resolved) => {}
        Some(NodeState::Paused) => {
            acc.paused = true;
            mark(
                acc,
                id,
                NodeState::Paused,
                format!(
                    "{}: paused waiting for base {}",
                    describe(graph, id),
                    describe(graph, base_node)
                ),
                oid_of(&node),
            );
            return;
        }
        _ => {
            let chain = blocking_chain(graph, id);
            mark(
                acc,
                id,
                NodeState::Failed,
                format!(
                    "{}: base {} unresolved; blocking chain: {}",
                    describe(graph, id),
                    describe(graph, base_node),
                    chain
                ),
                oid_of(&node),
            );
            return;
        }
    }
    if acc.paused {
        mark(
            acc,
            id,
            NodeState::Paused,
            format!("{}: paused mid-chain", describe(graph, id)),
            oid_of(&node),
        );
        return;
    }

    let base = acc.resolved.get(&base_node).cloned().unwrap();

    // Single-object cap: read declared result size before allocating, and
    // reject a spoofed base size without touching the expansion budget.
    let (declared_base, declared) =
        match crate::git::delta::declared_sizes(&payload) {
            Ok(v) => v,
            Err(e) => {
                mark(
                    acc,
                    id,
                    NodeState::Failed,
                    format!("{}: delta invalid: {e}", describe(graph, id)),
                    oid_of(&node),
                );
                return;
            }
        };
    if declared_base != base.content.len() as u64 {
        mark(
            acc,
            id,
            NodeState::Failed,
            format!(
                "{}: size spoof: delta header claims base {declared_base}, base is {} bytes",
                describe(graph, id),
                base.content.len()
            ),
            oid_of(&node),
        );
        return;
    }
    if declared > budget.max_single_bytes {
        mark(
            acc,
            id,
            NodeState::Failed,
            format!(
                "delta result {declared} bytes exceeds per-object cap {}",
                budget.max_single_bytes
            ),
            oid_of(&node),
        );
        return;
    }
    if acc.bytes_used + declared > budget.max_expand_bytes {
        acc.paused = true;
        mark(
            acc,
            id,
            NodeState::Paused,
            format!(
                "total expansion budget {} exhausted (need {declared} more)",
                budget.max_expand_bytes
            ),
            oid_of(&node),
        );
        return;
    }

    let outcome = match apply_delta(&base.content, &payload, budget.max_single_bytes) {
        Ok(o) => o,
        Err(e) => {
            mark(
                acc,
                id,
                NodeState::Failed,
                format!("{}: {e}", describe(graph, id)),
                oid_of(&node),
            );
            return;
        }
    };

    // Result type equals the base object's real type.
    let computed = git_oid(base.kind, &outcome.output);
    let oid_ok = node.oid.is_empty() || node.oid == computed;
    let oid = if node.oid.is_empty() { computed.clone() } else { node.oid.clone() };
    if !oid_ok {
        acc.evidence.push((
            Some(oid.clone()),
            format!(
                "oid mismatch for {}: index names {oid}, reconstruction is {computed}",
                describe(graph, id)
            ),
        ));
    }

    acc.steps.push(DeltaStepRec {
        oid: oid.clone(),
        step: depth,
        child_candidate_id: id,
        base_candidate_id: Some(base_node),
        base_oid: Some(base.oid.clone()),
        commands: outcome.commands,
        input_len: outcome.base_len,
        output_len: outcome.declared_result_len,
        verify: if oid_ok { "ok".to_string() } else { "oid-mismatch".to_string() },
    });

    acc.bytes_used += outcome.output.len() as u64;
    acc.depth_used = acc.depth_used.max(depth + 1);
    acc.state.insert(id, NodeState::Resolved);
    acc.resolved_by_oid.entry(oid.clone()).or_insert(id);
    acc.resolved.insert(
        id,
        ResolvedNode {
            oid,
            candidate_id: id,
            kind: base.kind,
            content: outcome.output,
            depth: depth + 1,
            oid_ok,
        },
    );
}

fn resolve_base(graph: &Graph, node: &CandidateNode) -> Result<i64, String> {
    if let Some(offset) = node.base_offset {
        let key = (node.source_id, offset);
        return graph
            .by_pack_offset
            .get(&key)
            .copied()
            .ok_or_else(|| {
                format!(
                    "missing external ofs-delta base at pack offset {offset} (source {})",
                    node.source_id
                )
            });
    }
    if let Some(oid) = &node.base_ref {
        return graph
            .best_for(oid)
            .map(|n| n.id)
            .ok_or_else(|| format!("missing external ref-delta base {oid}"));
    }
    Err(format!("{} has no base reference", node.locator))
}

fn oid_of(node: &CandidateNode) -> Option<String> {
    if node.oid.is_empty() { None } else { Some(node.oid.clone()) }
}

fn describe(graph: &Graph, id: i64) -> String {
    match graph.nodes.get(&id) {
        Some(n) => format!("{}@{}", n.kind_name, n.locator),
        None => format!("candidate#{id}"),
    }
}

/// Persist one run. Paused runs record only run/evidence rows: no partial
/// object is ever advertised as a complete reconstruction.
fn flush_run(
    store: &Store,
    branch: &str,
    budget: Budget,
    acc: &RunAcc,
    status: &str,
    messages: &[String],
) -> anyhow::Result<i64> {
    let mut conn = store.db.lock().unwrap();
    let tx = conn.transaction()?;

    let mut summary = messages.join("; ");
    if acc.paused {
        summary.push_str(&format!(
            " | paused: expand {}/{} bytes, depth {}",
            acc.bytes_used, budget.max_expand_bytes, acc.depth_used
        ));
    } else {
        summary.push_str(&format!(
            " | resolved={} failed={} expand {} bytes depth {}",
            acc.resolved.len(),
            acc.state.values().filter(|s| **s == NodeState::Failed).count(),
            acc.bytes_used,
            acc.depth_used
        ));
    }

    tx.execute(
        "INSERT INTO runs(branch, status, budget, depth_used, bytes_used, summary, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            branch,
            status,
            serde_json::to_string(&budget).unwrap_or_default(),
            acc.depth_used as i64,
            acc.bytes_used as i64,
            summary,
            now_ts()
        ],
    )?;
    let run_id = tx.last_insert_rowid();

    for (oid, message) in &acc.evidence {
        let level = if message.contains("cycle")
            || message.contains("mismatch")
            || message.contains("spoof")
            || message.contains("error")
            || message.contains("missing")
            || message.contains("invalid")
        {
            "error"
        } else {
            "warn"
        };
        tx.execute(
            "INSERT INTO evidence(run_id, oid, level, message) VALUES (?1,?2,?3,?4)",
            params![run_id, oid, level, message],
        )?;
    }

    if status != "paused" {
        for node in acc.resolved.values() {
            tx.execute(
                "INSERT INTO resolved(run_id, branch, oid, candidate_id, kind_name,
                     depth, content_len, oid_ok, content)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    run_id,
                    branch,
                    node.oid,
                    node.candidate_id,
                    node.kind.name(),
                    node.depth as i64,
                    node.content.len() as i64,
                    node.oid_ok as i64,
                    node.content
                ],
            )?;
        }
        for step in &acc.steps {
            let first = step.commands.first();
            let last = step.commands.last();
            for (seq, cmd) in step.commands.iter().enumerate() {
                tx.execute(
                    "INSERT INTO delta_commands(run_id, oid, step, seq, kind,
                         cmd_start, cmd_end, src_offset, src_len, out_offset, out_len)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        run_id, step.oid, step.step as i64, seq as i64, cmd.kind,
                        cmd.start as i64, cmd.end as i64,
                        cmd.src_offset as i64, cmd.src_len as i64,
                        cmd.out_offset as i64, cmd.out_len as i64
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO delta_steps(run_id, oid, step, child_candidate_id,
                     base_candidate_id, base_oid, cmd_start, cmd_end, cmd_count,
                     input_len, output_len, verify)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    run_id,
                    step.oid,
                    step.step as i64,
                    step.child_candidate_id,
                    step.base_candidate_id,
                    step.base_oid,
                    first.map(|c| c.start as i64).unwrap_or(0),
                    last.map(|c| c.end as i64).unwrap_or(0),
                    step.commands.len() as i64,
                    step.input_len as i64,
                    step.output_len as i64,
                    step.verify
                ],
            )?;
        }
    }

    tx.commit()?;
    Ok(run_id)
}
