//! The resolution engine.
//!
//! Candidates (pack entries / loose objects) form a delta DAG which may in
//! practice contain cycles, dangling bases, corrupt payloads and duplicate
//! oids.  The engine resolves everything it can, isolates every broken
//! object, records per-instruction delta evidence, and pauses into a
//! *retryable* intermediate state when a resource budget is hit.
//!
//! All scheduling is deterministic: import order never changes the ordering
//! of candidates when choosing a base or presenting conflicts.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{params, Connection};

use crate::delta::{self, ApplyOutcome, Budgets, Checkpoint, DeltaError, Pause, StepKind};
use crate::gitid::{git_object_id, to_hex};
use crate::store::Store;
use crate::types::GitType;

/// Resolution status of one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Resolved,
    Blocked,
    Paused,
    Cycle,
    Error,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::Blocked => "blocked",
            Status::Paused => "paused",
            Status::Cycle => "cycle",
            Status::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CandidateNode {
    pub id: i64,
    pub source_id: i64,
    pub source_filename: String,
    pub imported_at: i64,
    pub kind: GitType,
    pub oid_hex: Option<String>,
    pub offset: Option<i64>,
    pub declared_size: i64,
    pub actual_size: i64,
    pub crc_idx: Option<u32>,
    pub crc_actual: Option<u32>,
    pub parse_error: Option<String>,
    pub base_ref_hex: Option<String>,
    pub base_offset: Option<i64>,
    pub raw_payload: Option<Vec<u8>>,
    /// Resolved base candidate id chosen during this analysis.
    pub base_id: Option<i64>,
    pub pinned: bool,
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub total_candidates: usize,
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub cycle: usize,
    pub error: usize,
    pub total_bytes_used: u64,
    pub budget: Budgets,
    pub paused_reasons: Vec<(i64, String)>,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub budgets: Budgets,
    /// If true, keep resolving independent objects after a budget pause
    /// (global budget pauses still stop the rest once exhausted).
    pub continue_after_pause: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            budgets: Budgets::test_defaults(),
            continue_after_pause: true,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedObject {
    oid_hex: String,
    kind: GitType,
    content: Vec<u8>,
}

#[derive(Debug, Clone)]
enum Memo {
    Done(ResolvedObject),
    Failed(Status, String),
    /// Budget pause; can be retried.
    PausedAt(Pause, Vec<u8>, usize, i64),
}

/// Load every candidate and join the data needed to schedule resolution.
fn load_graph(conn: &Connection) -> rusqlite::Result<BTreeMap<i64, CandidateNode>> {
    let mut nodes = BTreeMap::new();
    let mut q = conn.prepare(
        "SELECT c.id, c.source_id, s.filename, s.imported_at, c.kind, c.oid_hex,
                c.offset, c.declared_size, c.actual_size, c.crc_idx, c.crc_actual,
                c.parse_error, c.base_ref_hex, c.base_offset, b.content,
                EXISTS(SELECT 1 FROM pins p WHERE p.oid_hex IS c.oid_hex
                       AND p.source_id = c.source_id) AS pinned
         FROM candidates c
         JOIN sources s ON s.id = c.source_id
         LEFT JOIN blobs b ON b.candidate_id = c.id AND b.role='raw'
         ORDER BY c.id",
    )?;
    let rows = q.query_map([], |r| {
        let kind_str: String = r.get(4)?;
        let kind = parse_kind(&kind_str);
        let raw: Option<Vec<u8>> = r.get(14)?;
        Ok(CandidateNode {
            id: r.get(0)?,
            source_id: r.get(1)?,
            source_filename: r.get(2)?,
            imported_at: r.get(3)?,
            kind,
            oid_hex: r.get(5)?,
            offset: r.get(6)?,
            declared_size: r.get(7)?,
            actual_size: r.get(8)?,
            crc_idx: r.get::<_, Option<i64>>(9)?.map(|v| v as u32),
            crc_actual: r.get::<_, Option<i64>>(10)?.map(|v| v as u32),
            parse_error: r.get(11)?,
            base_ref_hex: r.get(12)?,
            base_offset: r.get(13)?,
            raw_payload: raw,
            base_id: None,
            pinned: r.get::<_, i64>(15)? != 0,
        })
    })?;
    for row in rows {
        let node = row?;
        nodes.insert(node.id, node);
    }
    Ok(nodes)
}

fn parse_kind(s: &str) -> GitType {
    match s {
        "commit" => GitType::Commit,
        "tree" => GitType::Tree,
        "blob" => GitType::Blob,
        "tag" => GitType::Tag,
        "ofs-delta" => GitType::OfsDelta,
        "ref-delta" => GitType::RefDelta,
        other => panic!("unknown stored kind {other}"),
    }
}

/// A single resolution call: resolve everything (or the provided subgraph).
pub struct Engine<'a> {
    store: &'a Store,
    opts: RunOptions,
    nodes: BTreeMap<i64, CandidateNode>,
    memo: HashMap<i64, Memo>,
    /// Steps discovered during this call, grouped by candidate id.
    steps: HashMap<i64, Vec<delta::DeltaStep>>,
    edges: Vec<(i64, Option<i64>, String, Option<i64>, Option<String>)>,
    total_used: u64,
    /// Bytes newly produced per candidate on this run (for accounting).
    charged: HashMap<i64, u64>,
    pause_reasons: Vec<(i64, String)>,
}

impl<'a> Engine<'a> {
    pub fn new(store: &'a Store, opts: RunOptions) -> rusqlite::Result<Self> {
        let conn = store.conn.lock().unwrap();
        let nodes = load_graph(&conn)?;
        Ok(Engine {
            store,
            opts,
            nodes,
            memo: HashMap::new(),
            steps: HashMap::new(),
            edges: Vec::new(),
            total_used: 0,
            charged: HashMap::new(),
            pause_reasons: Vec::new(),
        })
    }

    /// Candidate ordering used for *all* deterministic tie-breaks:
    /// pinned source first, then earlier import, then source id, then offset,
    /// then candidate id — deliberately independent of import-side effects.
    fn candidate_rank(&self, cid: i64) -> (u8, i64, i64, i64, i64) {
        let n = &self.nodes[&cid];
        (
            if n.pinned { 0 } else { 1 },
            n.imported_at,
            n.source_id,
            n.offset.unwrap_or(i64::MAX),
            n.id,
        )
    }

    fn find_ofs_base(&self, source_id: i64, base_offset: i64) -> Option<i64> {
        let mut best: Option<i64> = None;
        for (cid, n) in &self.nodes {
            if n.source_id != source_id || n.offset != Some(base_offset) {
                continue;
            }
            best = Some(match best {
                None => *cid,
                Some(cur) => {
                    if self.candidate_rank(*cid) < self.candidate_rank(cur) {
                        *cid
                    } else {
                        cur
                    }
                }
            });
        }
        best
    }

    fn find_ref_bases(&self, oid_hex: &str) -> Vec<i64> {
        let mut ids: Vec<i64> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.oid_hex.as_deref() == Some(oid_hex))
            .map(|(cid, _)| *cid)
            .collect();
        ids.sort_by_key(|cid| self.candidate_rank(*cid));
        ids
    }

    /// Pick the base for a delta candidate, recording the edge.
    fn choose_base(&mut self, cid: i64) -> Result<i64, (Status, String)> {
        let (base_kind, base_offset, base_ref) = {
            let n = &self.nodes[&cid];
            (
                if n.kind == GitType::OfsDelta { "ofs" } else { "ref" },
                n.base_offset,
                n.base_ref_hex.clone(),
            )
        };
        let chosen = if base_kind == "ofs" {
            let n = &self.nodes[&cid];
            n.base_offset
                .and_then(|off| self.find_ofs_base(n.source_id, off))
        } else {
            self.find_ref_bases(base_ref.as_deref().unwrap_or(""))
                .into_iter()
                .next()
        };

        match chosen {
            Some(b) => {
                self.edges.push((cid, Some(b), base_kind.into(), base_offset, base_ref));
                self.nodes.get_mut(&cid).unwrap().base_id = Some(b);
                Ok(b)
            }
            None => {
                self.edges.push((cid, None, base_kind.into(), base_offset, base_ref.clone()));
                let msg = if base_kind == "ofs" {
                    format!("ofs-delta base at offset {} not found in this pack",
                        base_offset.unwrap_or(-1))
                } else {
                    format!("external base {} not imported", base_ref.unwrap_or_default())
                };
                Err((Status::Blocked, msg))
            }
        }
    }

    /// Depth-first resolution with cycle detection.
    fn resolve(&mut self, cid: i64, depth: usize, stack: &mut Vec<i64>) -> Memo {
        if let Some(m) = self.memo.get(&cid) {
            return m.clone();
        }
        if stack.contains(&cid) {
            let chain = std::iter::once(cid)
                .chain(stack.iter().rev().copied().take_while(|x| *x != cid))
                .collect::<Vec<_>>();
            let mut ids = chain;
            ids.push(cid);
            let names: Vec<String> = ids
                .iter()
                .map(|id| self.describe_candidate(*id))
                .collect();
            return Memo::Failed(Status::Cycle, format!("delta cycle: {}", names.join(" -> ")));
        }
        let node = self.nodes[&cid].clone();

        // Already broken at parse time.
        if node.parse_error.is_some() {
            return Memo::Failed(Status::Error, node.parse_error.clone().unwrap());
        }

        match node.kind {
            GitType::Commit | GitType::Tree | GitType::Blob | GitType::Tag => {
                self.resolve_base(cid, &node)
            }
            GitType::OfsDelta | GitType::RefDelta => {
                if depth + 1 > self.opts.budgets.max_depth {
                    let reason = delta::PauseReason::DepthExceeded {
                        depth: depth + 1,
                        limit: self.opts.budgets.max_depth,
                    };
                    return Memo::Failed(Status::Paused, reason.to_string());
                }
                let base = match self.choose_base(cid) {
                    Ok(b) => b,
                    Err((status, msg)) => return Memo::Failed(status, msg),
                };
                stack.push(cid);
                let base_memo = self.resolve(base, depth + 1, stack);
                stack.pop();
                match base_memo {
                    Memo::Done(obj) => self.apply_one_delta(cid, &node, &obj, depth),
                    Memo::Failed(status, msg) => Memo::Failed(status, format!(
                        "base {} cannot resolve: {msg}", self.describe_candidate(base))),
                    Memo::PausedAt(..) => Memo::Failed(
                        Status::Paused,
                        format!("base {} is paused at budget", self.describe_candidate(base)),
                    ),
                }
            }
        }
    }

    fn describe_candidate(&self, cid: i64) -> String {
        let n = &self.nodes[&cid];
        match (n.oid_hex.as_deref(), n.offset) {
            (Some(o), Some(off)) => format!("{}@{}", &o[..12.min(o.len())], off),
            (Some(o), None) => o[..12.min(o.len())].to_string(),
            (None, Some(off)) => format!("{}@{}", n.kind.label(), off),
            (None, None) => n.kind.label().to_string(),
        }
    }

    fn resolve_base(&mut self, cid: i64, node: &CandidateNode) -> Memo {
        let Some(content) = node.raw_payload.clone() else {
            return Memo::Failed(
                Status::Error,
                "base entry has no inflatable payload".into(),
            );
        };
        let computed = git_object_id(node.kind, &content);
        let computed_hex = to_hex(&computed);
        if let Some(declared) = &node.oid_hex {
            if declared != &computed_hex {
                return Memo::Failed(
                    Status::Error,
                    format!(
                        "object id mismatch: idx names {declared}, content hashes to {computed_hex}"
                    ),
                );
            }
        }
        if content.len() as u64 > self.opts.budgets.object_cap {
            return Memo::Failed(
                Status::Paused,
                format!(
                    "object {} size {} exceeds per-object cap {}",
                    computed_hex,
                    content.len(),
                    self.opts.budgets.object_cap
                ),
            );
        }
        self.charge(cid, content.len() as u64);
        Memo::Done(ResolvedObject {
            oid_hex: computed_hex,
            kind: node.kind,
            content,
        })
    }

    fn apply_one_delta(
        &mut self,
        cid: i64,
        node: &CandidateNode,
        base: &ResolvedObject,
        depth: usize,
    ) -> Memo {
        let Some(delta_bytes) = node.raw_payload.clone() else {
            return Memo::Failed(Status::Error, "delta has no payload".into());
        };

        // Resume from a persisted checkpoint if one exists.
        let checkpoint = self.load_checkpoint(cid);
        let already_charged = self.charged.get(&cid).copied().unwrap_or(0);
        let mut budgets = self.opts.budgets;
        budgets.remaining_bytes = self.opts.budgets.total_bytes.saturating_sub(self.total_used);
        let result: Result<ApplyOutcome, DeltaError> = {
            let cp_ref = checkpoint.as_ref();
            delta::apply_delta(
                &base.content,
                &delta_bytes,
                cp_ref,
                budgets,
                already_charged,
            )
        };

        match result {
            Ok(outcome) => {
                let computed = git_object_id(base.kind, &outcome.output);
                let computed_hex = to_hex(&computed);
                if let Some(declared) = &node.oid_hex
                    && declared != &computed_hex
                {
                    return Memo::Failed(
                        Status::Error,
                        format!(
                            "reconstructed object id mismatch: idx names {declared}, got {computed_hex}"
                        ),
                    );
                }
                let newly = (outcome.output.len() as u64).saturating_sub(already_charged);
                self.charge(cid, newly);
                self.charged.insert(cid, outcome.output.len() as u64);
                self.steps.insert(cid, outcome.steps);
                Memo::Done(ResolvedObject {
                    oid_hex: computed_hex,
                    kind: base.kind,
                    content: outcome.output,
                })
            }
            Err(DeltaError::Paused(pause)) => {
                let cp = delta::checkpoint_from(&delta_bytes, &pause);
                let newly = (cp.output.len() as u64).saturating_sub(already_charged);
                self.charge_raw(newly);
                self.charged.insert(cid, cp.output.len() as u64);
                let reason = pause.reason.to_string();
                self.pause_reasons.push((cid, reason.clone()));
                let _ = depth;
                Memo::PausedAt(pause, cp.output, cp.out_len, cid)
            }
            Err(other) => Memo::Failed(Status::Error, other.to_string()),
        }
    }
