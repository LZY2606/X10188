//! The resolution engine: candidate graph, delta chains, budgets and recovery.

use crate::delta::{apply_parsed, parse as parse_delta, DeltaOp};
use crate::gitobj::{hex, object_id, ptype, type_name};
use crate::store::Store;
use rusqlite::params;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolveStatus {
    Resolved,
    Error,
    MissingBase,
    PausedBudget,
    Cycle,
}

impl ResolveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveStatus::Resolved => "resolved",
            ResolveStatus::Error => "error",
            ResolveStatus::PausedBudget => "paused_budget",
            ResolveStatus::MissingBase => "missing_base",
            ResolveStatus::Cycle => "cycle",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "resolved" => ResolveStatus::Resolved,
            "paused_budget" => ResolveStatus::PausedBudget,
            "cycle" => ResolveStatus::Cycle,
            "missing_base" => ResolveStatus::MissingBase,
            _ => ResolveStatus::Error,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeReport {
    pub oid: String,
    pub candidate_id: Option<i64>,
    pub status: String,
    pub obj_type: Option<String>,
    pub size: Option<i64>,
    pub depth: Option<i64>,
    pub oid_ok: Option<bool>,
    pub expanded_bytes: i64,
    pub blocking_chain: Option<serde_json::Value>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RunReport {
    pub resolved: usize,
    pub error: usize,
    pub missing_base: usize,
    pub paused_budget: usize,
    pub cycle: usize,
    pub budget_remaining: i64,
    pub nodes: Vec<NodeReport>,
}

#[derive(Debug, Clone)]
struct Candidate {
    id: i64,
    origin: String,
    loose_id: Option<i64>,
    entry_id: Option<i64>,
    chain_len_hint: i64,
    sort_key: String,
}

#[derive(Debug, Clone)]
struct EntryInfo {
    id: i64,
    pack_id: i64,
    offset: usize,
    obj_type: u8,
    declared_size: u64,
    base_offset: Option<usize>,
    base_oid: Option<[u8; 20]>,
    payload: Option<Vec<u8>>,
    inflate_error: Option<String>,
}

#[derive(Debug, Clone)]
struct LooseInfo {
    id: i64,
    computed_oid: String,
    obj_type: u8,
    content: Vec<u8>,
}

#[derive(Clone)]
enum NodeOutcome {
    Full {
        obj_type: u8,
        content: Vec<u8>,
        oid: [u8; 20],
        depth: i64,
        expanded: u64,
    },
    DeltaStart {
        entry_id: i64,
        base_node: BaseRef,
        delta: Vec<u8>,
        depth: i64,
        expanded: u64,
    },
    Fail {
        status: ResolveStatus,
        reason: String,
        chain: Vec<ChainHop>,
    },
}

#[derive(Debug, Clone)]
enum BaseRef {
    Offset(usize),
    Oid([u8; 20]),
}

#[derive(Debug, Clone, Serialize)]
struct ChainHop {
    from: String,
    via: String,
    target: String,
    detail: String,
}

#[derive(Debug, Clone, Copy)]
struct BudgetGuard {
    max_depth: u32,
    total_left: i64,
    per_object_cap: u64,
    paused: bool,
    pause_reason: Option<&'static str>,
}

pub struct Engine<'a> {
    store: &'a mut Store,
    branch_id: i64,
    candidates_by_oid: BTreeMap<String, Vec<Candidate>>,
    entries_by_id: HashMap<i64, EntryInfo>,
    entries_by_pack_off: HashMap<(i64, usize), i64>,
    loose_by_id: HashMap<i64, LooseInfo>,
    /// DFS memo of entry resolution.
    memo: HashMap<i64, NodeOutcome>,
    active: HashSet<i64>,
    pins: HashMap<String, i64>,
    budget: BudgetGuard,
    intermediate_written: HashSet<String>,
}

impl<'a> Engine<'a> {
    pub fn new(store: &'a mut Store, branch_name: &str) -> Self {
        let branch_id = store.branch_id(branch_name).unwrap();
        let budget = store.budget();
        let total_left = budget.max_total_expanded as i64 - budget.total_expanded_used as i64;
        let per_object_cap = (budget.max_total_expanded as f64 * budget.max_single_ratio) as u64;

        let mut entries_by_id = HashMap::new();
        let mut entries_by_pack_off = HashMap::new();
        {
            let mut stmt = store
                .conn
                .prepare(
                    "SELECT id, pack_id, offset, obj_type, declared_size, base_offset,
                            base_oid, payload_path, inflate_error
                     FROM entries",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    let payload_path: Option<String> = r.get(7)?;
                    let base_oid_hex: Option<String> = r.get(6)?;
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)? as usize,
                        r.get::<_, i64>(3)? as u8,
                        r.get::<_, i64>(4)? as u64,
                        r.get::<_, Option<i64>>(5)?.map(|v| v as usize),
                        base_oid_hex,
                        payload_path,
                        r.get::<_, Option<String>>(8)?,
                    ))
                })
                .unwrap();
            for row in rows {
                let (id, pack_id, offset, obj_type, size, base_off, base_oid_hex, payload_path, inflate_error) =
                    row.unwrap();
                let payload = payload_path.and_then(|p| {
                    std::fs::read(store.payload_path(&p)).ok()
                });
                let base_oid = base_oid_hex.and_then(|h| {
                    crate::gitobj::from_hex(&h).filter(|v| v.len() == 20).map(|v| {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&v);
                        a
                    })
                });
                let info = EntryInfo {
                    id,
                    pack_id,
                    offset,
                    obj_type,
                    declared_size: size,
                    base_offset: base_off,
                    base_oid,
                    payload,
                    inflate_error,
                };
                entries_by_id.insert(id, info);
                entries_by_pack_off.insert((pack_id, offset), id);
            }
        }

        let mut loose_by_id = HashMap::new();
        {
            let mut stmt = store
                .conn
                .prepare(
                    "SELECT l.id, l.computed_oid, l.obj_type, l.content_path, l.parse_error,
                           s.parse_status
                     FROM loose_objects l JOIN sources s ON s.id=l.source_id",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? as u8,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                })
                .unwrap();
            for row in rows {
                let (id, oid, t, path, err, status) = row.unwrap();
                if err.is_some() || status != "ok" {
                    continue;
                }
                let content = std::fs::read(store.payload_path(&path)).unwrap_or_default();
                loose_by_id.insert(
                    id,
                    LooseInfo {
                        id,
                        computed_oid: oid,
                        obj_type: t,
                        content,
                    },
                );
            }
        }

        let mut candidates_by_oid: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        {
            let mut stmt = store
                .conn
                .prepare(
                    "SELECT id, oid, origin, loose_object_id, entry_id, chain_len, sort_key
                     FROM candidates WHERE valid=1",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                })
                .unwrap();
            for row in rows {
                let (id, oid, origin, loose_id, entry_id, chain_len, sort_key) = row.unwrap();
                let cand = Candidate {
                    id,
                    origin,
                    loose_id,
                    entry_id,
                    chain_len_hint: chain_len,
                    sort_key,
                };
                if let Some(oid) = oid {
                    candidates_by_oid.entry(oid).or_default().push(cand);
                }
            }
        }

        let mut pins = HashMap::new();
        {
            let mut stmt = store
                .conn
                .prepare("SELECT oid, candidate_id FROM pins WHERE branch_id=?1")
                .unwrap();
            let rows = stmt
                .query_map(params![branch_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .unwrap();
            for r in rows.flatten() {
                pins.insert(r.0, r.1);
            }
        }

        Engine {
            store,
            branch_id,
            candidates_by_oid,
            entries_by_id,
            entries_by_pack_off,
            loose_by_id,
            memo: HashMap::new(),
            active: HashSet::new(),
            pins,
            budget: BudgetGuard {
                max_depth: budget.max_depth,
                total_left: total_left.max(0),
                per_object_cap,
                paused: false,
                pause_reason: None,
            },
            intermediate_written: HashSet::new(),
        }
    }
}

/// Rebuild deterministic candidate rows from current sources.
/// Import order never influences ordering: the sort key is purely
/// (origin, chain length hint, source sha256, byte offset).
pub fn rebuild_candidates(store: &mut Store) {
    store.conn.execute("DELETE FROM candidates", []).ok();

    // Loose objects: direct candidates keyed by recomputed oid.
    let loose_rows: Vec<(i64, String, String)> = {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT l.id, l.computed_oid, s.sha256
                 FROM loose_objects l
                 JOIN sources s ON s.id=l.source_id
                 WHERE l.parse_error IS NULL AND l.oid_matches=1",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    for (loose_id, oid, sha) in loose_rows {
        let key = format!("1|loose|000000|{}|0000000000", sha);
        store
            .conn
            .execute(
                "INSERT INTO candidates(oid, origin, loose_object_id, entry_id, chain_len, sort_key)
                 VALUES (?1,'loose',?2,NULL,0,?3)",
                params![oid, loose_id, key],
            )
            .unwrap();
    }

    // Pack entries: chain-length hint computed by walking ofs links inside
    // the same pack; ref links count as 1 (they may terminate externally).
    #[allow(clippy::type_complexity)]
    let entry_rows: Vec<(i64, i64, i64, u8, Option<i64>, Option<String>, String)> = {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT e.id, e.pack_id, e.offset, e.obj_type, e.base_offset, e.base_oid, s.sha256
                 FROM entries e JOIN packs p ON p.id=e.pack_id
                 JOIN sources s ON s.id=p.source_id
                 WHERE e.inflate_error IS NULL",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)? as u8,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    #[allow(clippy::type_complexity)]
    let by_key: HashMap<(i64, i64), (u8, Option<i64>)> = entry_rows
        .iter()
        .map(|r| ((r.1, r.2), (r.3, r.4)))
        .collect();
    let mut chain_of: HashMap<i64, i64> = HashMap::new();
    for (id, pack_id, _offset, t, base_offset, _bo_oid, _sha) in &entry_rows {
        let depth = match t {
            &ptype::OFS_DELTA => {
                let mut d = 0i64;
                let mut cur = *base_offset;
                let mut guard = 0;
                while let Some(bo) = cur {
                    guard += 1;
                    if guard > 10_000 {
                        d = 10_000;
                        break;
                    }
                    match by_key.get(&(*pack_id, bo)) {
                        Some((bt, next)) => {
                            d += 1;
                            if *bt == ptype::OFS_DELTA {
                                cur = *next;
                            } else {
                                break;
                            }
                        }
                        None => {
                            d += 1;
                            break;
                        }
                    }
                }
                d
            }
            &ptype::REF_DELTA => 1,
            _ => 0,
        };
        chain_of.insert(*id, depth);
    }
    for (id, _pack_id, offset, t, _bo, _bo_oid, sha) in &entry_rows {
        let depth = chain_of.get(id).copied().unwrap_or(0);
        let key = format!("2|pack|{:06}|{}|{:012}", depth, sha, offset);
        store
            .conn
            .execute(
                "INSERT INTO candidates(oid, origin, loose_object_id, entry_id, chain_len, sort_key)
                 VALUES (NULL,'pack',NULL,?1,?2,?3)",
                params![id, depth, key],
            )
            .unwrap();
        let _ = t;
    }
}

impl<'a> Engine<'a> {
    /// Resolve every pack entry. Loose objects are already fully known.
    /// Returns a report; results are also persisted as resolutions.
    pub fn run_all(&mut self) -> RunReport {
        let entry_ids: Vec<i64> = self.entries_by_id.keys().copied().collect();
        let mut results: Vec<(i64, NodeOutcome)> = Vec::new();
        for id in entry_ids {
            if self.memo.contains_key(&id) {
                continue;
            }
            let outcome = self.resolve_entry(id, Vec::new());
            self.memoize_tree(id, &outcome);
            results.push((id, outcome));
        }

        // Build oid -> candidate list from freshly resolved entries.
        let mut entry_candidate: HashMap<i64, (String, i64)> = HashMap::new();
        for (id, outcome) in &results {
            if let NodeOutcome::Full { oid, .. } = outcome {
                let cand_id = self
                    .store
                    .conn
                    .query_row(
                        "SELECT id FROM candidates WHERE entry_id=?1 LIMIT 1",
                        params![id],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0);
                if cand_id != 0 {
                    entry_candidate.insert(*id, (hex(oid), cand_id));
                    self.store
                        .conn
                        .execute(
                            "UPDATE candidates SET oid=?1 WHERE id=?2",
                            params![hex(oid), cand_id],
                        )
                        .ok();
                    self.candidates_by_oid
                        .entry(hex(oid))
                        .or_default()
                        .push(Candidate {
                            id: cand_id,
                            origin: "pack".into(),
                            loose_id: None,
                            entry_id: Some(*id),
                            chain_len_hint: 0,
                            sort_key: String::new(),
                        });
                }
            }
        }

        // Persist a resolution per terminal result oid. Delta-only
        // intermediate entries are recorded via their own terminal oid too
        // (their reconstructed content is still a valid git object).
        let mut report = RunReport::default();
        for (id, outcome) in results {
            self.persist_outcome(id, &outcome, &mut report);
        }
        report.budget_remaining = self.budget.total_left;
        report
    }

    fn memoize_tree(&mut self, id: i64, outcome: &NodeOutcome) {
        self.memo.insert(id, outcome.clone());
    }

    fn resolve_entry(&mut self, entry_id: i64, path: Vec<(i64, BaseRef)>) -> NodeOutcome {
        if let Some(o) = self.memo.get(&entry_id).cloned() {
            return o;
        }
        if self.active.contains(&entry_id) {
            let chain = self.describe_cycle(&path, entry_id);
            return NodeOutcome::Fail {
                status: ResolveStatus::Cycle,
                reason: "delta chain forms a cycle".into(),
                chain,
            };
        }
        self.active.insert(entry_id);

        let info = match self.entries_by_id.get(&entry_id).cloned() {
            Some(i) => i,
            None => {
                self.active.remove(&entry_id);
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "entry vanished".into(),
                    chain: vec![],
                };
            }
        };

        let outcome = match info.obj_type {
            ptype::COMMIT | ptype::TREE | ptype::BLOB | ptype::TAG => self.resolve_full(&info),
            ptype::OFS_DELTA => self.resolve_ofs_delta(&info, &path),
            ptype::REF_DELTA => self.resolve_ref_delta(&info, &path),
            other => NodeOutcome::Fail {
                status: ResolveStatus::Error,
                reason: format!("unsupported object type {}", other),
                chain: vec![],
            },
        };
        self.active.remove(&entry_id);
        outcome
    }

    fn resolve_full(&mut self, info: &EntryInfo) -> NodeOutcome {
        if let Some(err) = &info.inflate_error {
            return NodeOutcome::Fail {
                status: ResolveStatus::Error,
                reason: format!("inflate failed: {}", err),
                chain: vec![],
            };
        }
        let content = match &info.payload {
            Some(c) => c.clone(),
            None => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "missing inflated payload".into(),
                    chain: vec![],
                };
            }
        };
        if content.len() as u64 != info.declared_size {
            return NodeOutcome::Fail {
                status: ResolveStatus::Error,
                reason: format!(
                    "size spoof: header declared {} bytes but inflated {} bytes",
                    info.declared_size,
                    content.len()
                ),
                chain: vec![],
            };
        }
        let oid = object_id(info.obj_type, &content);
        NodeOutcome::Full {
            obj_type: info.obj_type,
            content,
            oid,
            depth: 0,
            expanded: 0,
        }
    }

    fn resolve_ofs_delta(
        &mut self,
        info: &EntryInfo,
        path: &[(i64, BaseRef)],
    ) -> NodeOutcome {
        let base_offset = match info.base_offset {
            Some(o) => o,
            None => {
                let mut chain = self.path_to_chain(path, info.id, BaseRef::Offset(info.offset));
                chain.push(ChainHop {
                    from: format!("pack{}@{}", info.pack_id, info.offset),
                    via: "ofs".into(),
                    target: "<before-pack-start>".into(),
                    detail: "negative-offset distance runs before the pack header".into(),
                });
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "ofs-delta distance out of bounds".into(),
                    chain,
                };
            }
        };
        let base_entry_id = match self
            .entries_by_pack_off
            .get(&(info.pack_id, base_offset))
            .copied()
        {
            Some(id) => id,
            None => {
                let mut chain = self.path_to_chain(path, info.id, BaseRef::Offset(info.offset));
                chain.push(ChainHop {
                    from: format!("pack{}@{}", info.pack_id, info.offset),
                    via: "ofs".into(),
                    target: format!("pack{}@{}", info.pack_id, base_offset),
                    detail: "base offset not found among parsed entries".into(),
                });
                return NodeOutcome::Fail {
                    status: ResolveStatus::MissingBase,
                    reason: format!(
                        "ofs-delta base at pack {} offset {} missing",
                        info.pack_id, base_offset
                    ),
                    chain,
                };
            }
        };

        let mut child_path = path.to_vec();
        child_path.push((info.id, BaseRef::Offset(base_offset)));
        let base_outcome = self.resolve_entry(base_entry_id, child_path);
        self.apply_with_base(info, base_outcome, "ofs", &format!("pack{}@{}", info.pack_id, base_offset), path)
    }

    fn resolve_ref_delta(
        &mut self,
        info: &EntryInfo,
        path: &[(i64, BaseRef)],
    ) -> NodeOutcome {
        let base_oid = match info.base_oid {
            Some(o) => o,
            None => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "ref-delta missing base oid".into(),
                    chain: vec![],
                }
            }
        };
        let base_outcome = self.resolve_base_oid(base_oid);
        match base_outcome {
            Some(o) => {
                self.apply_with_base(info, o, "ref", &hex(&base_oid), path)
            }
            None => {
                let mut chain = self.path_to_chain(path, info.id, BaseRef::Oid(base_oid));
                chain.push(ChainHop {
                    from: format!("pack{}@{}", info.pack_id, info.offset),
                    via: "ref".into(),
                    target: hex(&base_oid),
                    detail: "no imported candidate provides this base object id".into(),
                });
                NodeOutcome::Fail {
                    status: ResolveStatus::MissingBase,
                    reason: format!("ref-delta base {} not imported", hex(&base_oid)),
                    chain,
                }
            }
        }
    }

    /// Locate a base object anywhere among loose objects and resolved
    /// pack entries. A pinned candidate always wins inside this branch;
    /// otherwise the deterministic candidate ordering decides.
    fn resolve_base_oid(&mut self, oid: [u8; 20]) -> Option<NodeOutcome> {
        let key = hex(&oid);
        let pinned = self.pins.get(&key).copied();

        // 1. loose objects (candidates sorted origin=loose first anyway).
        let mut loose: Vec<Candidate> = Vec::new();
        let mut pack: Vec<Candidate> = Vec::new();
        if let Some(list) = self.candidates_by_oid.get(&key) {
            for c in list {
                if c.loose_id.is_some() {
                    loose.push(c.clone());
                } else {
                    pack.push(c.clone());
                }
            }
        }
        loose.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
        pack.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));

        let mut ordered: Vec<Candidate> = loose.into_iter().chain(pack.into_iter()).collect();
        if let Some(pin_id) = pinned {
            ordered.sort_by_key(|c| if c.id == pin_id { 0 } else { 1 });
        }
        for c in ordered {
            if let Some(loose_id) = c.loose_id {
                if let Some(info) = self.loose_by_id.get(&loose_id).cloned() {
                    return Some(NodeOutcome::Full {
                        obj_type: info.obj_type,
                        content: info.content,
                        oid,
                        depth: 0,
                        expanded: 0,
                    });
                }
            }
            if let Some(entry_id) = c.entry_id {
                if self.memo.contains_key(&entry_id) {
                    if let Some(o) = self.memo.get(&entry_id).cloned() {
                        if matches!(o, NodeOutcome::Full { .. }) {
                            return Some(o);
                        }
                    }
                } else {
                    let o = self.resolve_entry(entry_id, Vec::new());
                    self.memo.insert(entry_id, o.clone());
                    if matches!(o, NodeOutcome::Full { .. }) {
                        return Some(o);
                    }
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_with_base(
        &mut self,
        info: &EntryInfo,
        base_outcome: NodeOutcome,
        base_kind: &str,
        base_location: &str,
        path: &[(i64, BaseRef)],
    ) -> NodeOutcome {
        let delta = match &info.payload {
            Some(d) => d.clone(),
            None => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "delta payload missing (inflate failed)".into(),
                    chain: vec![],
                };
            }
        };
        let parsed = match parse_delta(&delta) {
            Ok(p) => p,
            Err(e) => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: format!("corrupt delta: {}", e),
                    chain: vec![],
                };
            }
        };

        let (obj_type, base_content, base_oid, base_depth, base_expanded) = match base_outcome {
            NodeOutcome::Full {
                obj_type,
                content,
                oid,
                depth,
                expanded,
            } => (obj_type, content, oid, depth, expanded),
            NodeOutcome::Fail {
                status,
                reason,
                chain,
            } => {
                return NodeOutcome::Fail {
                    status,
                    reason: format!("base unusable: {}", reason),
                    chain,
                };
            }
            NodeOutcome::DeltaStart { .. } => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: "internal: unresolved delta start".into(),
                    chain: vec![],
                };
            }
        };

        // Depth budget.
        let depth = base_depth + 1;
        if depth as u32 > self.budget.max_depth {
            return NodeOutcome::Fail {
                status: ResolveStatus::PausedBudget,
                reason: format!(
                    "delta depth {} exceeds budget max_depth {}",
                    depth, self.budget.max_depth
                ),
                chain: self.path_to_chain(path, info.id, BaseRef::Oid(base_oid)),
            };
        }

        // Base size agreement check (a lie in the delta header).
        if parsed.base_size != base_content.len() as u64 {
            return NodeOutcome::Fail {
                status: ResolveStatus::Error,
                reason: format!(
                    "delta base size {} disagrees with actual base length {}",
                    parsed.base_size,
                    base_content.len()
                ),
                chain: vec![],
            };
        }

        // Per-object and total expansion budgets are checked *before* the
        // expensive copy work, so hitting a limit leaves a clean retry point.
        let need = parsed.result_size;
        if need > self.budget.per_object_cap {
            self.budget.paused = true;
            self.budget.pause_reason = Some("single object expansion cap exceeded");
            return NodeOutcome::Fail {
                status: ResolveStatus::PausedBudget,
                reason: format!(
                    "result {} bytes exceeds per-object cap {} bytes (ratio {})",
                    need,
                    self.budget.per_object_cap,
                    { let b = self.store.budget(); b.max_single_ratio }
                ),
                chain: self.path_to_chain(path, info.id, BaseRef::Oid(base_oid)),
            };
        }
        if need as i64 > self.budget.total_left {
            self.budget.paused = true;
            self.budget.pause_reason = Some("total expansion budget exhausted");
            return NodeOutcome::Fail {
                status: ResolveStatus::PausedBudget,
                reason: format!(
                    "result {} bytes exceeds remaining total expansion budget {} bytes",
                    need, self.budget.total_left
                ),
                chain: self.path_to_chain(path, info.id, BaseRef::Oid(base_oid)),
            };
        }

        let out = match apply_parsed(&base_content, &parsed) {
            Ok(o) => o,
            Err(e) => {
                return NodeOutcome::Fail {
                    status: ResolveStatus::Error,
                    reason: format!("delta application failed: {}", e),
                    chain: vec![],
                };
            }
        };
        if out.len() as u64 != info.declared_size {
            return NodeOutcome::Fail {
                status: ResolveStatus::Error,
                reason: format!(
                    "size spoof: pack header declared {} but delta result {} bytes",
                    info.declared_size,
                    out.len()
                ),
                chain: vec![],
            };
        }

        self.budget.total_left -= out.len() as i64;
        let expanded = base_expanded + out.len() as u64;
        let oid = object_id(obj_type, &out);

        // Persist a forensic intermediate for this delta application.
        let inter_name = format!(
            "branch{}_entry{}_step{}.raw",
            self.branch_id, info.id, depth
        );
        self.store.write_intermediate(&inter_name, &out).ok();
        self.intermediate_written.insert(inter_name.clone());

        let cmd_start = parsed
            .op_ranges
            .first()
            .map(|r| r.start)
            .unwrap_or(parsed.header_range.end);
        let cmd_end = parsed
            .op_ranges
            .last()
            .map(|r| r.end)
            .unwrap_or(parsed.header_range.end);
        let check_detail = self.verify_steps(&base_content, &parsed.ops, &out);

        self.store
            .conn
            .execute(
                "INSERT INTO delta_steps(branch_id, oid, step, base_oid, base_kind, base_location,
                                         delta_entry_id, cmd_start, cmd_end, cmd_count,
                                         in_len, out_len, check_ok, check_detail)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(branch_id, oid, step) DO UPDATE SET
                    base_oid=excluded.base_oid, base_kind=excluded.base_kind,
                    base_location=excluded.base_location, delta_entry_id=excluded.delta_entry_id,
                    cmd_start=excluded.cmd_start, cmd_end=excluded.cmd_end,
                    cmd_count=excluded.cmd_count, in_len=excluded.in_len,
                    out_len=excluded.out_len, check_ok=excluded.check_ok,
                    check_detail=excluded.check_detail",
                params![
                    self.branch_id,
                    hex(&oid),
                    depth,
                    hex(&base_oid),
                    base_kind,
                    base_location,
                    info.id,
                    cmd_start as i64,
                    cmd_end as i64,
                    parsed.ops.len() as i64,
                    base_content.len() as i64,
                    out.len() as i64,
                    check_detail.is_none() as i64,
                    check_detail
                ],
            )
            .ok();

        self.store
            .conn
            .execute(
                "INSERT INTO edges(branch_id, from_oid, to_oid, kind)
                 VALUES (?1,?2,?3,?4)
                 ON CONFLICT(branch_id, from_oid, to_oid, kind) DO NOTHING",
                params![self.branch_id, hex(&base_oid), hex(&oid), base_kind],
            )
            .ok();

        NodeOutcome::Full {
            obj_type,
            content: out,
            oid,
            depth,
            expanded,
        }
    }

    /// Independently replay copy/insert instructions and confirm bounds
    /// and exact output reconstruction.
    fn verify_steps(
        &self,
        base: &[u8],
        ops: &[DeltaOp],
        expected_out: &[u8],
    ) -> Option<String> {
        let mut replayed = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            match op {
                DeltaOp::Insert { data } => replayed.extend_from_slice(data),
                DeltaOp::Copy { offset, size } => {
                    let end = match offset.checked_add(*size) {
                        Some(e) if e <= base.len() => e,
                        _ => return Some(format!("op {} copy out of bounds [{},{})", i, offset, offset + size)),
                    };
                    replayed.extend_from_slice(&base[*offset..end]);
                }
            }
        }
        if replayed != expected_out {
            return Some("replayed output differs from applied output".into());
        }
        None
    }

    fn path_to_chain(
        &self,
        path: &[(i64, BaseRef)],
        current_entry: i64,
        current_target: BaseRef,
    ) -> Vec<ChainHop> {
        let mut hops = Vec::new();
        let entry_desc = |entry_id: i64| -> String {
            match self.entries_by_id.get(&entry_id) {
                Some(e) => format!("pack{}@{}", e.pack_id, e.offset),
                None => format!("entry{}", entry_id),
            }
        };
        for (eid, target) in path {
            let target_s = match target {
                BaseRef::Offset(o) => format!("offset#{}", o),
                BaseRef::Oid(o) => hex(&o[..]),
            };
            let info = self.entries_by_id.get(eid);
            let kind = match info.map(|i| i.obj_type) {
                Some(ptype::OFS_DELTA) => "ofs",
                Some(ptype::REF_DELTA) => "ref",
                _ => "?",
            };
            hops.push(ChainHop {
                from: entry_desc(*eid),
                via: kind.into(),
                target: target_s,
                detail: String::new(),
            });
        }
        let kind = match self.entries_by_id.get(&current_entry).map(|i| i.obj_type) {
            Some(ptype::OFS_DELTA) => "ofs",
            Some(ptype::REF_DELTA) => "ref",
            _ => "?",
        };
        let target_s = match current_target {
            BaseRef::Offset(o) => format!("offset#{}", o),
            BaseRef::Oid(o) => hex(&o[..]),
        };
        hops.push(ChainHop {
            from: entry_desc(current_entry),
            via: kind.into(),
            target: target_s,
            detail: String::new(),
        });
        hops
    }

    fn describe_cycle(&self, path: &[(i64, BaseRef)], back_to: i64) -> Vec<ChainHop> {
        let mut hops = self.path_to_chain(path, back_to, BaseRef::Offset(0));
        if let Some(info) = self.entries_by_id.get(&back_to) {
            hops.push(ChainHop {
                from: format!("pack{}@{}", info.pack_id, info.offset),
                via: "cycle".into(),
                target: format!("pack{}@{}", info.pack_id, info.offset),
                detail: "edge loops back into an active delta node".into(),
            });
        }
        hops
    }

    fn persist_outcome(&mut self, entry_id: i64, outcome: &NodeOutcome, report: &mut RunReport) {
        let info = match self.entries_by_id.get(&entry_id).cloned() {
            Some(i) => i,
            None => return,
        };
        let (status, oid, obj_type, size, depth, expanded, reason, chain) = match outcome {
            NodeOutcome::Full {
                obj_type,
                content,
                oid,
                depth,
                expanded,
            } => {
                let name = format!("resolved_branch{}_{}.raw", self.branch_id, hex(oid));
                self.store.write_payload(&name, content).ok();
                let oid_ok = object_id(*obj_type, content) == *oid;
                (
                    ResolveStatus::Resolved,
                    hex(oid),
                    Some(type_name(*obj_type).to_string()),
                    Some(content.len() as i64),
                    Some(*depth),
                    *expanded as i64,
                    if oid_ok { None } else { Some("recomputed oid mismatch".to_string()) },
                    None,
                )
            }
            NodeOutcome::Fail {
                status,
                reason,
                chain,
            } => (
                *status,
                format!("unresolved_pack{}@{}", info.pack_id, info.offset),
                None,
                None,
                None,
                0,
                Some(reason.clone()),
                Some(serde_json::to_value(chain).unwrap_or(serde_json::Value::Null)),
            ),
            NodeOutcome::DeltaStart { .. } => return,
        };
        let candidate_id = self
            .store
            .conn
            .query_row(
                "SELECT id FROM candidates WHERE entry_id=?1 LIMIT 1",
                params![entry_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
        let content_path = if status == ResolveStatus::Resolved {
            Some(format!("resolved_branch{}_{}.raw", self.branch_id, oid))
        } else {
            None
        };
        let chain_str = chain.as_ref().map(|c| c.to_string());
        self.store
            .conn
            .execute(
                "INSERT INTO resolutions(branch_id, oid, candidate_id, status, obj_type,
                                         content_path, size, oid_ok, depth, expanded_bytes,
                                         blocking_chain, reason, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,strftime('%s','now'))
                 ON CONFLICT(branch_id, oid) DO UPDATE SET
                    candidate_id=excluded.candidate_id,
                    status=excluded.status, obj_type=excluded.obj_type,
                    content_path=excluded.content_path, size=excluded.size,
                    oid_ok=excluded.oid_ok, depth=excluded.depth,
                    expanded_bytes=excluded.expanded_bytes,
                    blocking_chain=excluded.blocking_chain, reason=excluded.reason,
                    updated_at=excluded.updated_at",
                params![
                    self.branch_id,
                    oid,
                    if candidate_id == 0 { None } else { Some(candidate_id) },
                    status.as_str(),
                    obj_type,
                    content_path,
                    size,
                    if status == ResolveStatus::Resolved { Some(1i64) } else { None },
                    depth,
                    expanded,
                    chain_str,
                    reason
                ],
            )
            .ok();

        let node = NodeReport {
            oid,
            candidate_id: if candidate_id == 0 { None } else { Some(candidate_id) },
            status: status.as_str().to_string(),
            obj_type,
            size,
            depth,
            oid_ok: if status == ResolveStatus::Resolved { Some(true) } else { None },
            expanded_bytes: expanded,
            blocking_chain: chain,
            reason,
        };
        match status {
            ResolveStatus::Resolved => report.resolved += 1,
            ResolveStatus::Error => report.error += 1,
            ResolveStatus::MissingBase => report.missing_base += 1,
            ResolveStatus::PausedBudget => report.paused_budget += 1,
            ResolveStatus::Cycle => report.cycle += 1,
        }
        report.nodes.push(node);
    }

    pub fn commit_budget(&mut self) {
        let mut b = self.store.budget();
        let consumed = (b.max_total_expanded as i64 - self.budget.total_left).max(0) as u64;
        if consumed > 0 {
            self.store.add_used(consumed);
        }
    }
}
