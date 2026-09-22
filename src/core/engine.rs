// The "pack chain microscope" analysis engine.
//
// Parsed sources are turned into nodes (loose objects, pack entries). Delta
// chains are reconstructed by a memoized, cycle-checked DFS. Bad objects are
// isolated into Failed/Paused states while analysis continues for the rest.

use super::delta::{apply_delta, CmdKind, DeltaCmd, DeltaHeader, DeltaError, PauseReason};
use super::git::{git_object_id, EntryType, GitType};
use super::idx::{ParsedIdx, IdxEntry};
use super::loose::{oid_from_relpath, ParsedLoose};
use super::pack::{ParsedPack, PackEntry, StreamError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

#[derive(Clone, Serialize)]
pub struct SourceFile {
    pub id: String,
    pub filename: String,
    pub size: usize,
    pub sha256: String,
    pub kind: SourceKind,
    pub import_seq: usize,
    pub parse_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Evidence {
    pub id: usize,
    pub node_id: Option<String>,
    pub source_id: Option<String>,
    pub code: String,
    pub message: String,
    pub offset: Option<u64>,
}

#[derive(Clone, Serialize)]
pub struct StepCmd {
    pub index: usize,
    pub op: String,
    pub range_start: usize,
    pub range_end: usize,
    pub copy_offset: Option<usize>,
    pub len: usize,
}

#[derive(Clone, Serialize)]
pub struct DeltaStepView {
    pub order: usize,
    pub delta_node: String,
    pub base_node: String,
    pub base_oid: Option<String>,
    pub base_type: String,
    pub instr_start: usize,
    pub instr_end: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub base_size_check: String,
    pub output_size_check: String,
    pub oid_check: String,
    pub cmds: Vec<StepCmd>,
}

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum FailKind {
    BadCrc,
    BadInflate,
    SizeSpoof,
    SizeMismatch,
    BadDelta,
    OfsOutOfRange,
    MissingBase,
    Cycle,
    BadLoose,
}

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum PauseKind {
    Depth,
    TotalBytes,
    SingleObject,
}

#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum NodeState {
    Unprocessed,
    Resolved {
        object_type: String,
        size: u64,
        oid: String,
        oid_expected: Option<String>,
        oid_match: bool,
        depth: usize,
        chain_bytes: u64,
        steps: Vec<DeltaStepView>,
    },
    Failed {
        kind: FailKind,
        message: String,
        blocker_chain: Vec<String>,
    },
    Paused {
        kind: PauseKind,
        message: String,
        attempted_target: u64,
        blocker_chain: Vec<String>,
    },
}

#[derive(Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub source_id: String,
    pub source_name: String,
    pub node_kind: String, // "loose" | "pack"
    pub object_type: String, // blob/tree/.../ofs-delta/ref-delta
    pub offset: Option<u64>,
    pub data_offset: Option<u64>,
    pub end_offset: Option<u64>,
    pub declared_size: u64,
    pub idx_oid: Option<String>,
    pub state: NodeState,
    pub crc32: Option<u32>,
    pub crc_ok: Option<bool>,
    pub ofs_distance: Option<u64>,
    pub ofs_base_offset: Option<u64>,
    pub ref_base_oid: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct BudgetView {
    pub max_depth: usize,
    pub total_bytes: u64,
    pub single_ratio: f64,
    pub charged_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Budget {
    pub max_depth: usize,
    pub total_bytes: u64,
    pub single_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 32,
            total_bytes: 64 * 1024 * 1024,
            single_ratio: 0.9,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct CandidateInfo {
    pub oid: String,
    pub node_id: String,
    pub source_name: String,
    pub offset: Option<u64>,
    pub origin: String, // "index" | "loose-path" | "computed"
    pub chosen: bool,
}

fn hex20(b: &[u8; 20]) -> String {
    hex::encode(b)
}

struct Store {
    sources: Vec<SourceFile>,
    source_by_id: HashMap<String, usize>,
    packs: HashMap<String, ParsedPack>,
    idxs: HashMap<String, ParsedIdx>,
    looses: HashMap<String, ParsedLoose>,
    nodes: Vec<Node>,
    pos: HashMap<String, usize>,
    contents: HashMap<String, Vec<u8>>,
    evidence: Vec<Evidence>,
    /// node id -> statically claimed oid (idx mapping / loose path).
    claimed: HashMap<String, (String, [u8; 20])>,
    /// node id -> dynamically registered oids (actual recomputed hashes).
    dynamic: HashMap<String, Vec<[u8; 20]>>,
    /// Pack node lookup by (source id, entry offset).
    offset_index: HashMap<(String, u64), String>,
    /// Recorded delta edges node -> base node (attempted or committed).
    edges: HashMap<String, Vec<String>>,
    /// Recorded missing-base edges node -> base oid hex.
    missing_edges: HashMap<String, String>,
    charged: HashMap<String, u64>,
    charged_total: u64,
}

pub struct Engine {
    pub data_dir: PathBuf,
    store: Store,
    budget: Budget,
    /// Branch name -> (oid hex -> pinned node id).
    branches: BTreeMap<String, BTreeMap<String, String>>,
    active_branch: Option<String>,
    pins: BTreeMap<String, String>,
    seq: usize,
    pub recompute_runs: u64,
    pub recomputed_nodes: u64,
}

impl Store {
    fn new() -> Store {
        Store {
            sources: Vec::new(),
            source_by_id: HashMap::new(),
            packs: HashMap::new(),
            idxs: HashMap::new(),
            looses: HashMap::new(),
            nodes: Vec::new(),
            pos: HashMap::new(),
            contents: HashMap::new(),
            evidence: Vec::new(),
            claimed: HashMap::new(),
            dynamic: HashMap::new(),
            offset_index: HashMap::new(),
            edges: HashMap::new(),
            missing_edges: HashMap::new(),
            charged: HashMap::new(),
            charged_total: 0,
        }
    }

    fn add_evidence(
        &mut self,
        node_id: Option<String>,
        source_id: Option<String>,
        code: &str,
        message: String,
        offset: Option<u64>,
    ) {
        let id = self.evidence.len();
        self.evidence.push(Evidence {
            id,
            node_id,
            source_id,
            code: code.into(),
            message,
            offset,
        });
    }

    fn nid(&self, id: &str) -> usize {
        self.pos[id]
    }
}

impl Engine {
    pub fn new(data_dir: PathBuf) -> Self {
        std::fs::create_dir_all(data_dir.join("files")).ok();
        Engine {
            data_dir,
            store: Store::new(),
            budget: Budget::default(),
            branches: BTreeMap::new(),
            active_branch: None,
            pins: BTreeMap::new(),
            seq: 0,
            recompute_runs: 0,
            recomputed_nodes: 0,
        }
    }

    pub fn budget(&self) -> BudgetView {
        BudgetView {
            max_depth: self.budget.max_depth,
            total_bytes: self.budget.total_bytes,
            single_ratio: self.budget.single_ratio,
            charged_bytes: self.store.charged_total,
        }
    }

    pub fn set_budget(&mut self, max_depth: usize, total_bytes: u64, single_ratio: f64) {
        self.budget = Budget {
            max_depth,
            total_bytes,
            single_ratio,
        };
    }
}

// ---------------------------------------------------------------------------
// Importing
// ---------------------------------------------------------------------------

fn detect_kind(filename: &str, head: &[u8]) -> SourceKind {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") || (head.len() >= 4 && &head[..4] == b"PACK") {
        SourceKind::Pack
    } else if lower.ends_with(".idx") {
        SourceKind::Idx
    } else {
        // Loose objects and unknowns. We attempt to inflate everything else;
        // the caller passes a relative path hint for oid reconstruction.
        SourceKind::Loose
    }
}

impl Engine {
    /// Import one file. `relpath` may embed a "xx/yyyy..." loose object path.
    /// Returns the source id.
    pub fn import_file(&mut self, filename: &str, relpath: &str, data: Vec<u8>) -> String {
        let sha = hex::encode(Sha256::digest(&data));
        if let Some(&i) = self
            .store
            .sources
            .iter()
            .position(|s| s.sha256 == sha && s.filename == filename)
            .and_then(|i| Some(i))
        {
            return self.store.sources[i].id.clone();
        }
        // Content-identical re-import under the same bytes also dedups by hash.
        if let Some(s) = self.store.sources.iter().find(|s| s.sha256 == sha) {
            return s.id.clone();
        }

        self.seq += 1;
        let id = format!("src{:03}", self.seq);
        std::fs::write(self.data_dir.join("files").join(&id), &data).ok();

        let kind = detect_kind(filename, &data);
        let mut source = SourceFile {
            id: id.clone(),
            filename: filename.to_string(),
            size: data.len(),
            sha256: sha.clone(),
            kind,
            import_seq: self.seq,
            parse_error: None,
        };

        let old_nodes = self.store.nodes.len();
        match kind {
            SourceKind::Pack => {
                match super::pack::parse_pack(&data) {
                    Ok(pack) => {
                        if let Some(err) = &pack.scan_error {
                            self.store.add_evidence(
                                None,
                                Some(id.clone()),
                                "pack-scan",
                                err.clone(),
                                None,
                            );
                        }
                        if !pack.checksum_ok {
                            self.store.add_evidence(
                                None,
                                Some(id.clone()),
                                "pack-checksum",
                                format!(
                                    "pack trailer {} != computed {}",
                                    hex20(&pack.trailer_sha),
                                    hex20(&pack.computed_sha)
                                ),
                                Some((data.len() - 20) as u64),
                            );
                        }
                        self.build_pack_nodes(&id, &filename, &pack);
                        self.store.packs.insert(id.clone(), pack);
                    }
                    Err(e) => {
                        source.parse_error = Some(e.clone());
                        self.store
                            .add_evidence(None, Some(id.clone()), "pack-parse", e, None);
                    }
                }
            }
            SourceKind::Idx => match super::idx::parse_idx(&data) {
                Ok(idx) => {
                    if !idx.idx_checksum_ok {
                        self.store.add_evidence(
                            None,
                            Some(id.clone()),
                            "idx-checksum",
                            format!(
                                "idx trailer {} != computed {}",
                                hex::encode(idx.idx_checksum),
                                hex::encode(idx.computed_idx_sha)
                            ),
                            None,
                        );
                    }
                    self.store.idxs.insert(id.clone(), idx);
                }
                Err(e) => {
                    source.parse_error = Some(e.clone());
                    self.store
                        .add_evidence(None, Some(id.clone()), "idx-parse", e, None);
                }
            },
            SourceKind::Loose | SourceKind::Unknown => {
                let path_oid = oid_from_relpath(relpath);
                let loose = super::loose::parse_loose(&data, path_oid);
                self.build_loose_node(&id, &filename, &loose);
                self.store.looses.insert(id.clone(), loose);
            }
        }

        // Reconcile idx files against matching packs (CRC + offset claims).
        self.reconcile_idxs();
        // Build static candidate index / default ordering.
        self.rebuild_claims();
        // Resolve everything (incrementally if nodes pre-existed).
        if old_nodes > 0 {
            let affected = self.newly_affected(old_nodes);
            self.resolve_all(Some(affected));
        } else {
            self.resolve_all(None);
        }

        self.store.source_by_id.insert(id.clone(), self.store.sources.len());
        self.store.sources.push(source);
        id
    }

    fn build_pack_nodes(&mut self, source_id: &str, filename: &str, pack: &ParsedPack) {
        for entry in &pack.entries {
            let node_id = format!("{}:0x{:x}", source_id, entry.offset);
            let object_type = entry.etype.label().to_string();
            let mut node = Node {
                id: node_id.clone(),
                source_id: source_id.to_string(),
                source_name: filename.to_string(),
                node_kind: "pack".into(),
                object_type: object_type.clone(),
                offset: Some(entry.offset),
                data_offset: Some(entry.data_offset),
                end_offset: Some(entry.end_offset),
                declared_size: entry.declared_size,
                idx_oid: None,
                state: NodeState::Unprocessed,
                crc32: entry.crc32,
                crc_ok: None,
                ofs_distance: entry.ofs_distance,
                ofs_base_offset: None,
                ref_base_oid: entry.base_oid.map(hex20),
            };

            if let Some(d) = entry.ofs_distance {
                node.ofs_base_offset = entry
                    .offset
                    .checked_sub(d)
                    .map(|v| v);
            }

            match &entry.inflated {
                Ok(_) => {}
                Err(se) => {
                    let (kind, code) = match se {
                        StreamError::Zlib(_) => (FailKind::BadInflate, "bad-inflate"),
                        StreamError::SizeMismatch { .. } => {
                            (FailKind::SizeMismatch, "size-mismatch")
                        }
                        StreamError::SizeSpoof { .. } => (FailKind::SizeSpoof, "size-spoof"),
                    };
                    self.store.add_evidence(
                        Some(node_id.clone()),
                        Some(source_id.to_string()),
                        code,
                        se.to_string(),
                        Some(entry.data_offset),
                    );
                    node.state = NodeState::Failed {
                        kind,
                        message: se.to_string(),
                        blocker_chain: vec![node_id.clone()],
                    };
                }
            }

            let pos = self.store.nodes.len();
            self.store.nodes.push(node);
            self.store.pos.insert(node_id.clone(), pos);
            self.store
                .offset_index
                .insert((source_id.to_string(), entry.offset), node_id);
        }
    }

    fn build_loose_node(&mut self, source_id: &str, filename: &str, loose: &ParsedLoose) {
        let node_id = format!("{}:loose", source_id);
        let mut node = Node {
            id: node_id.clone(),
            source_id: source_id.to_string(),
            source_name: filename.to_string(),
            node_kind: "loose".into(),
            object_type: loose.kind.name().into(),
            offset: Some(0),
            data_offset: Some(0),
            end_offset: loose.consumed.map(|c| c as u64),
            declared_size: loose.declared_size,
            idx_oid: loose.path_oid.map(hex20),
            state: NodeState::Unprocessed,
            crc32: None,
            crc_ok: None,
            ofs_distance: None,
            ofs_base_offset: None,
            ref_base_oid: None,
        };
        match &loose.content {
            Ok(_) => {}
            Err(e) => {
                self.store.add_evidence(
                    Some(node_id.clone()),
                    Some(source_id.to_string()),
                    "bad-loose",
                    e.clone(),
                    None,
                );
                node.state = NodeState::Failed {
                    kind: FailKind::BadLoose,
                    message: e.clone(),
                    blocker_chain: vec![node_id.clone()],
                };
            }
        }
        let pos = self.store.nodes.len();
        self.store.nodes.push(node);
        self.store.pos.insert(node_id, pos);
    }
}

// ---------------------------------------------------------------------------
// Index reconciliation and candidate claims
// ---------------------------------------------------------------------------

impl Engine {
    fn reconcile_idxs(&mut self) {
        // Pair each idx with a pack: pack checksum SHA first, then filename stem.
        let pack_summaries: Vec<(String, String, [u8; 20])> = self
            .store
            .packs
            .iter()
            .map(|(id, p)| (id.clone(), self.source_filename(id), p.computed_sha))
            .collect();
        let idx_ids: Vec<String> = self.store.idxs.keys().cloned().collect();
        for idx_id in idx_ids {
            let idx = self.store.idxs[&idx_id].clone();
            let idx_name = self.source_filename(&idx_id);

            // Preferred: checksum equality.
            let mut paired: Option<String> = pack_summaries
                .iter()
                .find(|(_, _, sha)| *sha == idx.pack_checksum)
                .map(|(id, _, _)| id.clone());
            // Fallback: same file stem ("objects.pack" <-> "objects.idx").
            if paired.is_none() {
                let stem = idx_name.trim_end_matches(".idx");
                paired = pack_summaries
                    .iter()
                    .find(|(_, name, _)| name.trim_end_matches(".pack") == stem)
                    .map(|(id, _, _)| id.clone());
            }

            let Some(pack_id) = paired else {
                self.store.add_evidence(
                    None,
                    Some(idx_id),
                    "idx-unpaired",
                    format!(
                        "index advertises pack {} but no imported pack matches it",
                        hex20(&idx.pack_checksum)
                    ),
                    None,
                );
                continue;
            };

            let pack = self.store.packs[&pack_id].clone();
            if pack.num_entries != idx.num_entries {
                self.store.add_evidence(
                    None,
                    Some(idx_id.clone()),
                    "idx-count",
                    format!(
                        "index lists {} objects but pack header declares {}",
                        idx.num_entries, pack.num_entries
                    ),
                    None,
                );
            }
            if pack.computed_sha != idx.pack_checksum {
                // Stem-based pairing only: explicitly flag the mismatch.
                self.store.add_evidence(
                    None,
                    Some(idx_id.clone()),
                    "idx-pack-mismatch",
                    format!(
                        "index {} does not match pack {} (checksum mismatch); treating as not paired",
                        idx_name,
                        self.source_filename(&pack_id)
                    ),
                    None,
                );
                continue;
            }

            for ie in &idx.entries {
                let key = (pack_id.clone(), ie.offset);
                let Some(node_id) = self.store.offset_index.get(&key).cloned() else {
                    self.store.add_evidence(
                        None,
                        Some(idx_id.clone()),
                        "idx-offset",
                        format!(
                            "index entry {} points at offset {} which has no pack object",
                            hex20(&ie.oid),
                            ie.offset
                        ),
                        Some(ie.offset),
                    );
                    continue;
                };
                let pos = self.store.nid(&node_id);
                let node = &mut self.store.nodes[pos];
                node.idx_oid = Some(hex20(&ie.oid));
                if let (Some(have), Some(want)) = (node.crc32, ie.crc32) {
                    node.crc_ok = Some(have == want);
                    if have != want {
                        self.store.add_evidence(
                            Some(node_id.clone()),
                            Some(idx_id.clone()),
                            "bad-crc",
                            format!(
                                "compressed data CRC {have:08x} != index CRC {want:08x} for {}",
                                hex20(&ie.oid)
                            ),
                            node.offset,
                        );
                    }
                }
                self.store
                    .claimed
                    .entry(node_id.clone())
                    .or_insert_with(|| ("index".into(), ie.oid));
            }
        }
    }

    fn rebuild_claims(&mut self) {
        // Loose path claims (never overwrite an index claim; an idx claim wins
        // deterministically regardless of import order).
        for (source_id, loose) in self.store.looses.clone().iter() {
            if let Some(oid) = loose.path_oid {
                let node_id = format!("{source_id}:loose");
                self.store
                    .claimed
                    .entry(node_id)
                    .or_insert_with(|| ("loose-path".into(), oid));
            }
        }

        // Any already-resolved node that produced a materialized hash is a
        // dynamic candidate (needed for ref-delta and candidate tables).
        let mut resolved_claims: Vec<(String, [u8; 20])> = Vec::new();
        for node in &self.store.nodes {
            if let NodeState::Resolved { oid, .. } = &node.state {
                let mut b = [0u8; 20];
                hex::decode_to_slice(oid, &mut b).ok();
                resolved_claims.push((node.id.clone(), b));
            }
        }
        for (node_id, oid) in resolved_claims {
            self.store
                .dynamic
                .entry(node_id)
                .or_insert_with(Vec::new)
                .push(oid);
        }
    }

    fn source_filename(&self, id: &str) -> String {
        self.store
            .sources
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.filename.clone())
            .unwrap_or_else(|| id.to_string())
    }
}

// ---------------------------------------------------------------------------
// Delta chain reconstruction (memoized, cycle checked, budget bounded)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ChainOutcome {
    kind: GitType,
    oid: [u8; 20],
    data: Vec<u8>,
    depth: usize,
    chain_bytes: u64,
    steps: Vec<DeltaStepView>,
}

struct RunCtx<'a> {
    stack: Vec<String>,
    results: HashMap<String, Result<ChainOutcome, (FailKind, String)>>,
    paused: HashMap<String, (PauseKind, String, u64)>,
    pins: &'a BTreeMap<String, String>,
    charged_total: u64,
    local_charge: u64,
    counted: HashSet<String>,
}

impl Engine {
    fn gather_candidates(&self, oid: &[u8; 20]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = Vec::new();
        for (node_id, (_, claimed_oid)) in &self.store.claimed {
            if claimed_oid == oid {
                v.push((node_id.clone(), "index".into()));
            }
        }
        for (node_id, oids) in &self.store.dynamic {
            if oids.contains(oid) {
                v.push((node_id.clone(), "computed".into()));
            }
        }
        // Deterministic ordering, independent of import order:
        // pinned node first, then claimed-vs-computed, source name, offset.
        let oid_hex = hex20(oid);
        let pinned = self.pins.get(&oid_hex).cloned().or_else(|| {
            self.active_branch
                .as_ref()
                .and_then(|b| self.branches.get(b))
                .and_then(|m| m.get(&oid_hex))
                .cloned()
        });
        v.sort_by(|(a, _), (b, _)| {
            let pa = pinned.as_deref() == Some(a.as_str());
            let pb = pinned.as_deref() == Some(b.as_str());
            pb.cmp(&pa).then_with(|| {
                let na = &self.store.nodes[self.store.nid(a)];
                let nb = &self.store.nodes[self.store.nid(b)];
                na.source_name
                    .cmp(&nb.source_name)
                    .then(na.offset.cmp(&nb.offset))
                    .then(na.id.cmp(&nb.id))
            })
        });
        v.dedup_by(|(a, _), (b, _)| a == b);
        v
    }

    fn resolve_all(&mut self, only: Option<HashSet<String>>) {
        self.recompute_runs += 1;
        // Deterministic traversal order.
        let mut ids: Vec<String> = self.store.nodes.iter().map(|n| n.id.clone()).collect();
        ids.sort();
        let mut ctx = RunCtx {
            stack: Vec::new(),
            results: HashMap::new(),
            paused: HashMap::new(),
            pins: &self.pins,
            charged_total: self.store.charged_total,
            local_charge: 0,
            counted: HashSet::new(),
        };

        for id in ids {
            if let Some(set) = &only {
                if !set.contains(&id) {
                    continue;
                }
            }
            self.resolve_node(&id, 0, &mut ctx);
        }

        // Publish results to nodes.
        let produced: Vec<(String, Result<ChainOutcome, (FailKind, String)>)> = ctx
            .results
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (id, res) in produced {
            let pos = self.store.nid(&id);
            match res {
                Ok(out) => {
                    let oid = git_object_id(out.kind, &out.data);
                    let oid_hex = hex20(&oid);
                    let idx_oid = self.store.nodes[pos].idx_oid.clone();
                    let oid_match = match &idx_oid {
                        Some(want) => want == &oid_hex,
                        None => true,
                    };
                    if !oid_match {
                        if let Some(want) = &idx_oid {
                            self.store.add_evidence(
                                Some(id.clone()),
                                Some(self.store.nodes[pos].source_id.clone()),
                                "oid-mismatch",
                                format!(
                                    "reconstructed object hashes to {oid_hex} but expected {want}"
                                ),
                                self.store.nodes[pos].offset,
                            );
                        }
                    }
                    // Commit content + charge + dynamic registration.
                    self.store.contents.insert(id.clone(), out.data);
                    let charge = out.chain_bytes;
                    if !self.store.charged.contains_key(&id) {
                        self.store.charged.insert(id.clone(), charge);
                        self.store.charged_total = self
                            .store
                            .charged_total
                            .saturating_add(charge);
                    }
                    self.store
                        .dynamic
                        .entry(id.clone())
                        .or_insert_with(Vec::new)
                        .push(oid);
                    let node = &mut self.store.nodes[pos];
                    node.state = NodeState::Resolved {
                        object_type: out.kind.name().into(),
                        size: self
                            .store
                            .contents
                            .get(&id)
                            .map(|c| c.len() as u64)
                            .unwrap_or(0),
                        oid: oid_hex,
                        oid_expected: idx_oid,
                        oid_match,
                        depth: out.depth,
                        chain_bytes: out.chain_bytes,
                        steps: out.steps,
                    };
                }
                Err((kind, message)) => {
                    let chain = self.blocker_chain(&id, &ctx);
                    let node = &mut self.store.nodes[pos];
                    node.state = NodeState::Failed {
                        kind,
                        message,
                        blocker_chain: chain,
                    };
                }
            }
            self.recomputed_nodes += 1;
        }

        let paused: Vec<(String, PauseKind, String, u64)> = ctx
            .paused
            .iter()
            .map(|(k, (pk, m, t))| (k.clone(), *pk, m.clone(), *t))
            .collect();
        for (id, kind, message, target) in paused {
            let pos = self.store.nid(&id);
            let chain = self.blocker_chain(&id, &ctx);
            let node = &mut self.store.nodes[pos];
            // Paused must never overwrite a committed good object.
            if matches!(node.state, NodeState::Resolved { .. }) {
                continue;
            }
            node.state = NodeState::Paused {
                kind,
                message,
                attempted_target: target,
                blocker_chain: chain,
            };
        }
    }

    fn blocker_chain(&self, id: &str, ctx: &RunCtx) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cur = Some(id.to_string());
        let mut guard = 0;
        while let Some(node) = cur {
            chain.push(node.clone());
            guard += 1;
            if guard > 256 {
                break;
            }
            cur = self
                .store
                .edges
                .get(&node)
                .and_then(|v| v.last())
                .cloned();
            if cur.as_deref() == Some(id) {
                chain.push(format!("{} (cycle)", id));
                break;
            }
        }
        let _ = ctx;
        chain
    }

    fn reset_subtree(&mut self, ids: &HashSet<String>) {
        for id in ids {
            if let Some(&pos) = self.store.pos.get(id) {
                // Remove committed outputs/charges/claims that this run may
                // regenerate. Dynamic registrations are rebuilt afterwards.
                if let Some(charge) = self.store.charged.remove(id) {
                    self.store.charged_total =
                        self.store.charged_total.saturating_sub(charge);
                }
                self.store.contents.remove(id);
                self.store.dynamic.remove(id);
                self.store.edges.remove(id);
                self.store.missing_edges.remove(id);
                let node = &mut self.store.nodes[pos];
                if !matches!(node.state, NodeState::Failed { kind: FailKind::BadCrc | FailKind::BadInflate | FailKind::SizeSpoof | FailKind::SizeMismatch | FailKind::BadLoose, .. }) {
                    node.state = NodeState::Unprocessed;
                }
            }
        }
    }
}

enum Res {
    Ok,
    Fail(FailKind, String),
    Pause(PauseKind, String, u64),
}

impl Engine {
    fn single_cap(&self) -> u64 {
        (self.budget.total_bytes as f64 * self.budget.single_ratio).floor() as u64
    }

    fn resolve_node(&mut self, id: &str, depth: usize, ctx: &mut RunCtx) -> Res {
        if let Some(out) = self.existing_outcome(id) {
            ctx.results.entry(id.to_string()).or_insert(Ok(out));
            return Res::Ok;
        }
        if ctx.results.contains_key(id) {
            return Res::Ok;
        }
        if let Some((pk, m, t)) = ctx.paused.get(id).cloned() {
            return Res::Pause(pk, m, t);
        }
        if let Some((k, m)) = ctx.results.get(id).and_then(|r| r.as_ref().err()).cloned() {
            return Res::Fail(k, m);
        }

        // Cycle guard first.
        if ctx.stack.iter().any(|n| n == id) {
            let msg = format!("delta cycle detected through {id}");
            self.store.add_evidence(
                Some(id.to_string()),
                Some(self.store.nodes[self.store.nid(id)].source_id.clone()),
                "cycle",
                msg.clone(),
                None,
            );
            ctx.results
                .insert(id.to_string(), Err((FailKind::Cycle, msg.clone())));
            return Res::Fail(FailKind::Cycle, msg);
        }

        // Static fatal isolation (bad CRC / bad zlib / spoof / bad loose).
        {
            let node = &self.store.nodes[self.store.nid(id)];
            if let NodeState::Failed { kind, message, .. } = &node.state {
                if matches!(
                    kind,
                    FailKind::BadCrc
                        | FailKind::BadInflate
                        | FailKind::SizeSpoof
                        | FailKind::SizeMismatch
                        | FailKind::BadLoose
                ) {
                    ctx.results
                        .insert(id.to_string(), Err((*kind, message.clone())));
                    return Res::Fail(*kind, message.clone());
                }
            }
        }

        if depth >= self.budget.max_depth {
            let msg = format!("delta depth limit {} reached at {id}", self.budget.max_depth);
            self.store.add_evidence(
                Some(id.to_string()),
                Some(self.store.nodes[self.store.nid(id)].source_id.clone()),
                "budget-depth",
                msg.clone(),
                None,
            );
            ctx.paused.insert(
                id.to_string(),
                (PauseKind::Depth, msg.clone(), node_declared(self, id)),
            );
            return Res::Pause(PauseKind::Depth, msg, node_declared(self, id));
        }

        ctx.stack.push(id.to_string());

        let node_kind = self.store.nodes[self.store.nid(id)].node_kind.clone();
        let object_type = self.store.nodes[self.store.nid(id)].object_type.clone();
        let result = if node_kind == "loose" {
            self.resolve_loose(id, depth, ctx)
        } else if object_type == "ofs-delta" {
            self.resolve_ofs_delta(id, depth, ctx)
        } else if object_type == "ref-delta" {
            self.resolve_ref_delta(id, depth, ctx)
        } else {
            self.resolve_pack_base(id, depth, ctx)
        };

        ctx.stack.pop();

        // Ensure ctx maps reflect the outcome.
        match &result {
            Res::Ok => {
                if !ctx.results.contains_key(id) {
                    // Defensive: should already be inserted by materialize_*
                    ctx.results.insert(
                        id.to_string(),
                        Err((FailKind::BadDelta, "internal: missing outcome".into())),
                    );
                }
            }
            Res::Fail(k, m) => {
                ctx.results.insert(id.to_string(), Err((*k, m.clone())));
            }
            Res::Pause(k, m, t) => {
                ctx.paused.insert(id.to_string(), (*k, m.clone(), *t));
            }
        }
        result
    }

    fn existing_outcome(&self, id: &str) -> Option<ChainOutcome> {
        let node = self.store.nodes.get(*self.store.pos.get(id)?)?;
        let NodeState::Resolved {
            object_type,
            size,
            steps,
            ..
        } = &node.state
        else {
            return None;
        };
        let kind = match object_type.as_str() {
            "commit" => GitType::Commit,
            "tree" => GitType::Tree,
            "blob" => GitType::Blob,
            "tag" => GitType::Tag,
            _ => return None,
        };
        let data = self.store.contents.get(id)?.clone();
        let depth = if let NodeState::Resolved { depth, .. } = &node.state {
            *depth
        } else {
            0
        };
        let chain_bytes = if let NodeState::Resolved { chain_bytes, .. } = &node.state {
            *chain_bytes
        } else {
            *size
        };
        let oid = git_object_id(kind, &data);
        Some(ChainOutcome {
            kind,
            oid,
            data,
            depth,
            chain_bytes,
            steps: steps.clone(),
        })
    }

    fn charge_slot(&mut self, id: &str, bytes: u64, ctx: &mut RunCtx) -> Option<(PauseKind, String)> {
        let single_cap = self.single_cap();
        if bytes > single_cap {
            return Some((
                PauseKind::SingleObject,
                format!(
                    "object expansion {bytes} bytes exceeds single-object allowance {single_cap} ({}% of total budget)",
                    (self.budget.single_ratio * 100.0) as u32
                ),
            ));
        }
        let already = self.store.charged.contains_key(id);
        let counted = ctx.counted.contains(id);
        if !already && !counted {
            let used = ctx.charged_total + ctx.local_charge;
            if used.saturating_add(bytes) > self.budget.total_bytes {
                return Some((
                    PauseKind::TotalBytes,
                    format!(
                        "expanding {bytes} bytes would cross total budget {} (used {used})",
                        self.budget.total_bytes
                    ),
                ));
            }
            ctx.local_charge += bytes;
            ctx.counted.insert(id.to_string());
        }
        None
    }

    fn resolve_loose(&mut self, id: &str, depth: usize, ctx: &mut RunCtx) -> Res {
        let source_id = self.store.nodes[self.store.nid(id)].source_id.clone();
        let loose = self.store.looses.get(&source_id).cloned();
        let Some(loose) = loose else {
            return self.fail_node(id, FailKind::BadLoose, "loose payload missing", ctx);
        };
        let content = match loose.content {
            Ok(c) => c,
            Err(e) => return self.fail_node(id, FailKind::BadLoose, &e, ctx),
        };
        let bytes = content.len() as u64;
        if let Some((k, m)) = self.charge_slot(id, bytes, ctx) {
            return Res::Pause(k, m, bytes);
        }
        let oid = git_object_id(loose.kind, &content);
        let oid_match = match loose.path_oid {
            Some(want) => want == oid,
            None => true,
        };
        if !oid_match {
            self.store.add_evidence(
                Some(id.to_string()),
                Some(source_id),
                "oid-mismatch",
                format!(
                    "loose object hashes to {} but path advertised {}",
                    hex20(&oid),
                    hex20(&loose.path_oid.unwrap())
                ),
                None,
            );
        }
        self.register_dynamic(id, oid);
        ctx.results.insert(
            id.to_string(),
            Ok(ChainOutcome {
                kind: loose.kind,
                oid,
                data: content,
                depth,
                chain_bytes: bytes,
                steps: Vec::new(),
            }),
        );
        Res::Ok
    }

    fn resolve_pack_base(&mut self, id: &str, depth: usize, ctx: &mut RunCtx) -> Res {
        let node_pos = self.store.nid(id);
        let source_id = self.store.nodes[node_pos].source_id.clone();
        let offset = self.store.nodes[node_pos].offset.unwrap_or(0);
        let type_name = self.store.nodes[node_pos].object_type.clone();
        let declared = self.store.nodes[node_pos].declared_size;
        let kind = match type_name.as_str() {
            "commit" => GitType::Commit,
            "tree" => GitType::Tree,
            "blob" => GitType::Blob,
            "tag" => GitType::Tag,
            other => {
                return self.fail_node(
                    id,
                    FailKind::BadDelta,
                    &format!("unexpected base object type {other}"),
                    ctx,
                )
            }
        };

        let pack = self.store.packs.get(&source_id).cloned();
        let Some(pack) = pack else {
            return self.fail_node(id, FailKind::BadInflate, "pack payload missing", ctx);
        };
        let Some(entry) = pack.entries.iter().find(|e| e.offset == offset).cloned() else {
            return self.fail_node(id, FailKind::BadInflate, "pack entry missing", ctx);
        };
        let data = match entry.inflated {
            Ok(d) => d,
            Err(se) => {
                let k = match se {
                    StreamError::Zlib(_) => FailKind::BadInflate,
                    StreamError::SizeMismatch { .. } => FailKind::SizeMismatch,
                    StreamError::SizeSpoof { .. } => FailKind::SizeSpoof,
                };
                return self.fail_node(id, k, &se.to_string(), ctx);
            }
        };
        if let Some((pk, m)) = self.charge_slot(id, declared, ctx) {
            return Res::Pause(pk, m, declared);
        }
        let oid = git_object_id(kind, &data);
        self.register_dynamic(id, oid);
        ctx.results.insert(
            id.to_string(),
            Ok(ChainOutcome {
                kind,
                oid,
                data,
                depth,
                chain_bytes: declared,
                steps: Vec::new(),
            }),
        );
        Res::Ok
    }

    fn resolve_ofs_delta(&mut self, id: &str, depth: usize, ctx: &mut RunCtx) -> Res {
        let node_pos = self.store.nid(id);
        let source_id = self.store.nodes[node_pos].source_id.clone();
        let offset = self.store.nodes[node_pos].offset.unwrap_or(0);
        let base_offset = self.store.nodes[node_pos].ofs_base_offset;
        let distance = self.store.nodes[node_pos].ofs_distance;

        let Some(boff) = base_offset else {
            return self.fail_node(
                id,
                FailKind::OfsOutOfRange,
                &format!(
                    "ofs-delta negative distance {} underflows at offset {}",
                    distance.unwrap_or(0),
                    offset
                ),
                ctx,
            );
        };
        let base_id = self
            .store
            .offset_index
            .get(&(source_id.clone(), boff))
            .cloned();
        let Some(base_id) = base_id else {
            self.store.add_evidence(
                Some(id.to_string()),
                Some(source_id.clone()),
                "ofs-out-of-range",
                format!(
                    "ofs-delta at {offset} points at {boff} (distance {}), but no object starts there",
                    distance.unwrap_or(0)
                ),
                Some(offset),
            );
            return self.fail_node(
                id,
                FailKind::OfsOutOfRange,
                &format!("no pack object at ofs-delta base offset {boff}"),
                ctx,
            );
        };
        if boff >= offset {
            return self.fail_node(
                id,
                FailKind::OfsOutOfRange,
                &format!("ofs-delta base offset {boff} is not before {offset}"),
                ctx,
            );
        }
        self.record_edge(id, &base_id);
        self.apply_chain(id, &base_id, depth, ctx, "ofs")
    }

    fn resolve_ref_delta(&mut self, id: &str, depth: usize, ctx: &mut RunCtx) -> Res {
        let node_pos = self.store.nid(id);
        let source_id = self.store.nodes[node_pos].source_id.clone();
        let offset = self.store.nodes[node_pos].offset;
        let base_hex = self.store.nodes[node_pos].ref_base_oid.clone().unwrap();
        let mut oid = [0u8; 20];
        hex::decode_to_slice(&base_hex, &mut oid).ok();

        let candidates = self.gather_candidates(&oid);
        if candidates.is_empty() {
            self.store
                .missing_edges
                .insert(id.to_string(), base_hex.clone());
            self.store.add_evidence(
                Some(id.to_string()),
                Some(source_id.clone()),
                "missing-base",
                format!("ref-delta base object {base_hex} is not present in any imported source"),
                offset,
            );
            return self.fail_node(
                id,
                FailKind::MissingBase,
                &format!("missing base object {base_hex}"),
                ctx,
            );
        }
        if candidates.len() > 1 {
            let list = candidates
                .iter()
                .map(|(n, origin)| {
                    let node = &self.store.nodes[self.store.nid(n)];
                    format!(
                        "{} [{} @ {}]",
                        n,
                        origin,
                        node.offset
                            .map(|o| format!("0x{o:x}"))
                            .unwrap_or_else(|| "loose".into())
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let pinned = self.active_pin(&base_hex);
            if pinned.is_none() {
                self.store.add_evidence(
                    Some(id.to_string()),
                    Some(source_id.clone()),
                    "duplicate-oid",
                    format!(
                        "object {base_hex} has {} candidate sources; using {}; alternatives: {list}",
                        candidates.len(),
                        candidates[0].0
                    ),
                    offset,
                );
            }
        }
        let base_id = candidates[0].0.clone();
        self.record_edge(id, &base_id);
        self.apply_chain(id, &base_id, depth, ctx, "ref")
    }

    fn active_pin(&self, oid_hex: &str) -> Option<String> {
        self.pins
            .get(oid_hex)
            .cloned()
            .or_else(|| {
                self.active_branch
                    .as_ref()
                    .and_then(|b| self.branches.get(b))
                    .and_then(|m| m.get(oid_hex))
                    .cloned()
            })
    }

    fn record_edge(&mut self, id: &str, base_id: &str) {
        let v = self.store.edges.entry(id.to_string()).or_default();
        if !v.iter().any(|n| n == base_id) {
            v.push(base_id.to_string());
        }
    }

    fn register_dynamic(&mut self, id: &str, oid: [u8; 20]) {
        let v = self.store.dynamic.entry(id.to_string()).or_default();
        if !v.contains(&oid) {
            v.push(oid);
        }
    }

    fn fail_node(&mut self, id: &str, kind: FailKind, msg: &str, _ctx: &mut RunCtx) -> Res {
        Res::Fail(kind, msg.to_string())
    }
}

fn node_declared(engine: &Engine, id: &str) -> u64 {
    engine
        .store
        .nodes
        .get(*engine.store.pos.get(id).unwrap_or(&0))
        .map(|n| n.declared_size)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Applying one delta edge onto an already resolved base outcome
// ---------------------------------------------------------------------------

impl Engine {
    fn apply_chain(
        &mut self,
        id: &str,
        base_id: &str,
        depth: usize,
        ctx: &mut RunCtx,
        link: &str,
    ) -> Res {
        // Resolve the base first (recursive, memoized).
        match self.resolve_node(base_id, depth + 1, ctx) {
            Res::Ok => {}
            Res::Fail(k, m) => return Res::Fail(k, format!("base {base_id} failed: {m}")),
            Res::Pause(k, m, t) => {
                return Res::Pause(k, format!("blocked by base {base_id}: {m}"), t)
            }
        }
        let base_outcome = match ctx.results.get(base_id).cloned() {
            Some(Ok(o)) => o,
            Some(Err((k, m))) => return Res::Fail(k, format!("base {base_id}: {m}")),
            None => {
                // Base may already be committed from a previous run.
                match self.existing_outcome(base_id) {
                    Some(o) => {
                        ctx.results.insert(base_id.to_string(), Ok(o.clone()));
                        o
                    }
                    None => {
                        return Res::Fail(
                            FailKind::BadDelta,
                            format!("base {base_id} produced no outcome"),
                        )
                    }
                }
            }
        };

        // Fetch this node's inflated delta payload.
        let node_pos = self.store.nid(id);
        let source_id = self.store.nodes[node_pos].source_id.clone();
        let offset = self.store.nodes[node_pos].offset.unwrap_or(0);
        let declared_target = self.store.nodes[node_pos].declared_size;
        let idx_oid = self.store.nodes[node_pos].idx_oid.clone();
        let pack = self.store.packs.get(&source_id).cloned();
        let delta_bytes = match pack.and_then(|p| p.entries.iter().find(|e| e.offset == offset).cloned())
        {
            Some(PackEntry { inflated: Ok(d), .. }) => d,
            Some(PackEntry { inflated: Err(se), .. }) => {
                let k = match se {
                    StreamError::Zlib(_) => FailKind::BadInflate,
                    StreamError::SizeMismatch { .. } => FailKind::SizeMismatch,
                    StreamError::SizeSpoof { .. } => FailKind::SizeSpoof,
                };
                return Res::Fail(k, se.to_string());
            }
            None => return Res::Fail(FailKind::BadDelta, "delta entry vanished".into()),
        };

        let header = match super::delta::parse_header(&delta_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.store.add_evidence(
                    Some(id.to_string()),
                    Some(source_id),
                    "bad-delta",
                    e.to_string(),
                    Some(offset),
                );
                return Res::Fail(FailKind::BadDelta, e.to_string());
            }
        };

        // Budget: charging is per node output. Refuse before producing any
        // bytes so a paused attempt can never be mistaken for a full object.
        let total_remain = self
            .budget
            .total_bytes
            .saturating_sub(ctx.charged_total + ctx.local_charge);
        let single_allow = self.single_cap() as usize;
        let result = apply_delta(
            &base_outcome.data,
            &delta_bytes,
            single_allow,
            total_remain as usize,
        );

        let (out_data, cmds) = match result {
            Ok(v) => (v.0, v.1),
            Err(DeltaError::BudgetPaused { target_size, reason }) => {
                let kind = match reason {
                    PauseReason::SingleObject => PauseKind::SingleObject,
                    PauseReason::TotalBytes => PauseKind::TotalBytes,
                };
                let msg = format!(
                    "delta target {target_size} bytes blocked by {kind:?} budget (base {base_id})"
                );
                self.store.add_evidence(
                    Some(id.to_string()),
                    Some(source_id),
                    "budget-pause",
                    msg.clone(),
                    Some(offset),
                );
                return Res::Pause(kind, msg, target_size);
            }
            Err(other) => {
                self.store.add_evidence(
                    Some(id.to_string()),
                    Some(source_id),
                    "bad-delta",
                    other.to_string(),
                    Some(offset),
                );
                return Res::Fail(FailKind::BadDelta, other.to_string());
            }
        };

        if (out_data.len() as u64) != declared_target {
            let msg = format!(
                "pack entry declares {declared_target} bytes but delta reconstructs {} bytes",
                out_data.len()
            );
            self.store.add_evidence(
                Some(id.to_string()),
                Some(source_id),
                "size-mismatch",
                msg.clone(),
                Some(offset),
            );
            return Res::Fail(FailKind::SizeMismatch, msg);
        }

        // Charge the *newly produced* object once.
        if let Some((pk, m)) = self.charge_slot(id, out_data.len() as u64, ctx) {
            return Res::Pause(pk, m, out_data.len() as u64);
        }

        // Validate reconstructed oid (recomputed from scratch) before publishing.
        let oid = git_object_id(base_outcome.kind, &out_data);
        let oid_hex = hex20(&oid);
        let oid_check = match &idx_oid {
            Some(want) => {
                if want == &oid_hex {
                    "match".to_string()
                } else {
                    format!("mismatch: computed {oid_hex}, index expects {want}")
                }
            }
            None if !matches!(link, "ref") => "no-expected-oid".to_string(),
            None => "no-expected-oid".to_string(),
        };
        if let Some(want) = &idx_oid {
            if want != &oid_hex {
                self.store.add_evidence(
                    Some(id.to_string()),
                    Some(source_id.clone()),
                    "oid-mismatch",
                    format!("reconstructed {oid_hex} but expected {want}"),
                    Some(offset),
                );
            }
        }

        let base_size_check = if header.base_size as usize == base_outcome.data.len() {
            format!("match ({} bytes)", base_outcome.data.len())
        } else {
            format!(
                "mismatch: header {} vs base {}",
                header.base_size,
                base_outcome.data.len()
            )
        };
        let output_size_check = if header.target_size as usize == out_data.len() {
            format!("match ({} bytes)", out_data.len())
        } else {
            format!(
                "mismatch: header {} vs produced {}",
                header.target_size,
                out_data.len()
            )
        };

        let step = DeltaStepView {
            order: base_outcome.steps.len(),
            delta_node: id.to_string(),
            base_node: base_id.to_string(),
            base_oid: Some(hex20(&base_outcome.oid)),
            base_type: base_outcome.kind.name().to_string(),
            instr_start: header.instr_start,
            instr_end: delta_bytes.len(),
            input_len: base_outcome.data.len(),
            output_len: out_data.len(),
            base_size_check,
            output_size_check,
            oid_check,
            cmds: cmds.iter().map(cmd_view).collect(),
        };

        let mut steps = base_outcome.steps.clone();
        steps.push(step);

        let chain_bytes = base_outcome.chain_bytes + out_data.len() as u64;
        self.register_dynamic(id, oid);
        ctx.results.insert(
            id.to_string(),
            Ok(ChainOutcome {
                kind: base_outcome.kind,
                oid,
                data: out_data,
                depth,
                chain_bytes,
                steps,
            }),
        );
        Res::Ok
    }
}

fn cmd_view(c: &DeltaCmd) -> StepCmd {
    match c.kind {
        CmdKind::Copy { offset, len } => StepCmd {
            index: c.index,
            op: "copy".into(),
            range_start: c.range.0,
            range_end: c.range.1,
            copy_offset: Some(offset),
            len,
        },
        CmdKind::Insert { len } => StepCmd {
            index: c.index,
            op: "insert".into(),
            range_start: c.range.0,
            range_end: c.range.1,
            copy_offset: None,
            len,
        },
    }
}

// ---------------------------------------------------------------------------
// Incremental recomputation, resumption, deletion and branches
// ---------------------------------------------------------------------------

impl Engine {
    fn newly_affected(&self, old_node_count: usize) -> HashSet<String> {
        let mut affected: HashSet<String> = HashSet::new();
        // Every node added by this import is new.
        for n in &self.store.nodes[old_node_count..] {
            affected.insert(n.id.clone());
        }

        // Build reverse graph of recorded delta edges.
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        for (node, bases) in &self.store.edges {
            for b in bases {
                reverse.entry(b.as_str()).or_default().push(node.as_str());
            }
        }

        // Which oids did the newly added nodes start providing?
        let mut new_oids: HashSet<[u8; 20]> = HashSet::new();
        for n in &self.store.nodes[old_node_count..] {
            if let Some((_, oid)) = self.store.claimed.get(&n.id) {
                new_oids.insert(*oid);
            }
        }

        // Nodes that were missing exactly those bases, or whose default
        // candidate choice changed, plus their dependent closure.
        let mut seeds: HashSet<String> = HashSet::new();
        for n in &self.store.nodes[..old_node_count] {
            if let NodeState::Failed {
                kind: FailKind::MissingBase,
                ..
            }
            | NodeState::Paused { .. } = n.state
            {
                if let Some(hex_str) = self.store.missing_edges.get(&n.id) {
                    let mut oid = [0u8; 20];
                    if hex::decode_to_slice(hex_str, &mut oid).is_ok()
                        && new_oids.contains(&oid)
                    {
                        seeds.insert(n.id.clone());
                    }
                }
            }
            // A newly arriving candidate may re-rank duplicate-oid choices,
            // but only if this node is an unpinned ref-delta.
            if n.object_type == "ref-delta" {
                let want_hex = n.ref_base_oid.clone().unwrap_or_default();
                if self.active_pin(&want_hex).is_none() {
                    let mut oid = [0u8; 20];
                    if hex::decode_to_slice(&want_hex, &mut oid).is_ok() {
                        let cands = self.gather_candidates(&oid);
                        if let Some(current_base) =
                            self.store.edges.get(&n.id).and_then(|v| v.first())
                        {
                            if let Some((new_top, _)) = cands.first() {
                                if new_top != current_base {
                                    seeds.insert(n.id.clone());
                                }
                            }
                        } else if !cands.is_empty() {
                            seeds.insert(n.id.clone());
                        }
                    }
                }
            }
        }

        // Closure over reverse edges.
        let mut stack: Vec<String> = seeds.into_iter().chain(affected.iter().cloned()).collect();
        while let Some(id) = stack.pop() {
            if affected.insert(id.clone()) {
                if let Some(deps) = reverse.get(id.as_str()) {
                    for d in deps {
                        stack.push((*d).to_string());
                    }
                }
            }
        }
        affected
    }

    /// Retry paused chains after the budget has been raised. Only paused
    /// subgraphs (and their dependents) are reset and recomputed.
    pub fn resume(&mut self) -> u64 {
        let mut seeds: HashSet<String> = self
            .store
            .nodes
            .iter()
            .filter_map(|n| match n.state {
                NodeState::Paused { .. } => Some(n.id.clone()),
                _ => None,
            })
            .collect();
        let before = self.recomputed_nodes;
        if seeds.is_empty() {
            return 0;
        }
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        for (node, bases) in &self.store.edges {
            for b in bases {
                reverse.entry(b.as_str()).or_default().push(node.as_str());
            }
        }
        let mut stack: Vec<String> = seeds.drain().collect();
        let mut affected = HashSet::new();
        while let Some(id) = stack.pop() {
            if affected.insert(id.clone()) {
                if let Some(deps) = reverse.get(id.as_str()) {
                    for d in deps {
                        stack.push((*d).to_string());
                    }
                }
            }
        }
        self.reset_subtree(&affected);
        self.rebuild_claims();
        self.resolve_all(Some(affected));
        self.recomputed_nodes - before
    }

    /// Return ids of resolved objects that still depend on a source and would
    /// disappear if it were deleted.
    pub fn dependents_of_source(&self, source_id: &str) -> Vec<String> {
        let own: Vec<String> = self
            .store
            .nodes
            .iter()
            .filter(|n| n.source_id == source_id)
            .map(|n| n.id.clone())
            .collect();
        let own_set: HashSet<&str> = own.iter().map(|s| s.as_str()).collect();
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        for (node, bases) in &self.store.edges {
            for b in bases {
                reverse.entry(b.as_str()).or_default().push(node.as_str());
            }
        }
        let mut reachable: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = own.clone();
        while let Some(id) = stack.pop() {
            if reachable.insert(id.clone()) {
                if let Some(deps) = reverse.get(id.as_str()) {
                    for d in deps {
                        stack.push((*d).to_string());
                    }
                }
            }
        }
        let mut out: Vec<String> = reachable
            .into_iter()
            .filter(|id| !own_set.contains(id.as_str()))
            .collect();
        out.sort();
        out
    }

    /// Delete an imported source. When `force` is false and other objects still
    /// depend on it, returns Err with the dependent ids.
    pub fn delete_source(
        &mut self,
        source_id: &str,
        force: bool,
    ) -> Result<u64, (u64, Vec<String>)> {
        let dependents = self.dependents_of_source(source_id);
        if !force && !dependents.is_empty() {
            return Err((0, dependents));
        }

        let remove_nodes: HashSet<String> = self
            .store
            .nodes
            .iter()
            .filter(|n| n.source_id == source_id)
            .map(|n| n.id.clone())
            .collect();

        // Reset any external dependent subgraph (they will fail missing-base
        // or re-rank onto an alternative duplicate candidate).
        let mut affected: HashSet<String> =
            dependents.iter().cloned().collect();
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        for (node, bases) in &self.store.edges {
            for b in bases {
                reverse.entry(b.as_str()).or_default().push(node.as_str());
            }
        }
        // Extend affected with dependents of affected.
        let mut stack: Vec<String> = affected.iter().cloned().collect();
        while let Some(id) = stack.pop() {
            if remove_nodes.contains(&id) {
                continue;
            }
            if let Some(deps) = reverse.get(id.as_str()) {
                for d in deps {
                    let ds = (*d).to_string();
                    if affected.insert(ds.clone()) {
                        stack.push(ds);
                    }
                }
            }
        }
        self.reset_subtree(&affected);

        // Remove the source's nodes and all indices pointing at them.
        self.store.packs.remove(source_id);
        self.store.idxs.remove(source_id);
        self.store.looses.remove(source_id);
        for id in &remove_nodes {
            if let Some(&pos) = self.store.pos.get(id) {
                self.store.contents.remove(id);
                self.store.dynamic.remove(id);
                self.store.claimed.remove(id);
                self.store.edges.remove(id);
                self.store.missing_edges.remove(id);
                if let Some(c) = self.store.charged.remove(id) {
                    self.store.charged_total =
                        self.store.charged_total.saturating_sub(c);
                }
                let _ = pos;
            }
        }
        self.store.offset_index.retain(|(sid, _), _| sid != source_id);
        self.store.nodes.retain(|n| n.source_id != source_id);
        self.store.pos.clear();
        for (i, n) in self.store.nodes.iter().enumerate() {
            self.store.pos.insert(n.id.clone(), i);
        }
        if let Some(idx) = self.store.source_by_id.remove(source_id) {
            self.store.sources.retain(|s| s.id != source_id);
            let _ = idx;
            self.store.source_by_id.clear();
            for (i, s) in self.store.sources.iter().enumerate() {
                self.store.source_by_id.insert(s.id.clone(), i);
            }
        }
        let _ = std::fs::remove_file(self.data_dir.join("files").join(source_id));

        // Drop claims that referred to removed idx entries, then re-pair.
        self.store.claimed.retain(|node_id, _| {
            self.store.pos.contains_key(node_id)
        });
        self.reconcile_idxs();
        self.rebuild_claims();
        let before = self.recomputed_nodes;
        self.resolve_all(Some(affected));
        Ok(self.recomputed_nodes - before)
    }

    /// Pin a conflicting oid to a specific candidate node (analysis branch).
    pub fn save_branch(&mut self, name: &str, pins: BTreeMap<String, String>) {
        self.branches.insert(name.to_string(), pins);
    }

    pub fn set_branch(&mut self, name: Option<String>) -> Result<(), String> {
        if let Some(n) = &name {
            if !self.branches.contains_key(n) {
                return Err(format!("unknown branch {n}"));
            }
        }
        self.active_branch = name;
        // Full re-resolution; pins change chosen edges so any cached choice may
        // be stale.
        let ids: HashSet<String> = self.store.nodes.iter().map(|n| n.id.clone()).collect();
        self.reset_subtree(&ids);
        self.rebuild_claims();
        self.resolve_all(None);
        Ok(())
    }

    pub fn set_ephemeral_pin(&mut self, oid_hex: &str, node_id: Option<String>) {
        match node_id {
            Some(n) => {
                self.pins.insert(oid_hex.to_string(), n);
            }
            None => {
                self.pins.remove(oid_hex);
            }
        }
        let ids: HashSet<String> = self.store.nodes.iter().map(|n| n.id.clone()).collect();
        self.reset_subtree(&ids);
        self.rebuild_claims();
        self.resolve_all(None);
    }

    pub fn active_branch(&self) -> Option<&str> {
        self.active_branch.as_deref()
    }

    pub fn branches(&self) -> &BTreeMap<String, BTreeMap<String, String>> {
        &self.branches
    }
}
