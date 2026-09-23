//! Pack-chain analysis engine: graph build, budgeted delta reconstruction,
//! pause/resume, scoped recomputation and candidate reconciliation.

use crate::crc32::crc32;
use crate::db::Db;

use crate::delta::{apply_delta, CmdKind, CmdRange};
use crate::idx::{parse_idx, IdxInfo};
use crate::loose::{parse_loose, LooseObject};
use crate::oid::{content_fingerprint, object_id, Oid};
use crate::pack::{parse_pack, DeltaRef, ObjType, PackInfo};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: u32,
    pub max_bytes: u64,
    pub max_share: f64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets { max_depth: 50, max_bytes: 64 * 1024 * 1024, max_share: 0.25 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeMode {
    Full,
    Add,
    Oids,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeKey {
    pub source_fp: String,
    pub locator: String,
}

impl NodeKey {
    pub fn s(&self) -> String {
        format!("{}:{}", self.source_fp, self.locator)
    }
    pub fn parse(s: &str) -> NodeKey {
        if let Some((fp, loc)) = s.split_once(':') {
            NodeKey { source_fp: fp.to_string(), locator: loc.to_string() }
        } else {
            NodeKey { source_fp: s.to_string(), locator: String::new() }
        }
    }
}

#[derive(Debug, Clone)]
struct RawNode {
    key: NodeKey,
    source_id: i64,
    source_fp: String,
    source_kind: String,
    original_name: String,
    locator: String,
    entry_offset: Option<i64>,
    obj_type: String,
    /// Claimed git oid (from idx or filename), verified after resolution.
    claimed_oid: Option<Oid>,
    declared_size: Option<i64>,
    actual_size: Option<i64>,
    zlib_start: Option<i64>,
    zlib_end: Option<i64>,
    crc_expected: Option<i64>,
    crc_actual: Option<i64>,
    delta_type: Option<String>,
    delta_base_locator: Option<String>,
    parse_issue: Option<String>,
    /// Base content (non-delta) or delta instruction bytes.
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ReuseRecord {
    obj_type: String,
    oid: Oid,
    content: Vec<u8>,
    preview: String,
    steps: Vec<StoredStep>,
    path: Vec<NodeKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredStep {
    seq: i64,
    depth: i64,
    base_oid: Option<String>,
    base_locator: Option<String>,
    delta_type: Option<String>,
    base_size: i64,
    output_size: i64,
    cmd_count: i64,
    cmd_ranges: String,
    input_crc32: Option<i64>,
    output_sha: String,
    expected_oid: Option<String>,
    oid_match: bool,
    state: String,
}

#[derive(Debug, Clone)]
struct Resolved {
    obj_type: String,
    oid: Oid,
    content: Vec<u8>,
    /// Steps for the chain, ordered base -> tip.
    steps: Vec<Step>,
    /// Node keys of the chain, base -> tip.
    path: Vec<NodeKey>,
}

#[derive(Debug, Clone)]
struct Step {
    depth: usize,
    base_oid: Option<Oid>,
    base_locator: Option<String>,
    delta_type: Option<String>,
    base_size: usize,
    output_size: usize,
    cmds: Vec<CmdRange>,
    input_crc32: Option<u32>,
    output: Oid,
    expected: Option<Oid>,
    state: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RS {
    Resolved,
    Corrupt,
    MissingBase,
    OutOfBounds,
    Cycle,
    OidMismatch,
    Paused,
    WaitingPause,
    BadDelta,
    LooseHeader,
}

impl RS {
    fn name(self) -> &'static str {
        match self {
            RS::Resolved => "resolved",
            RS::Corrupt => "corrupt",
            RS::MissingBase => "missing_base",
            RS::OutOfBounds => "ofs_out_of_bounds",
            RS::Cycle => "cycle",
            RS::OidMismatch => "oid_mismatch",
            RS::Paused => "paused",
            RS::WaitingPause => "blocked_by_pause",
            RS::BadDelta => "bad_delta",
            RS::LooseHeader => "loose_header",
        }
    }
}

#[derive(Debug, Clone)]
enum Memo {
    Done(Resolved),
    Fail(RS, String),
    Paused {
        reason: String,
        chain_tip_to_current: Vec<NodeKey>,
    },
}

#[derive(Clone)]
pub struct Engine {
    pub db: Db,
    pub data_dir: Arc<String>,
}

impl Engine {
    pub fn clone_ref(&self) -> Engine {
        self.clone()
    }
}

fn preview_bytes(data: &[u8]) -> String {
    let n = data.len().min(400);
    match std::str::from_utf8(&data[..n]) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') => {
            s.replace('\0', "\\0")
        }
        _ => {
            let mut h = String::from("hex:");
            for b in data.iter().take(128) {
                h.push_str(&format!("{:02x}", b));
            }
            h
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyzeReport {
    pub mode: String,
    pub status: String,
    pub total_candidates: usize,
    pub resolved: usize,
    pub blocked: usize,
    pub corrupt: usize,
    pub paused: usize,
    pub recomputed: usize,
    pub reused: usize,
    pub bytes_spent: u64,
    pub max_bytes: u64,
    pub max_depth: u32,
    pub max_share: f64,
    pub message: String,
    pub issue_codes: Vec<String>,
}

impl Engine {
    pub fn new(data_dir: &str) -> rusqlite::Result<Engine> {
        std::fs::create_dir_all(format!("{}/objects", self.data_dir.as_str())).ok();
        let db = Db::open(&format!("{}/microscope.db", data_dir))?;
        Ok(Engine { db, data_dir: Arc::new(data_dir.to_string()) })
    }

    // ----- import -----------------------------------------------------------

    pub fn import_bytes(
        &self,
        filename: &str,
        data: &[u8],
    ) -> Result<(i64, String, String), String> {
        use crate::loose::detect_kind;
        let kind = detect_kind(filename, data);
        let kind_s = match kind {
            crate::loose::FileKind::Pack => "pack",
            crate::loose::FileKind::Idx => "idx",
            crate::loose::FileKind::Loose => "loose",
            crate::loose::FileKind::Unknown => {
                return Err("无法识别的文件类型（既不是 pack/idx 也不是 loose object）".into())
            }
        };
        let fp = content_fingerprint(data);
        let c = self.db.lock();
        let existing: Option<i64> = c
            .query_row(
                "SELECT id FROM sources WHERE fingerprint=?1",
                params![fp],
                |r| r.get(0),
            )
            .ok();
        if let Some(id) = existing {
            let stored: String =
                c.query_row("SELECT stored_path FROM sources WHERE id=?1", params![id], |r| {
                    r.get(0)
                }).unwrap();
            return Ok((id, kind_s.into(), stored));
        }
        let ext = match kind_s {
            "pack" => "pack",
            "idx" => "idx",
            _ => "loose",
        };
        let stored = format!("{}/{}-{}.{}", self.data_dir.as_str(), kind_s, &fp[..12], ext);
        std::fs::write(&stored, data).map_err(|e| e.to_string())?;
        let summary = match kind_s {
            "pack" => {
                let p = parse_pack(data.to_vec());
                serde_json::json!({
                    "version": p.version,
                    "count": p.count,
                    "entries_parsed": p.entries.len(),
                    "header_issue": p.header_issue,
                    "stored_trailer": p.stored_trailer.map(|o| o.hex()),
                    "computed_trailer": p.computed_trailer.map(|o| o.hex()),
                })
            }
            "idx" => {
                let idx = parse_idx(data);
                serde_json::json!({
                    "version": idx.version,
                    "count": idx.count,
                    "fanout": idx.fanout,
                    "pack_checksum": idx.pack_checksum.map(|o| o.hex()),
                    "issue": idx.issue,
                })
            }
            _ => {
                let lo = parse_loose(data);
                serde_json::json!({
                    "kind": lo.kind,
                    "declared_size": lo.declared_size,
                    "actual_size": lo.content.len(),
                    "issue": lo.issue,
                })
            }
        };
        c.execute(
            "INSERT INTO sources(kind, original_name, stored_path, fingerprint, size, parse_summary)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![kind_s, filename, stored, fp, data.len() as i64, summary.to_string()],
        )
        .map_err(|e| e.to_string())?;
        let id = c.last_insert_rowid();
        drop(c);
        self.pair_idx_sources();
        Ok((id, kind_s.into(), stored))
    }

    fn pair_idx_sources(&self) {
        let c = self.db.lock();
        let mut packs: Vec<(String, Option<Oid>, Option<Oid>)> = Vec::new();
        {
            let mut stmt = c
                .prepare("SELECT fingerprint, parse_summary FROM sources WHERE kind='pack'")
                .unwrap();
            let rows = stmt
                .query_map(params![], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .unwrap();
            for row in rows {
                let (fp, summary) = row.unwrap();
                let v: serde_json::Value = serde_json::from_str(&summary).unwrap_or_default();
                let stored = v
                    .get("stored_trailer")
                    .and_then(|x| x.as_str())
                    .and_then(Oid::parse_hex);
                let computed = v
                    .get("computed_trailer")
                    .and_then(|x| x.as_str())
                    .and_then(Oid::parse_hex);
                packs.push((fp, stored, computed));
            }
        }
        let mut stmt = c
            .prepare("SELECT id, parse_summary FROM sources WHERE kind='idx'")
            .unwrap();
        let idxs: Vec<(i64, Option<Oid>)> = stmt
            .query_map(params![], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap()
            .map(|row| {
                let (id, summary) = row.unwrap();
                let v: serde_json::Value = serde_json::from_str(&summary).unwrap_or_default();
                let checksum = v
                    .get("pack_checksum")
                    .and_then(|x| x.as_str())
                    .and_then(Oid::parse_hex);
                (id, checksum)
            })
            .collect();
        drop(stmt);
        for (id, checksum) in idxs {
            let pair = checksum.and_then(|want| {
                packs
                    .iter()
                    .find(|(_, stored, computed)| {
                        Some(want) == *stored || Some(want) == *computed
                    })
                    .map(|(fp, _, _)| fp.clone())
            });
            c.execute(
                "UPDATE sources SET paired_pack_fp=?1 WHERE id=?2",
                params![pair, id],
            )
            .ok();
        }
    }
}

// ----- run ---------------------------------------------------------------

struct Run<'a> {
    engine: &'a Engine,
    nodes: BTreeMap<NodeKey, RawNode>,
    order: Vec<NodeKey>,
    /// node -> declared base (only for delta nodes)
    base_of: HashMap<NodeKey, BaseRef>,
    memo: HashMap<NodeKey, Memo>,
    budgets: Budgets,
    bytes_spent: u64,
    recomputed: HashSet<NodeKey>,
    reused: HashSet<NodeKey>,
    snapshot: HashMap<NodeKey, ReuseRecord>,
    scope_keys: BTreeSet<NodeKey>,
    scope_mode: ScopeMode,
    scope_oids: BTreeSet<Oid>,
    pinned: HashMap<Oid, NodeKey>,
    /// node oid -> idx claim mismatches recorded during parse
    paused_chain_from_db: Vec<NodeKey>,
    saved_chain: Vec<NodeKey>,
    saved_chain_step: Option<(usize, usize)>,
    issue_codes: Vec<String>,
    cid_by_key: HashMap<NodeKey, i64>,
}

#[derive(Debug, Clone)]
enum BaseRef {
    Ofs { target_offset: u64, fp: String },
    Ref(Oid),
}

#[derive(Debug, Clone)]
struct BuiltNode {
    node: RawNode,
    base: Option<BaseRef>,
}

impl<'a> Run<'a> {
    fn new(
        engine: &'a Engine,
        budgets: Budgets,
        scope_mode: ScopeMode,
        scope_oids: BTreeSet<Oid>,
        snapshot: HashMap<NodeKey, ReuseRecord>,
        scope_keys: BTreeSet<NodeKey>,
        pinned: HashMap<Oid, NodeKey>,
        bytes_spent: u64,
        paused_chain_from_db: Vec<NodeKey>,
        saved_chain_step: Option<(usize, usize)>,
    ) -> Run<'a> {
        Run {
            engine,
            nodes: BTreeMap::new(),
            order: Vec::new(),
            base_of: HashMap::new(),
            memo: HashMap::new(),
            budgets,
            bytes_spent,
            recomputed: HashSet::new(),
            reused: HashSet::new(),
            snapshot,
            scope_keys,
            scope_mode,
            scope_oids,
            pinned,
            paused_chain_from_db,
            saved_chain: Vec::new(),
            saved_chain_step,
            issue_codes: Vec::new(),
            cid_by_key: HashMap::new(),
        }
    }

    fn in_scope(&self, k: &NodeKey) -> bool {
        match self.scope_mode {
            ScopeMode::Full => true,
            ScopeMode::Add => self.scope_keys.contains(k),
            ScopeMode::Oids => false,
        }
    }

    fn build(&mut self) {
        let c = self.engine.db.lock();
        let mut src_rows: Vec<(i64, String, String, String, String, String)> = {
            let mut stmt = c
                .prepare(
                    "SELECT id, kind, original_name, stored_path, fingerprint, parse_summary
                     FROM sources ORDER BY fingerprint, id",
                )
                .unwrap();
            stmt.query_map(params![], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };
        src_rows.sort_by(|a, b| a.4.cmp(&b.4));

        // pack entries: need offsets per pack for ofs-delta resolution
        let mut pack_entries_by_fp: BTreeMap<String, Vec<BuiltNode>> = BTreeMap::new();
        let mut loose_by_oid: HashMap<Oid, Vec<NodeKey>> = HashMap::new();
        let mut all = Vec::<BuiltNode>::new();

        for (sid, kind, name, stored, fp, summary_json) in &src_rows {
            let data = match std::fs::read(stored) {
                Ok(d) => d,
                Err(_) => continue,
            };
            match kind.as_str() {
                "pack" => {
                    let summary: serde_json::Value =
                        serde_json::from_str(summary_json).unwrap_or_default();
                    let pack = parse_pack(data);
                    let idx = self.paired_idx(&c, fp, &src_rows);
                    let idx_issues = idx.as_ref().and_then(|i| i.issue.clone());
                    if let Some(msg) = idx_issues {
                        self.record_issue(
                            "idx_checksum",
                            "error",
                            Some(*sid),
                            None,
                            msg,
                            serde_json::json!({"source": name}),
                        );
                    }
                    if let Some(msg) = &pack.header_issue {
                        self.record_issue(
                            "pack_trailer",
                            "error",
                            Some(*sid),
                            None,
                            msg.clone(),
                            serde_json::json!({
                                "stored_trailer": pack.stored_trailer.map(|o| o.hex()),
                                "computed_trailer": pack.computed_trailer.map(|o| o.hex()),
                                "version": pack.version,
                                "declared_count": pack.count,
                            }),
                        );
                    }
                    let _ = summary;
                    let mut built_vec = Vec::new();
                    for (i, e) in pack.entries.iter().enumerate() {
                        let locator = format!("pack@{}:off{}", &fp[..8], e.offset);
                        let key = NodeKey { source_fp: fp.clone(), locator: locator.clone() };
                        let idx_match = idx.as_ref().and_then(|idx| {
                            idx.entries.iter().find(|ie| ie.offset == e.offset)
                        });
                        let (crc_expected, claimed_oid) = match idx_match {
                            Some(ie) => (ie.crc32.map(|v| v as i64), Some(ie.oid)),
                            None => (None, None),
                        };
                        let crc_actual = e.computed_crc.map(|v| v as i64);
                        let (delta_type, base) = match &e.delta_ref {
                            Some(DeltaRef::Ofs { abs_offset, .. }) => (
                                Some("ofs-delta".to_string()),
                                Some(BaseRef::Ofs {
                                    target_offset: *abs_offset,
                                    fp: fp.clone(),
                                }),
                            ),
                            Some(DeltaRef::Ref(oid)) => (
                                Some("ref-delta".to_string()),
                                Some(BaseRef::Ref(*oid)),
                            ),
                            None => (None, None),
                        };
                        let node = RawNode {
                            key: key.clone(),
                            source_id: *sid,
                            source_fp: fp.clone(),
                            source_kind: "pack".into(),
                            original_name: name.clone(),
                            locator: locator.clone(),
                            entry_offset: Some(e.offset as i64),
                            obj_type: e.obj_type.name().to_string(),
                            claimed_oid,
                            declared_size: Some(e.declared_size as i64),
                            actual_size: Some(e.data.len() as i64),
                            zlib_start: Some(e.zlib_start as i64),
                            zlib_end: Some(e.zlib_end as i64),
                            crc_expected,
                            crc_actual,
                            delta_type,
                            delta_base_locator: match &e.delta_ref {
                                Some(DeltaRef::Ofs { abs_offset, .. }) => {
                                    Some(format!("offset {abs_offset}"))
                                }
                                Some(DeltaRef::Ref(o)) => Some(o.short()),
                                None => None,
                            },
                            parse_issue: e.parse_issue.clone(),
                            data: e.data.clone(),
                        };
                        built_vec.push(BuiltNode { node, base });
                        let _ = i;
                    }
                    // idx entries pointing to offsets absent in the pack
                    if let Some(idx) = &idx {
                        let present: HashSet<u64> =
                            pack.entries.iter().map(|e| e.offset).collect();
                        for ie in &idx.entries {
                            if !present.contains(&ie.offset) {
                                self.record_issue(
                                    "idx_pack_mismatch",
                                    "error",
                                    Some(*sid),
                                    None,
                                    format!(
                                        "idx claims {} at pack offset {} but pack has no object there",
                                        ie.oid.short(),
                                        ie.offset
                                    ),
                                    serde_json::json!({"oid": ie.oid.hex(), "offset": ie.offset}),
                                );
                            }
                        }
                        // pack entries absent from idx
                        let idx_offsets: HashSet<u64> =
                            idx.entries.iter().map(|e| e.offset).collect();
                        for e in &pack.entries {
                            if !idx_offsets.contains(&e.offset) {
                                self.record_issue(
                                    "idx_pack_mismatch",
                                    "warning",
                                    Some(*sid),
                                    None,
                                    format!(
                                        "pack object at offset {} is absent from paired idx",
                                        e.offset
                                    ),
                                    serde_json::json!({"offset": e.offset}),
                                );
                            }
                        }
                    }
                    pack_entries_by_fp.insert(fp.clone(), built_vec);
                }
                "loose" => {
                    let lo = parse_loose(&data);
                    let locator = format!("loose@{}", &fp[..8]);
                    let key = NodeKey { source_fp: fp.clone(), locator };
                    let computed = if lo.issue.is_none() {
                        Some(object_id(&lo.kind, &lo.content))
                    } else {
                        None
                    };
                    if let Some(msg) = &lo.issue {
                        self.record_issue(
                            "loose_header",
                            "error",
                            Some(*sid),
                            None,
                            msg.clone(),
                            serde_json::json!({"source": name}),
                        );
                    }
                    let node = RawNode {
                        key: key.clone(),
                        source_id: *sid,
                        source_fp: fp.clone(),
                        source_kind: "loose".into(),
                        original_name: name.clone(),
                        locator: key.locator.clone(),
                        entry_offset: None,
                        obj_type: if lo.kind.is_empty() { "unknown".into() } else { lo.kind.clone() },
                        claimed_oid: computed,
                        declared_size: Some(lo.declared_size as i64),
                        actual_size: Some(lo.content.len() as i64),
                        zlib_start: Some(0),
                        zlib_end: Some(data.len() as i64),
                        crc_expected: None,
                        crc_actual: None,
                        delta_type: None,
                        delta_base_locator: None,
                        parse_issue: lo.issue.clone(),
                        data: lo.content,
                    };
                    if let Some(o) = computed {
                        loose_by_oid.entry(o).or_default().push(key.clone());
                    }
                    all.push(BuiltNode { node, base: None });
                }
                _ => {}
            }
        }

        // Deterministic node order: pack by (fp, offset), loose by fp.
        let mut pack_all: Vec<BuiltNode> = pack_entries_by_fp
            .into_iter()
            .flat_map(|(_, v)| v)
            .collect();
        pack_all.sort_by(|a, b| {
            a.node
                .source_fp
                .cmp(&b.node.source_fp)
                .then(a.node.entry_offset.cmp(&b.node.entry_offset))
        });
        for bn in pack_all {
            let key = bn.node.key.clone();
            if let Some(base) = &bn.base {
                self.base_of.insert(key.clone(), base.clone());
            }
            self.nodes.insert(key.clone(), bn.node);
            self.order.push(key);
        }
        all.sort_by(|a, b| a.node.source_fp.cmp(&b.node.source_fp));
        for bn in all {
            let key = bn.node.key.clone();
            self.nodes.insert(key.clone(), bn.node);
            self.order.push(key);
        }

        // scope expansion for Add: new/changed sources plus reverse-dependents.
        if self.scope_mode == ScopeMode::Add && !self.scope_keys.is_empty() {
            let mut closure = self.scope_keys.clone();
            let mut stack: Vec<NodeKey> = closure.iter().cloned().collect();
            // Reverse edges need base resolution targets; build child lists.
            let mut children: HashMap<NodeKey, Vec<NodeKey>> = HashMap::new();
            for (child, base) in &self.base_of {
                match base {
                    BaseRef::Ofs { target_offset, fp } => {
                        if let Some(parent) = self.ofs_target(*target_offset, fp) {
                            children.entry(parent).or_default().push(child.clone());
                        }
                    }
                    BaseRef::Ref(oid) => {
                        for k in self.candidates_for_oid(*oid) {
                            children.entry(k).or_default().push(child.clone());
                        }
                    }
                }
            }
            while let Some(k) = stack.pop() {
                if let Some(kids) = children.get(&k) {
                    for kid in kids {
                        if closure.insert(kid.clone()) {
                            stack.push(kid.clone());
                        }
                    }
                }
            }
            self.scope_keys = closure;
        }
    }

    fn paired_idx(
        &self,
        c: &rusqlite::Connection,
        pack_fp: &str,
        rows: &[(i64, String, String, String, String, String)],
    ) -> Option<IdxInfo> {
        for (sid, kind, _, stored, fp, _) in rows {
            if kind != "idx" {
                continue;
            }
            let paired: Option<String> = c
                .query_row(
                    "SELECT paired_pack_fp FROM sources WHERE id=?1",
                    params![sid],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            if paired.as_deref() == Some(pack_fp) {
                if let Ok(data) = std::fs::read(stored) {
                    let idx = parse_idx(&data);
                    return Some(idx);
                }
            }
            // Also accept checksum-based pairing even if column missing.
            if paired.is_none() {
                if let Ok(data) = std::fs::read(stored) {
                    let idx = parse_idx(&data);
                    if idx.pack_checksum.map(|o| o.hex()).as_deref() == Some(pack_fp) {
                        return Some(idx);
                    }
                }
            }
            let _ = fp;
        }
        None
    }

    fn ofs_target(&self, offset: u64, fp: &str) -> Option<NodeKey> {
        self.nodes.values().find_map(|n| {
            if n.source_fp == fp && n.entry_offset == Some(offset as i64) {
                Some(n.key.clone())
            } else {
                None
            }
        })
    }

    fn candidates_for_oid(&self, oid: Oid) -> Vec<NodeKey> {
        let mut v: Vec<(NodeKey, bool)> = self
            .nodes
            .values()
            .filter(|n| n.claimed_oid == Some(oid))
            .map(|n| {
                let pinned = self.pinned.get(&oid) == Some(&n.key);
                (n.key.clone(), pinned)
            })
            .collect();
        v.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.source_fp.cmp(&b.0.source_fp))
                .then_with(|| a.0.locator.cmp(&b.0.locator))
        });
        v.into_iter().map(|(k, _)| k).collect()
    }

    fn record_issue(
        &mut self,
        code: &str,
        severity: &str,
        source_id: Option<i64>,
        candidate_id: Option<i64>,
        message: String,
        evidence: serde_json::Value,
    ) {
        if !self.issue_codes.contains(&code.to_string()) {
            self.issue_codes.push(code.to_string());
        }
        self.engine.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO issues(code, severity, source_id, candidate_id, message, evidence)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    code,
                    severity,
                    source_id,
                    candidate_id,
                    message,
                    evidence.to_string()
                ],
            )
            .ok();
    }
}

impl<'a> Run<'a> {
    fn resolve(&mut self, key: &NodeKey, chain: &mut Vec<NodeKey>) -> Memo {
        if let Some(m) = self.memo.get(key) {
            return m.clone();
        }
        if chain.iter().any(|k| k == key) {
            let cyc: Vec<String> = chain.iter().map(|k| k.s()).collect();
            return Memo::Fail(
                RS::Cycle,
                format!("delta cycle detected along: {}", cyc.join(" -> ")),
            );
        }

        // Snapshot reuse for nodes kept from a previous run (Add scope).
        if self.scope_mode == ScopeMode::Add && !self.in_scope(key) {
            if let Some(rec) = self.snapshot.get(key) {
                let steps = rec.steps.iter().map(stored_to_step).collect();
                self.reused.insert(key.clone());
                let m = Memo::Done(Resolved {
                    obj_type: rec.obj_type.clone(),
                    oid: rec.oid,
                    content: rec.content.clone(),
                    steps,
                    path: vec![key.clone()],
                });
                self.memo.insert(key.clone(), m.clone());
                return m;
            }
            // Out of scope but never resolved before: still must be evaluated,
            // without consuming this run's expansion budget.
        }

        let node = match self.nodes.get(key) {
            Some(n) => n.clone(),
            None => {
                return Memo::Fail(RS::Corrupt, "candidate vanished during analysis".into())
            }
        };

        if let Some(msg) = &node.parse_issue {
            return Memo::Fail(RS::Corrupt, msg.clone());
        }

        if node.source_kind == "loose" {
            if node.obj_type == "unknown" {
                return Memo::Fail(RS::LooseHeader, "loose object header invalid".into());
            }
            let oid = object_id(&node.obj_type, &node.data);
            let mut steps = Vec::new();
            if node.claimed_oid.map_or(true, |c| c == oid) {
                steps.push(Step {
                    depth: 0,
                    base_oid: None,
                    base_locator: None,
                    delta_type: None,
                    base_size: node.data.len(),
                    output_size: node.data.len(),
                    cmds: Vec::new(),
                    input_crc32: Some(crc32(&node.data)),
                    output: oid,
                    expected: node.claimed_oid,
                    state: "loose",
                });
                let m = Memo::Done(Resolved {
                    obj_type: node.obj_type.clone(),
                    oid,
                    content: node.data.clone(),
                    steps,
                    path: vec![key.clone()],
                });
                self.memo.insert(key.clone(), m.clone());
                return m;
            }
            return Memo::Fail(
                RS::OidMismatch,
                format!(
                    "loose object recomputed id {} disagrees with claimed {}",
                    oid.short(),
                    node.claimed_oid.unwrap().short()
                ),
            );
        }

        // Non-delta pack base object.
        let base_kind = match node.obj_type.as_str() {
            "commit" | "tree" | "blob" | "tag" => node.obj_type.clone(),
            "ofs-delta" | "ref-delta" => {
                return self.resolve_delta(&node, chain);
            }
            other => {
                return Memo::Fail(RS::Corrupt, format!("unknown pack object type {other}"));
            }
        };

        // Budget applies to reconstructed base bytes too.
        let need = node.data.len() as u64;
        if self.in_scope(key) && !self.snapshot.contains_key(key) {
            if let Some(reason) = self.check_budget(key, 0, need, &base_kind) {
                return self.mark_paused(&node, chain, reason, None);
            }
            self.bytes_spent += need;
        }
        let oid = object_id(&base_kind, &node.data);
        if let Some(claimed) = node.claimed_oid {
            if claimed != oid {
                return Memo::Fail(
                    RS::OidMismatch,
                    format!(
                        "object at {} recomputed id {} disagrees with idx claim {}",
                        node.locator,
                        oid.short(),
                        claimed.short()
                    ),
                );
            }
        }
        if let (Some(exp), Some(act)) = (node.crc_expected, node.crc_actual) {
            if exp != act {
                return Memo::Fail(
                    RS::Corrupt,
                    format!("crc32 mismatch at {}: idx expects {exp:08x} pack bytes {act:08x}", node.locator),
                );
            }
        }
        let step0 = Step {
            depth: 0,
            base_oid: None,
            base_locator: None,
            delta_type: None,
            base_size: node.data.len(),
            output_size: node.data.len(),
            cmds: Vec::new(),
            input_crc32: Some(crc32(&node.data)),
            output: oid,
            expected: node.claimed_oid,
            state: "base",
        };
        let m = Memo::Done(Resolved {
            obj_type: base_kind,
            oid,
            content: node.data.clone(),
            steps: vec![step0],
            path: vec![key.clone()],
        });
        self.memo.insert(key.clone(), m.clone());
        m
    }
}

impl<'a> Run<'a> {
    fn resolve_delta(&mut self, node: &RawNode, chain: &mut Vec<NodeKey>) -> Memo {
        let base_ref = match self.base_of.get(&node.key) {
            Some(b) => b.clone(),
            None => return Memo::Fail(RS::BadDelta, "delta node lacks base reference".into()),
        };

        // Resolve base target first.
        let base_key = match &base_ref {
            BaseRef::Ofs { target_offset, fp } => {
                match self.ofs_target(*target_offset, fp) {
                    Some(k) => k,
                    None => {
                        return Memo::Fail(
                            RS::OutOfBounds,
                            format!(
                                "{} points to pack offset {} which contains no object",
                                node.locator, target_offset
                            ),
                        );
                    }
                }
            }
            BaseRef::Ref(oid) => {
                let cands = self.candidates_for_oid(*oid);
                match cands.into_iter().next() {
                    Some(k) => k,
                    None => {
                        return Memo::Fail(
                            RS::MissingBase,
                            format!(
                                "{} requires external base {} which is absent from all sources",
                                node.locator,
                                oid.short()
                            ),
                        );
                    }
                }
            }
        };

        chain.push(node.key.clone());
        if chain.iter().filter(|k| **k == base_key).count() > 0 {
            chain.pop();
            return Memo::Fail(
                RS::Cycle,
                format!(
                    "delta cycle: {} -> {}",
                    node.locator,
                    self.nodes.get(&base_key).map(|n| n.locator.as_str()).unwrap_or("?")
                ),
            );
        }
        let base_memo = self.resolve(&base_key, chain);
        chain.pop();
        let base_res = match &base_memo {
            Memo::Done(r) => r.clone(),
            Memo::Fail(rs, msg) => {
                return Memo::Fail(
                    *rs,
                    format!("base {} blocked ({}): {msg}", base_key.locator, rs.name()),
                );
            }
            Memo::Paused { reason, .. } => {
                return Memo::Fail(RS::WaitingPause, format!("base paused: {reason}"));
            }
        };

        let mut steps = base_res.steps.clone();
        let next_depth = steps.len();
        if (next_depth as u32) >= self.budgets.max_depth {
            let reason = format!(
                "delta depth budget reached: chain length {} >= max_depth {}",
                next_depth, self.budgets.max_depth
            );
            return self.mark_paused(
                node,
                chain,
                reason,
                Some(PausedProg {
                    chain: self.chain_for(&node.key, &base_res),
                    step_index: steps.len(),
                }),
            );
        }

        let mut output = base_res.content.clone();
        let start_step_index = steps.len();
        let input_crc = crc32(&node.data);
        let (rebuilt, cmds) = match apply_delta(&output, &node.data) {
            Ok(v) => v,
            Err(e) => {
                return Memo::Fail(RS::BadDelta, format!("{}: {e}", node.locator));
            }
        };
        output = rebuilt;

        let output_oid = object_id(&base_res.obj_type, &output);
        let expected = node.claimed_oid;

        // Charge the produced bytes before recording success.
        if self.in_scope(&node.key) && !self.snapshot.contains_key(&node.key) {
            if let Some(reason) =
                self.check_budget(&node.key, next_depth as u32, output.len() as u64, &base_res.obj_type)
            {
                steps.push(Step {
                    depth: next_depth,
                    base_oid: Some(base_res.oid),
                    base_locator: Some(base_key.locator.clone()),
                    delta_type: node.delta_type.clone(),
                    base_size: base_res.content.len(),
                    output_size: output.len(),
                    cmds: cmds.clone(),
                    input_crc32: Some(input_crc),
                    output: output_oid,
                    expected,
                    state: "paused",
                });
                return self.mark_paused(
                    node,
                    chain,
                    reason,
                    Some(PausedProg {
                        chain: self.chain_from_steps(&node.key, &base_key, &base_res),
                        step_index: start_step_index,
                    }),
                );
            }
            self.bytes_spent += output.len() as u64;
        }

        if let Some(want) = expected {
            if want != output_oid {
                return Memo::Fail(
                    RS::OidMismatch,
                    format!(
                        "reconstructed {} has id {} but idx claims {}",
                        node.locator,
                        output_oid.short(),
                        want.short()
                    ),
                );
            }
        }
        if let (Some(exp), Some(act)) = (node.crc_expected, node.crc_actual) {
            if exp != act {
                return Memo::Fail(
                    RS::Corrupt,
                    format!("crc32 mismatch at {}: idx expects {exp:08x} pack {act:08x}", node.locator),
                );
            }
        }

        steps.push(Step {
            depth: next_depth,
            base_oid: Some(base_res.oid),
            base_locator: Some(base_key.locator.clone()),
            delta_type: node.delta_type.clone(),
            base_size: base_res.content.len(),
            output_size: output.len(),
            cmds,
            input_crc32: Some(input_crc),
            output: output_oid,
            expected,
            state: "applied",
        });

        let mut path = base_res.path.clone();
        path.push(node.key.clone());
        let m = Memo::Done(Resolved {
            obj_type: base_res.obj_type.clone(),
            oid: output_oid,
            content: output,
            steps,
            path,
        });
        self.memo.insert(node.key.clone(), m.clone());
        m
    }

    fn chain_for(&self, tip: &NodeKey, base_res: &Resolved) -> Vec<NodeKey> {
        let mut v = base_res.path.clone();
        if !v.contains(tip) {
            v.push(tip.clone());
        }
        v
    }

    fn check_budget(
        &self,
        key: &NodeKey,
        depth: u32,
        need: u64,
        obj_type: &str,
    ) -> Option<String> {
        let _ = (key, obj_type);
        if depth >= self.budgets.max_depth {
            return Some(format!(
                "max depth {} reached", self.budgets.max_depth
            ));
        }
        if self.bytes_spent + need > self.budgets.max_bytes {
            return Some(format!(
                "total expansion budget {} bytes exhausted: {} spent, {need} needed",
                self.budgets.max_bytes, self.bytes_spent
            ));
        }
        let per_obj_cap = (self.budgets.max_bytes as f64 * self.budgets.max_share) as u64;
        if need > per_obj_cap.max(1) {
            return Some(format!(
                "single object needs {need} bytes, exceeding share cap {} ({}% of {})",
                per_obj_cap,
                self.budgets.max_share * 100.0,
                self.budgets.max_bytes
            ));
        }
        None
    }

    fn mark_paused(
        &mut self,
        node: &RawNode,
        chain: &mut Vec<NodeKey>,
        reason: String,
        prog: Option<PausedProg>,
    ) -> Memo {
        let mut ids: Vec<NodeKey> = chain.clone();
        if !ids.contains(&node.key) {
            ids.push(node.key.clone());
        }
        if let Some(p) = prog {
            let mut merged = p.chain;
            for k in ids {
                if !merged.contains(&k) {
                    merged.push(k);
                }
            }
            self.saved_chain = merged;
            self.saved_chain_step = Some((p.step_index, 0));
        } else {
            self.saved_chain = ids;
        }
        Memo::Paused { reason, chain_tip_to_current: Vec::new() }
    }
}

struct PausedProg {
    chain: Vec<NodeKey>,
    step_index: usize,
}

// ----- public analyze -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    status: String,
    max_depth: u32,
    max_bytes: u64,
    max_share: f64,
    bytes_spent: u64,
    scope: Vec<String>,
    paused_chain: Vec<String>,
    message: String,
}

impl Engine {
    pub fn analyze(
        &self,
        mode: ScopeMode,
        budgets_override: Option<Budgets>,
        continue_run: bool,
    ) -> AnalyzeReport {
        let budgets = budgets_override.unwrap_or_default();
        let c = self.db.lock();
        let prev: Option<PersistedState> = c
            .query_row(
                "SELECT status,max_depth,max_bytes,max_share,bytes_spent,scope,paused_chain,message
                 FROM analysis_state WHERE id=1",
                params![],
                |r| {
                    Ok(PersistedState {
                        status: r.get(0)?,
                        max_depth: r.get(1)?,
                        max_bytes: r.get(2)?,
                        max_share: r.get(3)?,
                        bytes_spent: r.get::<_, i64>(4)? as u64,
                        scope: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                        paused_chain: serde_json::from_str(&r.get::<_, String>(6)?)
                            .unwrap_or_default(),
                        message: r.get(7)?,
                    })
                },
            )
            .ok();
        drop(c);

        let (scope_mode, bytes_start, seed_scope, paused_seed) = if continue_run {
            match &prev {
                Some(p) if p.status == "paused" => {
                    let scope: BTreeSet<NodeKey> =
                        p.scope.iter().map(|s| NodeKey::parse(s)).collect();
                    let chain: Vec<NodeKey> =
                        p.paused_chain.iter().map(|s| NodeKey::parse(s)).collect();
                    (
                        ScopeMode::Add,
                        p.bytes_spent,
                        scope,
                        chain,
                    )
                }
                _ => {
                    return self.report_only(budgets, "没有可恢复的暂停分析".into());
                }
            }
        } else {
            match mode {
                ScopeMode::Full => (ScopeMode::Full, 0, BTreeSet::new(), Vec::new()),
                ScopeMode::Add => {
                    // Scoped run after import: seed scope is built inside Run
                    // from sources not present in the previous objects snapshot;
                    // we approximate via candidates lacking resolved rows.
                    (ScopeMode::Add, 0, BTreeSet::new(), Vec::new())
                }
                ScopeMode::Oids => (ScopeMode::Oids, 0, BTreeSet::new(), Vec::new()),
            }
        };

        // Pins.
        let pins: HashMap<Oid, NodeKey> = {
            let c = self.db.lock();
            let mut stmt = c.prepare("SELECT oid, source_id, locator FROM pins").unwrap();
            stmt.query_map(params![], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .map(|(oid_s, sid, locator)| {
                let fp: String = self
                    .db
                    .0
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT fingerprint FROM sources WHERE id=?1",
                        params![sid],
                        |r| r.get(0),
                    )
                    .unwrap_or_default();
                (Oid::parse_hex(&oid_s).unwrap(), NodeKey { source_fp: fp, locator })
            })
            .collect()
        };

        // Snapshot prior derived rows for reuse (used by Add scoped runs).
        let snapshot = if scope_mode == ScopeMode::Add && !continue_run {
            self.snapshot_all()
        } else {
            HashMap::new()
        };

        // Clear derived tables. On full runs everything is recomputed.
        {
            let c = self.db.lock();
            c.execute_batch(
                "DELETE FROM delta_steps;
                 DELETE FROM edges;
                 DELETE FROM issues;
                 DELETE FROM candidates;
                 DELETE FROM objects;",
            )
            .ok();
        }

        let mut run = Run::new(
            self,
            if continue_run {
                prev.as_ref().map(|p| Budgets {
                    max_depth: p.max_depth,
                    max_bytes: budgets.max_bytes,
                    max_share: p.max_share,
                })
            } else {
                None
            }
            .unwrap_or(budgets),
            scope_mode,
            BTreeSet::new(),
            snapshot,
            seed_scope,
            pins,
            bytes_start,
            paused_seed,
            None,
        );
        run.build();

        // For a fresh Add run, seed scope = nodes whose key is absent from
        // snapshot, expanded to reverse dependents (done in build()).
        if scope_mode == ScopeMode::Add && !continue_run && run.scope_keys.is_empty() {
            let seed: BTreeSet<NodeKey> = run
                .nodes
                .keys()
                .filter(|k| !run.snapshot.contains_key(k))
                .cloned()
                .collect();
            run.scope_keys = seed;
            run.expand_scope_to_dependents();
        }

        let order = run.order.clone();
        let mut results: Vec<(NodeKey, Memo)> = Vec::new();
        for k in &order {
            let mut chain = Vec::new();
            let m = run.resolve(k, &mut chain);
            results.push((k.clone(), m));
        }

        let report = run.reconcile(results, prev.clone().map(|p| (p.status, p.message)));
        report
    }

    fn report_only(&self, budgets: Budgets, message: String) -> AnalyzeReport {
        let c = self.db.lock();
        let (resolved, blocked, corrupt, paused, total): (i64, i64, i64, i64, i64) = c
            .query_row(
                "SELECT
                   SUM(status='resolved'),
                   SUM(status IN ('missing_base','ofs_out_of_bounds','cycle','blocked_by_pause')),
                   SUM(status IN ('corrupt','bad_delta','oid_mismatch','loose_header')),
                   SUM(status='paused'),
                   COUNT(*)
                 FROM candidates",
                params![],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap_or((0, 0, 0, 0, 0));
        AnalyzeReport {
            mode: "resume".into(),
            status: "idle".into(),
            total_candidates: total as usize,
            resolved: resolved as usize,
            blocked: blocked as usize,
            corrupt: corrupt as usize,
            paused: paused as usize,
            recomputed: 0,
            reused: 0,
            bytes_spent: 0,
            max_bytes: budgets.max_bytes,
            max_depth: budgets.max_depth,
            max_share: budgets.max_share,
            message,
            issue_codes: Vec::new(),
        }
    }

    fn snapshot_all(&self) -> HashMap<NodeKey, ReuseRecord> {
        let c = self.db.lock();
        let mut out = HashMap::new();
        let mut stmt = c
            .prepare(
                "SELECT ca.source_id, ca.locator, ca.resolution_oid, ca.resolved_type,
                        ca.resolved_size, s.fingerprint
                 FROM candidates ca JOIN sources s ON s.id=ca.source_id
                 WHERE ca.status='resolved'",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (_, locator, oid_s, typ, size, fp) = row.unwrap();
            let oid = match Oid::parse_hex(&oid_s) {
                Some(o) => o,
                None => continue,
            };
            let (content_path,): (String,) = c
                .query_row(
                    "SELECT content_path FROM objects WHERE oid=?1",
                    params![oid_s],
                    |r| Ok((r.get(0)?,)),
                )
                .unwrap_or_default();
            let content = std::fs::read(&content_path).unwrap_or_default();
            let mut steps_stmt = c
                .prepare(
                    "SELECT seq,depth,base_oid,base_locator,delta_type,base_size,output_size,
                            cmd_count,cmd_ranges,input_crc32,output_sha,expected_oid,oid_match,state
                     FROM delta_steps WHERE candidate_id IN (
                        SELECT id FROM candidates WHERE locator=?1
                     ) ORDER BY seq",
                )
                .unwrap();
            let steps: Vec<StoredStep> = steps_stmt
                .query_map(params![locator], |r| {
                    Ok(StoredStep {
                        seq: r.get(0)?,
                        depth: r.get(1)?,
                        base_oid: r.get(2)?,
                        base_locator: r.get(3)?,
                        delta_type: r.get(4)?,
                        base_size: r.get(5)?,
                        output_size: r.get(6)?,
                        cmd_count: r.get(7)?,
                        cmd_ranges: r.get(8)?,
                        input_crc32: r.get(9)?,
                        output_sha: r.get(10)?,
                        expected_oid: r.get(11)?,
                        oid_match: r.get::<_, i64>(12)? != 0,
                        state: r.get(13)?,
                    })
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            let path = rebuild_path(&steps, &locator);
            let key = NodeKey { source_fp: fp, locator };
            let _ = size;
            out.insert(
                key,
                ReuseRecord {
                    obj_type: typ,
                    oid,
                    content,
                    preview: String::new(),
                    steps,
                    path,
                },
            );
        }
        out
    }
}

fn rebuild_path(steps: &[StoredStep], tip_locator: &str) -> Vec<NodeKey> {
    let mut path = Vec::new();
    if let Some(first) = steps.first() {
        if let Some(loc) = &first.base_locator {
            path.push(NodeKey::parse(loc));
        }
    }
    for s in steps {
        if let Some(loc) = &s.base_locator {
            let k = NodeKey::parse(loc);
            if !path.contains(&k) {
                path.push(k);
            }
        }
    }
    let tip = NodeKey::parse(tip_locator);
    if !path.contains(&tip) {
        path.push(tip);
    }
    path
}

fn stored_to_step(s: &StoredStep) -> Step {
    let cmds: Vec<CmdRange> = serde_json::from_str(&s.cmd_ranges).unwrap_or_default();
    Step {
        depth: s.depth as usize,
        base_oid: s.base_oid.as_deref().and_then(Oid::parse_hex),
        base_locator: s.base_locator.clone(),
        delta_type: s.delta_type.clone(),
        base_size: s.base_size as usize,
        output_size: s.output_size as usize,
        cmds,
        input_crc32: s.input_crc32.map(|v| v as u32),
        output: Oid::parse_hex(&s.output_sha).unwrap_or(Oid::zero()),
        expected: s.expected_oid.as_deref().and_then(Oid::parse_hex),
        state: "applied",
    }
}

impl<'a> Run<'a> {
    fn expand_scope_to_dependents(&mut self) {
        let mut children: HashMap<NodeKey, Vec<NodeKey>> = HashMap::new();
        for (child, base) in &self.base_of {
            match base {
                BaseRef::Ofs { target_offset, fp } => {
                    if let Some(parent) = self.ofs_target(*target_offset, fp) {
                        children.entry(parent).or_default().push(child.clone());
                    }
                }
                BaseRef::Ref(oid) => {
                    for k in self.candidates_for_oid(*oid) {
                        children.entry(k).or_default().push(child.clone());
                    }
                }
            }
        }
        let mut stack: Vec<NodeKey> = self.scope_keys.iter().cloned().collect();
        while let Some(k) = stack.pop() {
            if let Some(kids) = children.get(&k) {
                for kid in kids {
                    if self.scope_keys.insert(kid.clone()) {
                        stack.push(kid.clone());
                    }
                }
            }
        }
    }

    fn reconcile(
        &mut self,
        results: Vec<(NodeKey, Memo)>,
        prev: Option<(String, String)>,
    ) -> AnalyzeReport {
        let mut resolved_set: HashMap<Oid, Vec<(NodeKey, Resolved)>> = HashMap::new();
        let mut counters = Counters::default();
        let mut blocked_rows: Vec<(NodeKey, RS, String)> = Vec::new();
        let mut paused_rows: Vec<(NodeKey, String)> = Vec::new();
        let mut any_pause_msg: Option<String> = None;

        for (k, memo) in &results {
            match memo {
                Memo::Done(r) => {
                    resolved_set.entry(r.oid).or_default().push((k.clone(), r.clone()));
                }
                Memo::Fail(rs, msg) => {
                    use RS::*;
                    match rs {
                        MissingBase | OutOfBounds | Cycle | WaitingPause => {
                            blocked_rows.push((k.clone(), *rs, msg.clone()))
                        }
                        _ => blocked_rows.push((k.clone(), *rs, msg.clone())),
                    }
                }
                Memo::Paused { reason, .. } => {
                    paused_rows.push((k.clone(), reason.clone()));
                    any_pause_msg.get_or_insert_with(|| reason.clone());
                }
            }
        }

        // Pick one candidate per oid, honoring pins then deterministic order.
        let mut picked: HashMap<NodeKey, Oid> = HashMap::new();
        let mut picked_by_oid: HashMap<Oid, NodeKey> = HashMap::new();
        let mut oid_groups: Vec<(Oid, Vec<(NodeKey, Resolved)>)> =
            resolved_set.into_iter().collect();
        oid_groups.sort_by(|a, b| a.0.cmp(&b.0));
        for (oid, mut group) in oid_groups {
            group.sort_by(|a, b| {
                let pa = self.pinned.get(&oid) == Some(&a.0);
                let pb = self.pinned.get(&oid) == Some(&b.0);
                pb.cmp(&pa)
                    .then_with(|| a.0.source_fp.cmp(&b.0.source_fp))
                    .then_with(|| a.0.locator.cmp(&b.0.locator))
            });
            let (winner_key, winner_res) = group[0].clone();
            picked.insert(winner_key.clone(), oid);
            picked_by_oid.insert(oid, winner_key.clone());
            if group.len() > 1 {
                for (k, _) in &group[1..] {
                    let _ = k;
                }
                self.record_issue(
                    "duplicate_oid",
                    "warning",
                    None,
                    None,
                    format!(
                        "oid {} has {} candidate sources; picked {}{}",
                        oid.short(),
                        group.len(),
                        winner_key.locator,
                        if self.pinned.get(&oid).is_some() { " (pinned)" } else { "" }
                    ),
                    serde_json::json!({
                        "oid": oid.hex(),
                        "candidates": group.iter().map(|(k,_)| k.s()).collect::<Vec<_>>(),
                        "picked": winner_key.s(),
                    }),
                );
            }
            let _ = winner_res;
        }
        counters.total = results.len();
        counters.resolved = picked.len();
        counters.blocked = blocked_rows
            .iter()
            .filter(|(_, rs, _)| {
                matches!(rs, RS::MissingBase | RS::OutOfBounds | RS::Cycle | RS::WaitingPause)
            })
            .count();
        counters.corrupt = blocked_rows
            .iter()
            .filter(|(_, rs, _)| {
                !matches!(rs, RS::MissingBase | RS::OutOfBounds | RS::Cycle | RS::WaitingPause)
            })
            .count();
        counters.paused = paused_rows.len();

        self.write_candidates(&results, &picked, &blocked_rows, &paused_rows);
        self.write_edges();
        self.write_steps(&results, &picked);
        self.write_objects(&results, &picked);
        self.write_block_chains(&blocked_rows, &paused_rows, &picked_by_oid);
        self.persist_state(&counters, &paused_rows, any_pause_msg, prev);

        let status = if paused_rows.is_empty() { "complete" } else { "paused" };
        let message = if paused_rows.is_empty() {
            format!(
                "分析完成：{} 已还原，{} 阻塞，{} 损坏，{} 重复/告警",
                counters.resolved,
                counters.blocked,
                counters.corrupt,
                self.issue_codes.iter().filter(|c| **c == "duplicate_oid").count()
            )
        } else {
            any_pause_msg.unwrap_or_default()
        };
        AnalyzeReport {
            mode: match self.scope_mode {
                ScopeMode::Full => "full".into(),
                ScopeMode::Add => "scoped".into(),
                ScopeMode::Oids => "oids".into(),
            },
            status: status.into(),
            total_candidates: counters.total,
            resolved: counters.resolved,
            blocked: counters.blocked,
            corrupt: counters.corrupt,
            paused: counters.paused,
            recomputed: results
                .iter()
                .filter(|(k, _)| {
                    let in_scope = self.in_scope(k) || self.scope_mode == ScopeMode::Full;
                    in_scope
                        && matches!(self.memo.get(k), Some(Memo::Done(_)))
                        && !self.reused.contains(k)
                })
                .count(),
            reused: self.reused.len(),
            bytes_spent: self.bytes_spent,
            max_bytes: self.budgets.max_bytes,
            max_depth: self.budgets.max_depth,
            max_share: self.budgets.max_share,
            message,
            issue_codes: self.issue_codes.clone(),
        }
    }
}

#[derive(Default)]
struct Counters {
    total: usize,
    resolved: usize,
    blocked: usize,
    corrupt: usize,
    paused: usize,
}

impl<'a> Run<'a> {
    fn write_candidates(
        &mut self,
        results: &[(NodeKey, Memo)],
        picked: &HashMap<NodeKey, Oid>,
        blocked_rows: &[(NodeKey, RS, String)],
        paused_rows: &[(NodeKey, String)],
    ) {
        let c = self.engine.db.lock();
        for (k, memo) in results {
            let node = match self.nodes.get(k) {
                Some(n) => n,
                None => continue,
            };
            let (status, res_oid, res_type, res_size, preview, block_reason) = match memo {
                Memo::Done(r) => (
                    "resolved".to_string(),
                    Some(r.oid.hex()),
                    Some(r.obj_type.clone()),
                    Some(r.content.len() as i64),
                    Some(preview_bytes(&r.content)),
                    if picked.get(k) == Some(&r.oid) {
                        None
                    } else {
                        Some("duplicate_oid_alternate".to_string())
                    },
                ),
                Memo::Fail(rs, msg) => (
                    rs.name().to_string(),
                    None,
                    None,
                    None,
                    None,
                    Some(msg.clone()),
                ),
                Memo::Paused { reason, .. } => {
                    ("paused".to_string(), None, None, None, None, Some(reason.clone()))
                }
            };
            let duplicate = matches!(memo, Memo::Done(r)) && picked.get(k) != Some(&match memo {
                Memo::Done(r) => r.oid,
                _ => Oid::zero(),
            });
            let final_status = if matches!(memo, Memo::Done(_)) && duplicate {
                "duplicate_alternate".to_string()
            } else {
                status
            };
            c.execute(
                "INSERT INTO candidates(
                    source_id, locator, entry_offset, obj_type, oid, declared_size, actual_size,
                    zlib_start, zlib_end, crc_expected, crc_actual, delta_type,
                    delta_base_locator, parse_issue, status, resolution_oid, resolved_type,
                    resolved_size, resolved_preview, block_reason)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    node.source_id,
                    node.locator,
                    node.entry_offset,
                    node.obj_type,
                    node.claimed_oid.map(|o| o.hex()),
                    node.declared_size,
                    node.actual_size,
                    node.zlib_start,
                    node.zlib_end,
                    node.crc_expected,
                    node.crc_actual,
                    node.delta_type,
                    node.delta_base_locator,
                    node.parse_issue,
                    final_status,
                    res_oid,
                    res_type,
                    res_size,
                    preview,
                    block_reason,
                ],
            )
            .unwrap();
            let id = c.last_insert_rowid();
            self.cid_by_key.insert(k.clone(), id);
        }
        let _ = (blocked_rows, paused_rows);
    }

    fn write_edges(&mut self) {
        let c = self.engine.db.lock();
        for (child, base) in &self.base_of {
            let child_id = self.cid_by_key.get(child).copied();
            let (parent_id, parent_oid, kind) = match base {
                BaseRef::Ofs { target_offset, fp } => {
                    let pk = self.ofs_target(*target_offset, fp);
                    let pid = pk.as_ref().and_then(|k| self.cid_by_key.get(k)).copied();
                    let oid = pk.and_then(|k| {
                        self.memo.get(&k).and_then(|m| match m {
                            Memo::Done(r) => Some(r.oid.hex()),
                            _ => None,
                        })
                    });
                    (pid, oid, "ofs-delta")
                }
                BaseRef::Ref(oid) => {
                    let pk = self.candidates_for_oid(*oid).into_iter().next();
                    let pid = pk.as_ref().and_then(|k| self.cid_by_key.get(k)).copied();
                    (pid, Some(oid.hex()), "ref-delta")
                }
            };
            if let Some(cid) = child_id {
                c.execute(
                    "INSERT INTO edges(child_id, parent_id, parent_oid, kind)
                     VALUES (?1,?2,?3,?4)",
                    params![cid, parent_id, parent_oid, kind],
                )
                .ok();
            }
        }
    }
}

impl<'a> Run<'a> {
    fn write_steps(&mut self, results: &[(NodeKey, Memo)], picked: &HashMap<NodeKey, Oid>) {
        let c = self.engine.db.lock();
        for (k, memo) in results {
            let cid = match self.cid_by_key.get(k) {
                Some(id) => *id,
                None => continue,
            };
            if let Memo::Done(r) = memo {
                let is_picked = picked.get(k) == Some(&r.oid);
                if !is_picked {
                    continue;
                }
                for (i, st) in r.steps.iter().enumerate() {
                    let ranges: Vec<serde_json::Value> = st
                        .cmds
                        .iter()
                        .map(|cm| {
                            serde_json::json!({
                                "index": cm.index,
                                "opcode_offset": cm.opcode_offset,
                                "raw_len": cm.raw_len,
                                "dst_offset": cm.dst_offset,
                                "dst_len": cm.dst_len,
                                "kind": match &cm.kind {
                                    CmdKind::Copy { src_offset, src_len } => serde_json::json!({
                                        "op": "copy", "src_offset": src_offset, "src_len": src_len
                                    }),
                                    CmdKind::Insert { src_len } => serde_json::json!({
                                        "op": "insert", "src_len": src_len
                                    }),
                                }
                            })
                        })
                        .collect();
                    let ranges_s = serde_json::to_string(&ranges).unwrap();
                    let oid_match = st.expected.map(|e| e == st.output);
                    c.execute(
                        "INSERT INTO delta_steps(candidate_id, seq, depth, base_oid, base_locator,
                            delta_type, base_size, output_size, cmd_count, cmd_ranges,
                            input_crc32, output_sha, expected_oid, oid_match, state)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                        params![
                            cid,
                            i as i64,
                            st.depth as i64,
                            st.base_oid.map(|o| o.hex()),
                            st.base_locator,
                            st.delta_type,
                            st.base_size as i64,
                            st.output_size as i64,
                            st.cmds.len() as i64,
                            ranges_s,
                            st.input_crc32.map(|v| v as i64),
                            st.output.hex(),
                            st.expected.map(|o| o.hex()),
                            oid_match.map(|b| b as i64),
                            st.state,
                        ],
                    )
                    .ok();
                }
            }
        }
    }

    fn write_objects(&mut self, results: &[(NodeKey, Memo)], picked: &HashMap<NodeKey, Oid>) {
        let c = self.engine.db.lock();
        for (k, memo) in results {
            if let Memo::Done(r) = memo {
                if picked.get(k) != Some(&r.oid) {
                    continue;
                }
                let cid = self.cid_by_key.get(k).copied();
                let path = format!("{}/objects/{}", self.engine.data_dir.as_str(), r.oid.hex());
                if !std::path::Path::new(&path).exists() {
                    std::fs::write(&path, &r.content).ok();
                }
                c.execute(
                    "INSERT OR REPLACE INTO objects(oid, obj_type, size, preview, content_path, picked_candidate_id)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        r.oid.hex(),
                        r.obj_type,
                        r.content.len() as i64,
                        preview_bytes(&r.content),
                        path,
                        cid
                    ],
                )
                .ok();
            }
        }
    }
}

impl<'a> Run<'a> {
    fn write_block_chains(
        &mut self,
        blocked_rows: &[(NodeKey, RS, String)],
        paused_rows: &[(NodeKey, String)],
        picked_by_oid: &HashMap<Oid, NodeKey>,
    ) {
        for (k, rs, msg) in blocked_rows {
            let cid = self.cid_by_key.get(k).copied();
            let chain = self.blocked_chain(k, picked_by_oid);
            let evidence = serde_json::json!({
                "candidate": k.s(),
                "status": rs.name(),
                "chain": chain,
            });
            let code = match rs {
                RS::MissingBase => "missing_base",
                RS::OutOfBounds => "ofs_out_of_bounds",
                RS::Cycle => "cycle",
                RS::WaitingPause => "blocked_by_pause",
                RS::OidMismatch => "oid_mismatch",
                RS::BadDelta => "bad_delta",
                RS::Corrupt => "corrupt_object",
                RS::LooseHeader => "loose_header",
                RS::Paused => "budget_pause",
            };
            self.record_issue(
                code,
                match rs {
                    RS::MissingBase | RS::WaitingPause => "warning",
                    _ => "error",
                },
                self.nodes.get(k).map(|n| n.source_id),
                cid,
                msg.clone(),
                evidence,
            );
        }
        for (k, reason) in paused_rows {
            let cid = self.cid_by_key.get(k).copied();
            let chain = self.paused_chain_labels(k);
            self.record_issue(
                "budget_pause",
                "warning",
                self.nodes.get(k).map(|n| n.source_id),
                cid,
                reason.clone(),
                serde_json::json!({"candidate": k.s(), "chain": chain, "retryable": true}),
            );
        }
    }

    fn blocked_chain(&self, k: &NodeKey, picked: &HashMap<Oid, NodeKey>) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = k.clone();
        let mut guard = 0usize;
        let mut seen = HashSet::new();
        loop {
            guard += 1;
            if guard > 200 || !seen.insert(cur.clone()) {
                out.push(format!("{} (cycle/guard)", cur.locator));
                break;
            }
            out.push(cur.s());
            match self.base_of.get(&cur) {
                Some(BaseRef::Ofs { target_offset, fp }) => {
                    match self.ofs_target(*target_offset, fp) {
                        Some(nk) => cur = nk,
                        None => {
                            out.push(format!("<missing offset {target_offset} in pack {}>", &fp[..8]));
                            break;
                        }
                    }
                }
                Some(BaseRef::Ref(oid)) => match self.candidates_for_oid(*oid).into_iter().next() {
                    Some(nk) => cur = nk,
                    None => {
                        out.push(format!("<missing external base {}>", oid.short()));
                        break;
                    }
                },
                None => break,
            }
        }
        let _ = picked;
        out
    }

    fn paused_chain_labels(&self, k: &NodeKey) -> Vec<String> {
        // Prefer the chain captured during the triggering resolution.
        if !self.saved_chain.is_empty() && self.saved_chain.iter().any(|c| c == k) {
            return self.saved_chain.iter().map(|c| c.s()).collect();
        }
        self.blocked_chain(k, &HashMap::new())
    }

    fn persist_state(
        &mut self,
        counters: &Counters,
        paused_rows: &[(NodeKey, String)],
        pause_msg: Option<String>,
        prev: Option<(String, String)>,
    ) {
        let status = if paused_rows.is_empty() { "complete" } else { "paused" };
        let scope: Vec<String> = self.scope_keys.iter().map(|k| k.s()).collect();
        let chain: Vec<String> = self.saved_chain.iter().map(|k| k.s()).collect();
        let message = pause_msg.unwrap_or_else(|| {
            prev.map(|(_, m)| m)
                .unwrap_or_else(|| "analysis complete".into())
        });
        let c = self.engine.db.lock();
        c.execute(
            "INSERT INTO analysis_state(id,status,max_depth,max_bytes,max_share,bytes_spent,scope,paused_chain,message)
             VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET
               status=excluded.status, max_depth=excluded.max_depth,
               max_bytes=excluded.max_bytes, max_share=excluded.max_share,
               bytes_spent=excluded.bytes_spent, scope=excluded.scope,
               paused_chain=excluded.paused_chain, message=excluded.message,
               updated_at=strftime('%s','now')",
            params![
                status,
                self.budgets.max_depth,
                self.budgets.max_bytes as i64,
                self.budgets.max_share,
                self.bytes_spent as i64,
                serde_json::to_string(&scope).unwrap(),
                serde_json::to_string(&chain).unwrap(),
                message,
            ],
        )
        .ok();
        let _ = counters;
    }
}

// ----- pins / deletion / queries ------------------------------------------

impl Engine {
    pub fn set_pin(&self, oid: Oid, source_id: i64, locator: &str, note: &str) -> Result<(), String> {
        let c = self.db.lock();
        let fp: String = c
            .query_row("SELECT fingerprint FROM sources WHERE id=?1", params![source_id], |r| {
                r.get(0)
            })
            .map_err(|_| "source not found".to_string())?;
        let key = NodeKey { source_fp: fp, locator: locator.to_string() };
        let exists: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE source_id=?1 AND locator=?2 AND resolution_oid=?3",
                params![source_id, locator, oid.hex()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            return Err("该候选当前没有还原为指定 oid，无法固定".into());
        }
        c.execute(
            "INSERT INTO pins(oid, source_id, locator, note) VALUES (?1,?2,?3,?4)
             ON CONFLICT(oid) DO UPDATE SET source_id=excluded.source_id,
               locator=excluded.locator, note=excluded.note",
            params![oid.hex(), source_id, key.locator, note],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn unpin(&self, oid: &Oid) -> Result<(), String> {
        let c = self.db.lock();
        let n = c
            .execute("DELETE FROM pins WHERE oid=?1", params![oid.hex()])
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("该 oid 未被固定".into());
        }
        Ok(())
    }

    /// Objects currently resolved through a candidate from this source.
    pub fn source_dependents(&self, source_id: i64) -> Vec<serde_json::Value> {
        let c = self.db.lock();
        let mut stmt = c
            .prepare(
                "SELECT locator, resolution_oid, resolved_type, resolved_size, status
                 FROM candidates WHERE source_id=?1 AND resolution_oid IS NOT NULL
                 ORDER BY locator",
            )
            .unwrap();
        stmt.query_map(params![source_id], |r| {
            Ok(serde_json::json!({
                "locator": r.get::<_, String>(0)?,
                "oid": r.get::<_, String>(1)?,
                "type": r.get::<_, String>(2)?,
                "size": r.get::<_, i64>(3)?,
                "status": r.get::<_, String>(4)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn delete_source(&self, source_id: i64, force: bool) -> Result<serde_json::Value, String> {
        let deps = self.source_dependents(source_id);
        if !deps.is_empty() && !force {
            return Ok(serde_json::json!({"blocked": true, "dependents": deps}));
        }
        let (path, fp): (String, String) = {
            let c = self.db.lock();
            c.query_row(
                "SELECT stored_path, fingerprint FROM sources WHERE id=?1",
                params![source_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "source not found".to_string())?
        };
        {
            let c = self.db.lock();
            c.execute("DELETE FROM sources WHERE id=?1", params![source_id])
                .map_err(|e| e.to_string())?;
        }
        std::fs::remove_file(&path).ok();
        let _ = fp;
        // Recompute; new sources may now win previously duplicate oids.
        let report = self.analyze(ScopeMode::Full, None, false);
        Ok(serde_json::json!({"blocked": false, "report": report}))
    }
}

impl Engine {
    pub fn state_json(&self) -> serde_json::Value {
        let c = self.db.lock();
        let sources: Vec<serde_json::Value> = {
            let mut stmt = c
                .prepare(
                    "SELECT id, kind, original_name, size, fingerprint, paired_pack_fp,
                            parse_summary, imported_at
                     FROM sources ORDER BY fingerprint",
                )
                .unwrap();
            stmt.query_map(params![], |r| {
                let summary: String = r.get(6).unwrap_or_default();
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "kind": r.get::<_, String>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "size": r.get::<_, i64>(3)?,
                    "fingerprint": r.get::<_, String>(4)?,
                    "paired_pack_fp": r.get::<_, Option<String>>(5)?,
                    "summary": serde_json::from_str::<serde_json::Value>(&summary).unwrap_or_default(),
                    "imported_at": r.get::<_, i64>(7)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };

        let candidates: Vec<serde_json::Value> = {
            let mut stmt = c
                .prepare(
                    "SELECT ca.id, ca.source_id, s.kind, ca.locator, ca.entry_offset, ca.obj_type,
                            ca.oid, ca.declared_size, ca.actual_size, ca.zlib_start, ca.zlib_end,
                            ca.crc_expected, ca.crc_actual, ca.delta_type, ca.delta_base_locator,
                            ca.parse_issue, ca.status, ca.resolution_oid, ca.resolved_type,
                            ca.resolved_size, ca.resolved_preview, ca.block_reason, s.fingerprint
                     FROM candidates ca JOIN sources s ON s.id=ca.source_id
                     ORDER BY s.fingerprint, ca.entry_offset, ca.locator",
                )
                .unwrap();
            stmt.query_map(params![], |r| {
                let crc_bad = match (r.get::<_, Option<i64>>(11)?, r.get::<_, Option<i64>>(12)?) {
                    (Some(a), Some(b)) => a != b,
                    _ => false,
                };
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "source_id": r.get::<_, i64>(1)?,
                    "source_kind": r.get::<_, String>(2)?,
                    "locator": r.get::<_, String>(3)?,
                    "entry_offset": r.get::<_, Option<i64>>(4)?,
                    "obj_type": r.get::<_, String>(5)?,
                    "claimed_oid": r.get::<_, Option<String>>(6)?,
                    "declared_size": r.get::<_, Option<i64>>(7)?,
                    "actual_size": r.get::<_, Option<i64>>(8)?,
                    "zlib_start": r.get::<_, Option<i64>>(9)?,
                    "zlib_end": r.get::<_, Option<i64>>(10)?,
                    "crc_expected": r.get::<_, Option<i64>>(11)?,
                    "crc_actual": r.get::<_, Option<i64>>(12)?,
                    "crc_bad": crc_bad,
                    "delta_type": r.get::<_, Option<String>>(13)?,
                    "delta_base": r.get::<_, Option<String>>(14)?,
                    "parse_issue": r.get::<_, Option<String>>(15)?,
                    "status": r.get::<_, String>(16)?,
                    "resolution_oid": r.get::<_, Option<String>>(17)?,
                    "resolved_type": r.get::<_, Option<String>>(18)?,
                    "resolved_size": r.get::<_, Option<i64>>(19)?,
                    "preview": r.get::<_, Option<String>>(20)?,
                    "block_reason": r.get::<_, Option<String>>(21)?,
                    "fingerprint": r.get::<_, String>(22)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };

        let edges: Vec<serde_json::Value> = c
            .prepare("SELECT child_id, parent_id, parent_oid, kind FROM edges ORDER BY id")
            .unwrap()
            .query_map(params![], |r| {
                Ok(serde_json::json!({
                    "child_id": r.get::<_, i64>(0)?,
                    "parent_id": r.get::<_, Option<i64>>(1)?,
                    "parent_oid": r.get::<_, Option<String>>(2)?,
                    "kind": r.get::<_, String>(3)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let issues: Vec<serde_json::Value> = c
            .prepare(
                "SELECT id, code, severity, source_id, candidate_id, message, evidence
                 FROM issues ORDER BY id",
            )
            .unwrap()
            .query_map(params![], |r| {
                let ev: String = r.get(6).unwrap_or_else(|_| "{}".into());
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "code": r.get::<_, String>(1)?,
                    "severity": r.get::<_, String>(2)?,
                    "source_id": r.get::<_, Option<i64>>(3)?,
                    "candidate_id": r.get::<_, Option<i64>>(4)?,
                    "message": r.get::<_, String>(5)?,
                    "evidence": serde_json::from_str::<serde_json::Value>(&ev).unwrap_or_default(),
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let steps: Vec<serde_json::Value> = c
            .prepare(
                "SELECT candidate_id, seq, depth, base_oid, base_locator, delta_type, base_size,
                        output_size, cmd_count, cmd_ranges, input_crc32, output_sha,
                        expected_oid, oid_match, state
                 FROM delta_steps ORDER BY candidate_id, seq",
            )
            .unwrap()
            .query_map(params![], |r| {
                let ranges: String = r.get(9).unwrap_or_default();
                Ok(serde_json::json!({
                    "candidate_id": r.get::<_, i64>(0)?,
                    "seq": r.get::<_, i64>(1)?,
                    "depth": r.get::<_, i64>(2)?,
                    "base_oid": r.get::<_, Option<String>>(3)?,
                    "base_locator": r.get::<_, Option<String>>(4)?,
                    "delta_type": r.get::<_, Option<String>>(5)?,
                    "base_size": r.get::<_, i64>(6)?,
                    "output_size": r.get::<_, i64>(7)?,
                    "cmd_count": r.get::<_, i64>(8)?,
                    "cmd_ranges": serde_json::from_str::<serde_json::Value>(&ranges).unwrap_or_default(),
                    "input_crc32": r.get::<_, Option<i64>>(10)?,
                    "output_sha": r.get::<_, String>(11)?,
                    "expected_oid": r.get::<_, Option<String>>(12)?,
                    "oid_match": r.get::<_, Option<i64>>(13)?,
                    "state": r.get::<_, String>(14)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let objects: Vec<serde_json::Value> = c
            .prepare("SELECT oid, obj_type, size, preview FROM objects ORDER BY oid")
            .unwrap()
            .query_map(params![], |r| {
                Ok(serde_json::json!({
                    "oid": r.get::<_, String>(0)?,
                    "type": r.get::<_, String>(1)?,
                    "size": r.get::<_, i64>(2)?,
                    "preview": r.get::<_, String>(3)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let pins: Vec<serde_json::Value> = c
            .prepare("SELECT oid, source_id, locator, note FROM pins ORDER BY oid")
            .unwrap()
            .query_map(params![], |r| {
                Ok(serde_json::json!({
                    "oid": r.get::<_, String>(0)?,
                    "source_id": r.get::<_, i64>(1)?,
                    "locator": r.get::<_, String>(2)?,
                    "note": r.get::<_, String>(3)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let analysis: serde_json::Value = c
            .query_row(
                "SELECT status,max_depth,max_bytes,max_share,bytes_spent,scope,paused_chain,message
                 FROM analysis_state WHERE id=1",
                params![],
                |r| {
                    Ok(serde_json::json!({
                        "status": r.get::<_, String>(0)?,
                        "max_depth": r.get::<_, u32>(1)?,
                        "max_bytes": r.get::<_, i64>(2)?,
                        "max_share": r.get::<_, f64>(3)?,
                        "bytes_spent": r.get::<_, i64>(4)?,
                        "scope": serde_json::from_str::<serde_json::Value>(
                            &r.get::<_, String>(5)?).unwrap_or(serde_json::json!([])),
                        "paused_chain": serde_json::from_str::<serde_json::Value>(
                            &r.get::<_, String>(6)?).unwrap_or(serde_json::json!([])),
                        "message": r.get::<_, String>(7)?,
                    }))
                },
            )
            .unwrap_or(serde_json::json!({"status": "idle"}));

        serde_json::json!({
            "sources": sources,
            "candidates": candidates,
            "edges": edges,
            "issues": issues,
            "steps": steps,
            "objects": objects,
            "pins": pins,
            "analysis": analysis,
        })
    }

    pub fn object_content(&self, oid_hex: &str) -> Option<(String, Vec<u8>)> {
        let oid = Oid::parse_hex(oid_hex)?;
        let c = self.db.lock();
        let (typ, path): (String, String) = c
            .query_row(
                "SELECT obj_type, content_path FROM objects WHERE oid=?1",
                params![oid.hex()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok()?;
        let data = std::fs::read(path).ok()?;
        Some((typ, data))
    }
}
