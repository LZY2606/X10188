//! Import pipeline, candidate selection, per-branch delta resolution,
//! budgeted reconstruction with resumable intermediate state and local
//! recomputation of dependency subgraphs.

use crate::delta::{apply_delta, DeltaStep};
use crate::git::{
    self, git_object_id, inflate_stream, oid_hex, IdxScan, LooseScan, ObjType, PackScan,
    RawEntry,
};
use crate::store::{DbEntry, DbResolution, Store};
use rusqlite::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const DEFAULT_BRANCH: &str = "default";

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub total_bytes: usize,
    pub max_depth: u32,
    pub single_object_ratio: (u32, u32), // numerator/denominator of total
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            total_bytes: 64 * 1024 * 1024,
            max_depth: 50,
            single_object_ratio: (1, 2),
        }
    }
}

impl Budget {
    pub fn object_cap(&self) -> usize {
        self.total_bytes * self.single_object_ratio.0 as usize
            / self.single_object_ratio.1 as usize
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockedBy {
    pub oid: String,
    pub sources: Vec<i64>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub duplicate: bool,
    pub kind: String,
    pub filename: String,
    pub entries: usize,
    pub errors: Vec<String>,
    pub pack_checksum: Option<String>,
    pub matched_pack_source: Option<i64>,
    pub matched_idx_source: Option<i64>,
    pub resolved: usize,
    pub blocked: usize,
    pub errored: usize,
    pub pending: usize,
}

pub struct AppState {
    pub store: Store,
    pub budget: Mutex<Budget>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(data_dir: &Path) -> std::io::Result<SharedState> {
        let store = Store::open(data_dir)?;
        {
            let c = store.conn.lock().unwrap();
            c.execute(
                "INSERT OR IGNORE INTO branches(name,note,created_at) VALUES(?1,'默认分析分支',?2)",
                params![DEFAULT_BRANCH, now_ts()],
            )
            .map_err(crate::store::io_err)?;
        }
        let state = Arc::new(AppState {
            store,
            budget: Mutex::new(Budget::default()),
        });
        // Re-resolve everything that may be in an intermediate state.
        state.resolve_branch(DEFAULT_BRANCH, None);
        Ok(state)
    }

    pub fn budget(&self) -> Budget {
        *self.budget.lock().unwrap()
    }

    pub fn set_budget(&self, b: Budget) {
        *self.budget.lock().unwrap() = b;
        self.store.set_setting("budget", &serde_json::to_string(&BudgSer::from(b)).unwrap());
    }
}

#[derive(Serialize)]
struct BudgSer {
    total_bytes: usize,
    max_depth: u32,
    single_object_ratio: (u32, u32),
}
impl From<Budget> for BudgSer {
    fn from(b: Budget) -> Self {
        BudgSer {
            total_bytes: b.total_bytes,
            max_depth: b.max_depth,
            single_object_ratio: b.single_object_ratio,
        }
    }
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// Where a candidate's verified payload lives.
enum CandidatePayload {
    /// Raw inflated payload stored inline in the entries row.
    Inline,
    /// Resolved reconstructed content stored as an object file.
    ObjectFile(PathBuf),
}

struct Candidate {
    entry: DbEntry,
    kind: ObjType,
    payload: CandidatePayload,
    verified: bool,
    sources: BTreeSet<i64>,
}

fn detect_kind(bytes: &[u8], filename: &str) -> &'static str {
    if bytes.len() >= 4 && &bytes[0..4] == b"PACK" {
        "pack"
    } else if bytes.len() >= 8
        && &bytes[0..4] == b"\xfftOc"
        && &bytes[4..8] == 2u32.to_be_bytes()
    {
        "idx"
    } else if bytes.len() >= 256 * 4 && !bytes.is_empty() && bytes[0] != 0x78 {
        // Heuristic: v1 idx starts with a small fanout count, not zlib.
        let first = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if first <= 1 && bytes[0] != b'P' && filename.ends_with(".idx") {
            "idx"
        } else if looks_like_loose(bytes, filename) {
            "loose"
        } else {
            "unknown"
        }
    } else if looks_like_loose(bytes, filename) {
        "loose"
    } else {
        "unknown"
    }
}

fn looks_like_loose(bytes: &[u8], filename: &str) -> bool {
    // zlib stream header bytes.
    let zlib = matches!(bytes.first(), Some(0x78) | Some(0x08) | Some(0x18) | Some(0x28) | Some(0x38) | Some(0x48) | Some(0x58) | Some(0x68));
    zlib || filename.contains('/') || filename.ends_with(".loose")
}

impl AppState {
    /// Import raw bytes under a logical filename. Idempotent on sha256:
    /// re-importing the same content returns the existing record.
    pub fn import_bytes(&self, filename: &str, bytes: &[u8]) -> ImportReport {
        let sha = sha256_hex(bytes);
        if let Some(existing) = self.store.source_by_sha(&sha) {
            let counts = self.branch_counts(DEFAULT_BRANCH);
            return ImportReport {
                source_id: existing.id,
                duplicate: true,
                kind: existing.kind,
                filename: existing.filename,
                entries: self.store.entries_of_source(existing.id).len(),
                errors: Vec::new(),
                pack_checksum: None,
                matched_pack_source: None,
                matched_idx_source: None,
                resolved: counts.0,
                blocked: counts.1,
                errored: counts.2,
                pending: counts.3,
            };
        }

        let safe_name: String = filename
            .split('/')
            .last()
            .unwrap_or(filename)
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || "._-" .contains(c) { c } else { '_' })
            .collect();
        let stored_name = format!("{sha}_{safe_name}");
        let path = self.store.imports_dir().join(&stored_name);
        std::fs::write(&path, bytes).unwrap();

        let kind = detect_kind(bytes, filename);
        let mut report = ImportReport {
            source_id: 0,
            duplicate: false,
            kind: kind.into(),
            filename: filename.into(),
            entries: 0,
            errors: Vec::new(),
            pack_checksum: None,
            matched_pack_source: None,
            matched_idx_source: None,
            resolved: 0,
            blocked: 0,
            errored: 0,
            pending: 0,
        };

        let sid = {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "INSERT INTO sources(filename,kind,sha256,size,imported_at) \
                 VALUES(?1,?2,?3,?4,?5)",
                params![safe_name, kind, sha, bytes.len() as i64, now_ts()],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        report.source_id = sid;

        match kind {
            "pack" => self.ingest_pack(sid, bytes, &mut report),
            "idx" => self.ingest_idx(sid, bytes, &mut report),
            "loose" => self.ingest_loose(sid, filename, bytes, &mut report),
            _ => report.errors.push("unrecognized file type".into()),
        }

        // Pair pack/idx by pack checksum (both directions).
        self.pair_pack_idx(sid);

        // Determine affected oids and re-resolve only that subgraph.
        let affected = self.affected_oids_for_new_source(sid);
        self.resolve_branch(DEFAULT_BRANCH, Some(&affected));

        let counts = self.branch_counts(DEFAULT_BRANCH);
        report.resolved = counts.0;
        report.blocked = counts.1;
        report.errored = counts.2;
        report.pending = counts.3;
        report
    }

    fn branch_counts(&self, branch: &str) -> (usize, usize, usize, usize) {
        let mut r = b = e = p = 0;
        for res in self.store.resolutions_of(branch) {
            match res.status.as_str() {
                "resolved" => r += 1,
                "blocked" => b += 1,
                "error" => e += 1,
                "pending" => p += 1,
                _ => {}
            }
        }
        (r, b, e, p)
    }
}

impl AppState {
    fn ingest_pack(&self, sid: i64, bytes: &[u8], report: &mut ImportReport) {
        let scan: PackScan = git::scan_pack(bytes, self.budget().object_cap());
        report.pack_checksum = Some(oid_hex(&scan.actual_checksum));
        {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "UPDATE sources SET pack_checksum=?1 WHERE id=?2",
                params![oid_hex(&scan.actual_checksum), sid],
            )
            .unwrap();
        }
        if !scan.checksum_ok {
            report
                .errors
                .push("pack trailing sha1 checksum mismatch".into());
        }
        if let Some(f) = &scan.fatal {
            report.errors.push(f.clone());
        }

        // Build a transient offset -> oid map from a matching idx (if any).
        let idx_info = self.find_matching_idx(&oid_hex(&scan.actual_checksum));
        let mut offset_oid: HashMap<u64, ([u8; 20], Option<u32>)> = HashMap::new();
        if let Some((idx_sid, idx)) = &idx_info {
            report.matched_idx_source = Some(*idx_sid);
            for o in &idx.objects {
                offset_oid.insert(o.pack_offset, (o.oid, o.crc32));
            }
        }

        let c = self.store.conn.lock().unwrap();
        for ent in &scan.entries {
            let (oid_h, crc_expected) = offset_oid
                .get(&ent.offset)
                .map(|(o, crc)| (Some(oid_hex(o)), *crc))
                .unwrap_or((None, None));
            let mut crc_ok: Option<bool> = None;
            let mut parse_error = ent.inflate_error.clone();
            if let Some(payload) = &ent.payload {
                if let Some(expected_crc) = crc_expected {
                    let start = ent.offset as usize;
                    let end = ent.data_offset as usize
                        + ent.compressed_len.unwrap_or(0) as usize;
                    let actual = crc32fast::hash(&bytes[start..end]);
                    let ok = actual == expected_crc;
                    crc_ok = Some(ok);
                    if !ok {
                        let msg = git::ParseError::CrcMismatch {
                            at: ent.offset,
                            expected: expected_crc,
                            actual,
                        }
                        .to_string();
                        parse_error = Some(match parse_error {
                            Some(p) => format!("{p}; {msg}"),
                            None => msg,
                        });
                    }
                }
            }
            let payload = ent.payload.clone();
            c.execute(
                "INSERT INTO entries(source_id,pack_source_id,oid,kind,role,\"offset\",\
                        data_offset,compressed_len,declared_size,ofs_distance,ref_base,\
                        has_payload,parse_error,idx_crc_ok,content) \
                 VALUES(?1,?2,?3,?4,'pack-object',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    sid,
                    sid,
                    oid_h,
                    ent.kind.name(),
                    ent.offset as i64,
                    ent.data_offset as i64,
                    ent.compressed_len.map(|v| v as i64),
                    ent.declared_size as i64,
                    ent.ofs_distance.map(|v| v as i64),
                    ent.ref_base.map(|o| oid_hex(&o)),
                    payload.is_some(),
                    parse_error,
                    crc_ok,
                    payload,
                ],
            )
            .unwrap();
        }
        report.entries = scan.entries.len();
    }

    fn find_matching_idx(&self, pack_checksum: &str) -> Option<(i64, IdxScan)> {
        for s in self.store.list_sources() {
            if s.kind == "idx" {
                if let Some(bytes) = self.read_source_bytes(s.id) {
                    let scan = git::scan_idx(&bytes);
                    if oid_hex(&scan.pack_checksum) == pack_checksum {
                        return Some((s.id, scan));
                    }
                }
            }
        }
        None
    }

    pub fn read_source_bytes(&self, sid: i64) -> Option<Vec<u8>> {
        let s = self.store.source_by_id(sid)?;
        let entry = std::fs::read_dir(self.store.imports_dir())
            .ok()?
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with(&s.sha256))?;
        std::fs::read(entry.path()).ok()
    }
}

impl AppState {
    fn ingest_idx(&self, sid: i64, bytes: &[u8], report: &mut ImportReport) {
        let scan = git::scan_idx(bytes);
        report.pack_checksum = Some(oid_hex(&scan.pack_checksum));
        if let Some(e) = &scan.error {
            report.errors.push(e.clone());
        }
        if !scan.fanout_ok {
            report
                .errors
                .push("idx fanout table is not monotonic".into());
        }
        {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "UPDATE sources SET pack_checksum=?1 WHERE id=?2",
                params![oid_hex(&scan.pack_checksum), sid],
            )
            .unwrap();
            for o in &scan.objects {
                c.execute(
                    "INSERT INTO entries(source_id,pack_source_id,oid,kind,role,\"offset\",\
                            idx_crc_ok,declared_size,has_payload) \
                     VALUES(?1,NULL,?2,'idx-ref','idx-record',?3,?4,0,0)",
                    params![sid, oid_hex(&o.oid), o.pack_offset as i64, scan.checksum_ok],
                )
                .unwrap();
            }
        }
        report.entries = scan.objects.len();
    }

    /// Loose object import. Two accepted forms:
    /// 1. filename contains a 40-hex oid (standard loose naming),
    /// 2. explicit `<oid>.loose`.
    fn ingest_loose(&self, sid: i64, filename: &str, bytes: &[u8], report: &mut ImportReport) {
        let hex40: String = filename
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        let claimed = if hex40.len() >= 40 {
            hex::decode(&hex40[..40]).ok()
        } else {
            None
        };
        let hard_cap = self.budget().object_cap();
        let (scan, oid_bytes): (LooseScan, [u8; 20]) = match claimed {
            Some(mut o) if o.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&o);
                (git::scan_loose(bytes, &arr, hard_cap), arr)
            }
            _ => {
                // Inflate once to learn the oid from content, then verify loop.
                let (raw, _) = match git::inflate_loose(bytes, hard_cap) {
                    Ok(v) => v,
                    Err(e) => {
                        let c = self.store.conn.lock().unwrap();
                        c.execute(
                            "INSERT INTO entries(source_id,oid,kind,role,declared_size,\
                                    has_payload,parse_error) VALUES(?1,NULL,'blob','loose-object',0,0,?2)",
                            params![sid, e],
                        )
                        .unwrap();
                        report.entries = 1;
                        report.errors.push(e);
                        return;
                    }
                };
                let parsed = parse_loose_raw(&raw);
                match parsed {
                    Some((kind, data)) => {
                        let oid = git_object_id(kind, &data);
                        (git::scan_loose(bytes, &oid, hard_cap), oid)
                    }
                    None => {
                        let c = self.store.conn.lock().unwrap();
                        c.execute(
                            "INSERT INTO entries(source_id,oid,kind,role,declared_size,\
                                    has_payload,parse_error) VALUES(?1,NULL,'blob','loose-object',0,0,?2)",
                            params![sid, "could not parse loose object header"],
                        )
                        .unwrap();
                        report.entries = 1;
                        report
                            .errors
                            .push("could not parse loose object header".into());
                        return;
                    }
                }
            }
        };
        if let Some(e) = &scan.error {
            report.errors.push(e.clone());
        }
        let c = self.store.conn.lock().unwrap();
        c.execute(
            "INSERT INTO entries(source_id,oid,kind,role,declared_size,has_payload,\
                    parse_error,content) VALUES(?1,?2,?3,'loose-object',?4,?5,?6,?7)",
            params![
                sid,
                oid_hex(&oid_bytes),
                scan.kind.name(),
                scan.declared_size as i64,
                !scan.data.is_empty(),
                scan.error,
                scan.data
            ],
        )
        .unwrap();
        report.entries = 1;
    }

    fn pair_pack_idx(&self, sid: i64) {
        let src = match self.store.source_by_id(sid) {
            Some(s) => s,
            None => return,
        };
        let c = self.store.conn.lock().unwrap();
        let checksum: Option<String> = c
            .query_row(
                "SELECT pack_checksum FROM sources WHERE id=?1",
                params![sid],
                |r| r.get(0),
            )
            .ok();
        if src.kind == "pack" {
            let want = checksum.clone();
            let found: Option<i64> = c
                .query_row(
                    "SELECT id FROM sources WHERE kind='idx' AND pack_checksum=?1",
                    params![want],
                    |r| r.get::<_, i64>(0),
                )
                .ok();
            if let Some(idx_id) = found {
                c.execute(
                    "UPDATE sources SET idx_source_id=?1 WHERE id=?2",
                    params![idx_id, sid],
                )
                .unwrap();
                c.execute(
                    "UPDATE sources SET pack_source_id=?1 WHERE id=?2",
                    params![sid, idx_id],
                )
                .unwrap();
                // Attach pack_source_id + known oid onto that idx's records.
                attach_idx_oids(&c, idx_id, sid);
            }
        } else if src.kind == "idx" {
            let want = checksum.clone();
            let mut pack_id: Option<i64> = None;
            {
                let mut stmt = c
                    .prepare("SELECT id FROM sources WHERE kind='pack' AND pack_checksum=?1")
                    .unwrap();
                pack_id = stmt
                    .query_row(params![want], |r| r.get::<_, i64>(0))
                    .ok();
            }
            if let Some(pid) = pack_id {
                c.execute(
                    "UPDATE sources SET idx_source_id=?1 WHERE id=?2",
                    params![sid, pid],
                )
                .unwrap();
                c.execute(
                    "UPDATE sources SET pack_source_id=?1 WHERE id=?2",
                    params![pid, sid],
                )
                .unwrap();
                attach_idx_oids(&c, sid, pid);
            }
        }
    }
}

fn attach_idx_oids(c: &rusqlite::Connection, idx_id: i64, pack_id: i64) {
    // Fill oid on pack-object rows from the idx by offset.
    c.execute(
        "UPDATE entries
         SET oid=(SELECT oid FROM entries AS i
                  WHERE i.source_id=?1 AND i.role='idx-record'
                    AND i.\"offset\"=entries.\"offset\" LIMIT 1),
             pack_source_id=?2
         WHERE source_id=?2 AND role='pack-object'",
        params![idx_id, pack_id],
    )
    .unwrap();
    c.execute(
        "UPDATE entries SET pack_source_id=?2 WHERE source_id=?1 AND role='idx-record'",
        params![idx_id, pack_id],
    )
    .unwrap();
}

fn parse_loose_raw(raw: &[u8]) -> Option<(ObjType, Vec<u8>)> {
    let nul = raw.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&raw[..nul]).ok()?;
    let (ts, ss) = header.split_once(' ')?;
    let kind = match ts {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        _ => return None,
    };
    let size: usize = ss.parse().ok()?;
    let data = &raw[nul + 1..];
    if data.len() != size {
        return None;
    }
    Some((kind, data.to_vec()))
}

impl AppState {
    /// Oids whose resolution result could change after importing `sid`.
    fn affected_oids_for_new_source(&self, sid: i64) -> BTreeSet<String> {
        let mut affected: BTreeSet<String> = HashSet::new();
        let new_entries: Vec<DbEntry> = self.store.entries_of_source(sid);
        for e in &new_entries {
            if let Some(o) = &e.oid {
                affected.insert(o.clone());
            }
        }
        // Any pending/blocked entry whose missing base might now exist.
        for res in self.store.resolutions_of(DEFAULT_BRANCH) {
            if res.status == "pending" || res.status == "blocked" {
                if let Some(e) = self.store.entry_by_id(res.entry_id) {
                    affected.insert(oid_key_for_entry(&e));
                    if let Some(b) = &e.ref_base {
                        affected.insert(b.clone());
                    }
                }
            }
        }
        // Close over existing dependents via resolution dependency edges.
        let all = self.store.all_entries();
        let by_oid = group_by_oid(&all);
        let mut stack: Vec<String> = affected.iter().cloned().collect();
        while let Some(oid) = stack.pop() {
            for e in all.iter() {
                if depends_on(e, &oid) {
                    let key = oid_key_for_entry(e);
                    if affected.insert(key.clone()) {
                        stack.push(key);
                    }
                }
            }
            let _ = by_oid;
        }
        affected
    }
}

fn oid_key_for_entry(e: &DbEntry) -> String {
    e.oid.clone().unwrap_or_else(|| format!("pack{}:{}", e.pack_source_id.unwrap_or(0), e.offset.unwrap_or(0)))
}

fn group_by_oid(entries: &[DbEntry]) -> BTreeMap<String, Vec<&DbEntry>> {
    let mut m: BTreeMap<String, Vec<&DbEntry>> = BTreeMap::new();
    for e in entries {
        m.entry(oid_key_for_entry(e)).or_default().push(e);
    }
    m
}

fn depends_on(e: &DbEntry, base_oid: &str) -> bool {
    if e.ref_base.as_deref() == Some(base_oid) {
        return true;
    }
    false
}

#[derive(Clone)]
struct CandidateRef {
    entry_id: i64,
    source_id: i64,
    oid: String,
    kind: String,
    role: String,
    parse_error: Option<String>,
    idx_crc_ok: Option<bool>,
}

/// Deterministic candidate ordering independent of import order:
/// verified loose > good pack object (indexed + CRC ok) > indexed pack object
/// > unindexed pack object; ties broken by smallest source id and entry id.
fn candidate_rank(e: &DbEntry) -> u8 {
    if e.role == "loose-object" {
        0
    } else if e.role == "pack-object" {
        match e.idx_crc_ok {
            Some(true) if e.oid.is_some() => 1,
            Some(false) => 4,
            _ if e.oid.is_some() => 2,
            _ => 3,
        }
    } else {
        5
    }
}

impl AppState {
    /// Resolve (or re-resolve) entries in `scope` (None = everything) for one
    /// branch. Uses a single run ledger; budget exhaustion leaves entries in
    /// `pending` with a resumable blocking chain and never stores partial
    /// objects.
    pub fn resolve_branch(&self, branch: &str, scope: Option<&BTreeSet<String>>) -> RunSummary {
        self.ensure_branch(branch);
        let pins = self.pins_for(branch);
        let entries = self.store.all_entries();
        let mut groups: BTreeMap<String, Vec<DbEntry>> = BTreeMap::new();
        for e in entries {
            if e.role == "idx-record" {
                continue;
            }
            let key = oid_key_for_entry(&e);
            if let Some(s) = scope {
                if !s.contains(&key) {
                    continue;
                }
            }
            groups.entry(key).or_default().push(e);
        }
        for v in groups.values_mut() {
            v.sort_by(|a, b| {
                candidate_rank(a)
                    .cmp(&candidate_rank(b))
                    .then(a.source_id.cmp(&b.source_id))
                    .then(a.id.cmp(&b.id))
            });
        }

        // Reset scoped resolution rows so partial output can never linger.
        {
            let c = self.store.conn.lock().unwrap();
            for ents in groups.values() {
                for e in ents {
                    c.execute(
                        "DELETE FROM resolutions WHERE branch=?1 AND entry_id=?2",
                        params![branch, e.id],
                    )
                    .unwrap();
                    c.execute(
                        "DELETE FROM delta_steps WHERE branch=?1 AND entry_id=?2",
                        params![branch, e.id],
                    )
                    .unwrap();
                }
            }
        }

        let budget = self.budget();
        let mut ctx = ResolveCtx {
            branch: branch.to_string(),
            groups,
            pins,
            budget,
            spent: 0,
            stack: Vec::new(),
            memo: HashMap::new(),
        };
        let keys: Vec<String> = ctx.groups.keys().cloned().collect();
        let mut statuses: HashMap<String, String> = HashMap::new();
        for key in keys {
            let outcome = ctx.resolve(&key, 0, self);
            statuses.insert(key, outcome.status());
        }
        let summary = ctx.flush(self);
        summary
    }

    fn ensure_branch(&self, name: &str) {
        let c = self.store.conn.lock().unwrap();
        c.execute(
            "INSERT OR IGNORE INTO branches(name,note,created_at) VALUES(?1,'固定来源分析分支',?2)",
            params![name, now_ts()],
        )
        .unwrap();
    }

    fn pins_for(&self, branch: &str) -> HashMap<String, i64> {
        let c = self.store.conn.lock().unwrap();
        let mut stmt = c
            .prepare("SELECT oid,source_id FROM pins WHERE branch=?1")
            .unwrap();
        let rows = stmt
            .query_map(params![branch], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .unwrap();
        rows.flatten().collect()
    }
}

#[derive(Debug, Clone)]
enum Outcome {
    Resolved {
        kind: ObjType,
        content: Vec<u8>,
        depth: u32,
        steps: Vec<StoredStep>,
        sources: BTreeSet<i64>,
    },
    Blocked {
        chain: Vec<BlockedBy>,
        depth: u32,
    },
    Error {
        message: String,
        depth: u32,
    },
    Pending {
        reason: String,
        chain: Vec<BlockedBy>,
        depth: u32,
    },
}

impl Outcome {
    fn status(&self) -> String {
        match self {
            Outcome::Resolved { .. } => "resolved",
            Outcome::Blocked { .. } => "blocked",
            Outcome::Error { .. } => "error",
            Outcome::Pending { .. } => "pending",
        }
        .to_string()
    }
}

#[derive(Debug, Clone)]
struct StoredStep {
    hop: u32,
    base_entry_id: Option<i64>,
    base_oid: String,
    step: DeltaStep,
    verify: String,
}

#[derive(Default, Debug, Clone)]
pub struct RunSummary {
    pub resolved: usize,
    pub blocked: usize,
    pub errored: usize,
    pub pending: usize,
    pub spent: usize,
    pub paused: bool,
}

struct ResolveCtx {
    branch: String,
    groups: BTreeMap<String, Vec<DbEntry>>,
    pins: HashMap<String, i64>,
    budget: Budget,
    spent: usize,
    stack: Vec<String>,
    memo: HashMap<String, Outcome>,
}

impl ResolveCtx {
    fn choose_entry(&self, key: &str) -> Option<(usize, DbEntry)> {
        let cands = self.groups.get(key)?;
        if let Some(&sid) = key.rsplit('=').next().and_then(|_| None) {
            let _ = sid;
        }
        // Pin by oid (only when the key is a real oid).
        if key.len() == 40 {
            if let Some(&sid) = self.pins.get(key) {
                if let Some(pos) = cands.iter().position(|e| e.source_id == sid) {
                    return Some((pos, cands[pos].clone()));
                }
                return None; // pinned source deleted / absent -> invalid pin
            }
        }
        cands.first().cloned().map(|e| (0, e))
    }
}

impl ResolveCtx {
    fn resolve(&mut self, key: &str, depth: u32, app: &AppState) -> Outcome {
        if let Some(o) = self.memo.get(key) {
            return o.clone();
        }
        if self.stack.iter().any(|k| k == key) {
            let mut path = self.stack.clone();
            path.push(key.to_string());
            return Outcome::Error {
                message: format!("delta cycle detected: {}", path.join(" -> ")),
                depth,
            };
        }
        if depth > self.budget.max_depth {
            return Outcome::Pending {
                reason: format!("delta depth budget {} exceeded", self.budget.max_depth),
                chain: vec![],
                depth,
            };
        }

        let chosen = match self.choose_entry(key) {
            Some(v) => v,
            None => {
                return Outcome::Blocked {
                    chain: vec![BlockedBy {
                        oid: key.to_string(),
                        sources: Vec::new(),
                        reason: "pinned source no longer present".into(),
                    }],
                    depth,
                }
            }
        };
        let entry = chosen.1.clone();
        self.stack.push(key.to_string());

        let outcome = self.resolve_entry(&entry, depth, app);
        self.stack.pop();
        self.memo.insert(key.to_string(), outcome.clone());
        outcome
    }

    fn resolve_entry(&mut self, entry: &DbEntry, depth: u32, app: &AppState) -> Outcome {
        // Parse-time corruption (bad CRC, size spoof, bad zlib boundary,
        // out-of-bounds ofs) isolates this object immediately.
        if let Some(err) = &entry.parse_error {
            return Outcome::Error {
                message: err.clone(),
                depth,
            };
        }
        let kind = match entry.kind.as_str() {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            "ofs-delta" => ObjType::OfsDelta,
            "ref-delta" => ObjType::RefDelta,
            other => {
                return Outcome::Error {
                    message: format!("unknown stored kind {other:?}"),
                    depth,
                }
            }
        };

        match kind {
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => {
                let data = match &entry.content_blob {
                    Some(d) => d.clone(),
                    None => {
                        return Outcome::Error {
                            message: "non-delta entry missing inflated payload".into(),
                            depth,
                        }
                    }
                };
                if let Err(o) = self.charge(&data, depth) {
                    return o;
                }
                Outcome::Resolved {
                    kind,
                    content: data,
                    depth,
                    steps: Vec::new(),
                    sources: iter_set(entry.source_id),
                }
            }
            ObjType::OfsDelta => self.resolve_ofs(entry, depth, app),
            ObjType::RefDelta => self.resolve_ref(entry, depth, app),
        }
    }

    /// Charge expanded bytes against the run ledger. Returns a retriable
    /// `Pending` outcome on budget breach so callers never keep partial bytes.
    fn charge(&mut self, data: &[u8], depth: u32) -> Result<(), Outcome> {
        if data.len() > self.budget.object_cap() {
            return Err(Outcome::Pending {
                reason: format!(
                    "single object of {} bytes exceeds object cap {} (ratio {}/{})",
                    data.len(),
                    self.budget.object_cap(),
                    self.budget.single_object_ratio.0,
                    self.budget.single_object_ratio.1
                ),
                chain: vec![],
                depth,
            });
        }
        self.spent = self.spent.saturating_add(data.len());
        if self.spent > self.budget.total_bytes {
            return Err(Outcome::Pending {
                reason: format!(
                    "total expansion budget {} exhausted (spent {})",
                    self.budget.total_bytes, self.spent
                ),
                chain: vec![],
                depth,
            });
        }
        Ok(())
    }
}

fn iter_set(sid: i64) -> BTreeSet<i64> {
    let mut s = BTreeSet::new();
    s.insert(sid);
    s
}

impl ResolveCtx {
    fn ofs_base_key(&self, entry: &DbEntry) -> Option<String> {
        let dist = entry.ofs_distance? as i64;
        let cur = entry.offset?;
        let target = cur - dist;
        // Find base group: search all entries for matching pack_source+offset.
        let base_entry = self
            .groups
            .values()
            .flatten()
            .find(|e| e.pack_source_id == entry.pack_source_id && e.offset == Some(target))?;
        Some(oid_key_for_entry(base_entry))
    }

    fn resolve_ofs(&mut self, entry: &DbEntry, depth: u32, app: &AppState) -> Outcome {
        let dist = match entry.ofs_distance {
            Some(d) => d,
            None => {
                return Outcome::Error {
                    message: "ofs-delta entry missing distance".into(),
                    depth,
                }
            }
        };
        let cur = match entry.offset {
            Some(o) => o,
            None => {
                return Outcome::Error {
                    message: "ofs-delta entry missing own offset".into(),
                    depth,
                }
            }
        };
        let target = cur - dist as i64;
        if target < 12 || target >= cur {
            return Outcome::Error {
                message: git::ParseError::OffsetOutOfBounds {
                    at: cur as u64,
                    distance: dist as u64,
                    target,
                }
                .to_string(),
                depth,
            };
        }
        let base_key = match self.ofs_base_key(entry) {
            Some(k) => k,
            None => {
                return Outcome::Blocked {
                    chain: vec![BlockedBy {
                        oid: format!("offset:{target}@pack{}", entry.pack_source_id.unwrap_or(0)),
                        sources: Vec::new(),
                        reason: format!("ofs-delta base at pack offset {target} is absent (thin pack, external base not imported)"),
                    }],
                    depth,
                }
            }
        };
        let base = self.resolve(&base_key, depth + 1, app);
        self.apply_against(entry, depth, base, app)
    }

    fn resolve_ref(&mut self, entry: &DbEntry, depth: u32, app: &AppState) -> Outcome {
        let base_oid = match &entry.ref_base {
            Some(o) => o.clone(),
            None => {
                return Outcome::Error {
                    message: "ref-delta entry missing base oid".into(),
                    depth,
                }
            }
        };
        if !self.groups.contains_key(&base_oid) {
            return Outcome::Blocked {
                chain: vec![BlockedBy {
                    oid: base_oid,
                    sources: Vec::new(),
                    reason: "ref-delta base object not present in any imported source".into(),
                }],
                depth,
            };
        }
        let base = self.resolve(&base_oid, depth + 1, app);
        self.apply_against(entry, depth, base, app)
    }

    fn apply_against(
        &mut self,
        entry: &DbEntry,
        depth: u32,
        base: Outcome,
        app: &AppState,
    ) -> Outcome {
        let (base_kind, base_data, base_depth, base_sources, base_entry_id, base_oid, base_steps) =
            match base {
                Outcome::Resolved {
                    kind,
                    content,
                    depth,
                    steps,
                    sources,
                } => {
                    let beid = if entry.kind == "ref-delta" {
                        entry.ref_base.as_ref().and_then(|o| {
                            self.groups
                                .get(o)
                                .and_then(|v| v.first())
                                .map(|e| e.id)
                        })
                    } else {
                        self.ofs_base_key(entry).and_then(|k| {
                            self.groups.get(&k).and_then(|v| v.first()).map(|e| e.id)
                        })
                    };
                    let boid = match &entry.kind[..] {
                        "ref-delta" => entry.ref_base.clone().unwrap_or_default(),
                        _ => self
                            .ofs_base_key(entry)
                            .unwrap_or_else(|| String::new()),
                    };
                    (kind, content, depth, sources, beid, boid, steps)
                }
                Outcome::Blocked { mut chain, .. } => {
                    chain.push(BlockedBy {
                        oid: oid_key_for_entry(entry),
                        sources: iter_set(entry.source_id).into_iter().collect(),
                        reason: "delta target waits on its base".into(),
                    });
                    return Outcome::Blocked { chain, depth };
                }
                Outcome::Error { message, .. } => {
                    return Outcome::Blocked {
                        chain: vec![BlockedBy {
                            oid: match &entry.kind[..] {
                                "ref-delta" => entry.ref_base.clone().unwrap_or_default(),
                                _ => format!("ofs@{}", entry.offset.unwrap_or(-1)),
                            },
                            sources: Vec::new(),
                            reason: format!("base unusable: {message}"),
                        }],
                        depth,
                    }
                }
                Outcome::Pending {
                    reason,
                    mut chain,
                    ..
                } => {
                    chain.push(BlockedBy {
                        oid: oid_key_for_entry(entry),
                        sources: iter_set(entry.source_id).into_iter().collect(),
                        reason: format!("waiting behind budget pause ({reason})"),
                    });
                    return Outcome::Pending {
                        reason,
                        chain,
                        depth,
                    };
                }
            };

        let delta = match &entry.content_blob {
            Some(d) => d.clone(),
            None => {
                return Outcome::Error {
                    message: "delta entry missing instruction payload".into(),
                    depth,
                }
            }
        };
        let (mut out, raw_steps) =
            match apply_delta(&base_data, &delta, self.budget.object_cap()) {
                Ok(v) => v,
                Err(crate::delta::DeltaError::BudgetExceeded { produced, cap }) => {
                    return Outcome::Pending {
                        reason: format!("reconstruction hit object cap {cap} at {produced} bytes"),
                        chain: vec![],
                        depth,
                    }
                }
                Err(crate::delta::DeltaError::Parse(p)) => {
                    return Outcome::Error {
                        message: p.to_string(),
                        depth,
                    }
                }
            };
        if let Err(o) = self.charge(&out, depth) {
            let _ = out;
            return o;
        }

        // Recompute Git object id and verify.
        // The true type is inherited from the fully reconstructed base type.
        let actual_oid = git_object_id(base_kind, &out);
        let mut verify = format!("git-sha1={}", oid_hex(&actual_oid));
        if let Some(expected) = &entry.oid {
            verify += if expected == &oid_hex(&actual_oid) {
                " MATCH"
            } else {
                " MISMATCH"
            };
        }
        let mut steps = base_steps;
        for (i, mut st) in raw_steps.into_iter().enumerate() {
            st.base_oid = base_oid.clone();
            steps.push(StoredStep {
                hop: base_depth + 1,
                base_entry_id,
                base_oid: base_oid.clone(),
                step: st,
                verify: if i == 0 {
                    format!(
                        "base {base_kind} ({} bytes) -> delta hop {}; {verify}",
                        base_data.len(),
                        base_depth + 1
                    )
                } else {
                    verify.clone()
                },
            });
        }
        let mut sources = base_sources;
        sources.insert(entry.source_id);
        Outcome::Resolved {
            kind: base_kind,
            content: out,
            depth: base_depth + 1,
            steps,
            sources,
        }
    }
}

impl ResolveCtx {
    fn flush(&self, app: &AppState) -> RunSummary {
        let mut summary = RunSummary {
            spent: self.spent,
            ..Default::default()
        };
        let c = app.store.conn.lock().unwrap();
        for (key, outcome) in &self.memo {
            let entry_ids: Vec<i64> = self
                .groups
                .get(key)
                .map(|v| v.iter().map(|e| e.id).collect())
                .unwrap_or_default();
            let primary = match entry_ids.first() {
                Some(id) => *id,
                None => continue,
            };
            match outcome {
                Outcome::Resolved {
                    kind,
                    content,
                    depth,
                    steps,
                    ..
                } => {
                    let sha = sha256_hex(content);
                    let dir = app.store.objects_dir();
                    let obj_path = dir.join(format!("{sha}.obj"));
                    if !obj_path.exists() {
                        std::fs::write(&obj_path, content).ok();
                    }
                    let git = git_object_id(*kind, content);
                    let git_hex = oid_hex(&git);
                    let oid_ok = self
                        .groups
                        .get(key)
                        .and_then(|v| v.iter().find_map(|e| e.oid.clone()))
                        .map(|expected| expected == git_hex)
                        .unwrap_or(true);
                    c.execute(
                        "INSERT INTO resolutions(branch,entry_id,status,depth,content_sha256,\
                                content_len,git_oid,oid_ok,error,blocking_chain,attempted_at) \
                         VALUES(?1,?2,'resolved',?3,?4,?5,?6,?7,NULL,NULL,?8) \
                         ON CONFLICT(branch,entry_id) DO UPDATE SET status='resolved',\
                                depth=excluded.depth,content_sha256=excluded.content_sha256,\
                                content_len=excluded.content_len,git_oid=excluded.git_oid,\
                                oid_ok=excluded.oid_ok,error=NULL,blocking_chain=NULL,\
                                attempted_at=excluded.attempted_at",
                        params![
                            self.branch,
                            primary,
                            *depth as i64,
                            sha,
                            content.len() as i64,
                            git_hex,
                            oid_ok,
                            now_ts()
                        ],
                    )
                    .unwrap();
                    for st in steps {
                        c.execute(
                            "INSERT INTO delta_steps(branch,entry_id,hop,base_entry_id,base_oid,\
                                    instr_start,instr_end,opcode,detail,input_len,output_len,verify) \
                             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                            params![
                                self.branch,
                                primary,
                                st.hop as i64,
                                st.base_entry_id,
                                st.base_oid,
                                st.step.instr_start as i64,
                                st.step.instr_end as i64,
                                st.step.opcode as i64,
                                st.step.detail,
                                st.step.input_len as i64,
                                st.step.output_len as i64,
                                st.verify
                            ],
                        )
                        .unwrap();
                    }
                    summary.resolved += 1;
                }
                Outcome::Blocked { chain, .. } => {
                    write_nonresolved(&c, &self.branch, primary, "blocked", chain, None);
                    summary.blocked += 1;
                }
                Outcome::Error { message, .. } => {
                    let chain = vec![BlockedBy {
                        oid: key.clone(),
                        sources: entry_ids.iter().filter_map(|id| self.groups
                            .values()
                            .flatten()
                            .find(|e| e.id == *id)
                            .map(|e| e.source_id))
                            .collect(),
                        reason: message.clone(),
                    }];
                    write_nonresolved(
                        &c,
                        &self.branch,
                        primary,
                        "error",
                        &chain,
                        Some(message),
                    );
                    summary.errored += 1;
                }
                Outcome::Pending {
                    reason, chain, ..
                } => {
                    let mut chain = chain.clone();
                    chain.push(BlockedBy {
                        oid: key.clone(),
                        sources: entry_ids
                            .iter()
                            .filter_map(|id| {
                                self.groups
                                    .values()
                                    .flatten()
                                    .find(|e| e.id == *id)
                                    .map(|e| e.source_id)
                            })
                            .collect(),
                        reason: reason.clone(),
                    });
                    write_nonresolved(
                        &c,
                        &self.branch,
                        primary,
                        "pending",
                        &chain,
                        Some(reason),
                    );
                    summary.pending += 1;
                    summary.paused = true;
                }
            }
        }
        let status = if summary.paused { "paused" } else { "complete" };
        let pending_keys: Vec<String> = self
            .memo
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Pending { .. }))
            .map(|(k, _)| k.clone())
            .collect();
        c.execute(
            "INSERT INTO runs(branch,started_at,finished_at,status,total_budget,total_spent,\
                    object_cap,max_depth,pending_entries) VALUES(?1,?2,?2,?3,?4,?5,?6,?7,?8)",
            params![
                self.branch,
                now_ts(),
                status,
                self.budget.total_bytes as i64,
                self.spent as i64,
                self.budget.object_cap() as i64,
                self.budget.max_depth as i64,
                serde_json::to_string(&pending_keys).unwrap()
            ],
        )
        .unwrap();
        summary
    }
}

fn write_nonresolved(
    c: &rusqlite::Connection,
    branch: &str,
    entry_id: i64,
    status: &str,
    chain: &[BlockedBy],
    error: Option<&str>,
) {
    c.execute(
        "INSERT INTO resolutions(branch,entry_id,status,depth,content_sha256,content_len,\
                git_oid,oid_ok,error,blocking_chain,attempted_at) \
         VALUES(?1,?2,?3,0,NULL,0,NULL,0,?4,?5,?6) \
         ON CONFLICT(branch,entry_id) DO UPDATE SET status=excluded.status,\
                content_sha256=NULL,content_len=0,git_oid=NULL,oid_ok=0,\
                error=excluded.error,blocking_chain=excluded.blocking_chain,\
                attempted_at=excluded.attempted_at",
        params![
            branch,
            entry_id,
            status,
            error,
            serde_json::to_string(chain).unwrap(),
            now_ts()
        ],
    )
    .unwrap();
}

#[derive(Debug, Clone, Serialize)]
pub struct DependentsInfo {
    pub can_delete: bool,
    pub dependents: Vec<DependentEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependentEntry {
    pub entry_id: i64,
    pub oid: Option<String>,
    pub kind: String,
    pub status: String,
    pub sources: Vec<i64>,
}

impl AppState {
    /// Objects that would lose their chosen candidate if `sid` were deleted.
    pub fn delete_preview(&self, sid: i64) -> DependentsInfo {
        let entries = self.store.all_entries();
        let mut groups: BTreeMap<String, Vec<DbEntry>> = BTreeMap::new();
        for e in &entries {
            if e.role == "idx-record" {
                continue;
            }
            groups.entry(oid_key_for_entry(e)).or_default().push(e.clone());
        }
        for v in groups.values_mut() {
            v.sort_by(|a, b| {
                candidate_rank(a)
                    .cmp(&candidate_rank(b))
                    .then(a.source_id.cmp(&b.source_id))
                    .then(a.id.cmp(&b.id))
            });
        }
        let mut dependents = Vec::new();
        for (key, cands) in &groups {
            let chosen = cands.first();
            let still_has_other = cands.iter().any(|e| e.source_id != sid);
            let chosen_from_this = chosen.map(|e| e.source_id == sid).unwrap_or(false);
            if chosen_from_this && !still_has_other {
                let entry = chosen.unwrap();
                let status = self
                    .store
                    .resolution(DEFAULT_BRANCH, entry.id)
                    .map(|r| r.status)
                    .unwrap_or_else(|| "unresolved".into());
                dependents.push(DependentEntry {
                    entry_id: entry.id,
                    oid: entry.oid.clone().or_else(|| Some(key.clone())),
                    kind: entry.kind.clone(),
                    status,
                    sources: cands.iter().map(|e| e.source_id).collect(),
                });
            }
        }
        DependentsInfo {
            can_delete: dependents.is_empty(),
            dependents,
        }
    }

    pub fn delete_source(&self, sid: i64, force: bool) -> Result<DependentsInfo, String> {
        let info = self.delete_preview(sid);
        if !info.can_delete && !force {
            return Err("source still required by resolved/pending objects".into());
        }
        let src = self
            .store
            .source_by_id(sid)
            .ok_or_else(|| "source not found".to_string())?;
        if let Some(entry) = std::fs::read_dir(self.store.imports_dir())
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with(&src.sha256))
        {
            std::fs::remove_file(entry.path()).ok();
        }
        {
            let c = self.store.conn.lock().unwrap();
            c.execute("DELETE FROM sources WHERE id=?1", params![sid])
                .map_err(|e| e.to_string())?;
        }
        // Everything may shift candidate ranking: re-resolve all.
        self.resolve_branch(DEFAULT_BRANCH, None);
        Ok(info)
    }

    /// Retry after a budget pause or base addition. Scoping to pending keys
    /// keeps it local when possible.
    pub fn retry(&self, branch: &str) -> RunSummary {
        self.resolve_branch(branch, None)
    }

    pub fn create_branch(&self, name: &str) -> Result<(), String> {
        if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) {
            return Err("invalid branch name".into());
        }
        self.ensure_branch(name);
        self.resolve_branch(name, None);
        Ok(())
    }

    pub fn pin_source(&self, branch: &str, oid: &str, source_id: i64) -> Result<(), String> {
        if oid.len() != 40 || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("oid must be 40 hex chars".into());
        }
        if self.store.source_by_id(source_id).is_none() {
            return Err("source not found".into());
        }
        self.ensure_branch(branch);
        {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "INSERT INTO branches(name,note,created_at) VALUES(?1,'',?2) \
                 ON CONFLICT(name) DO NOTHING",
                params![branch, now_ts()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO pins(branch,oid,source_id) VALUES(?1,?2,?3) \
                 ON CONFLICT(branch,oid) DO UPDATE SET source_id=excluded.source_id",
                params![branch, oid, source_id],
            )
            .unwrap();
        }
        let mut scope = BTreeSet::new();
        scope.insert(oid.to_string());
        // Dependents must move with the pinned source.
        let all = self.store.all_entries();
        let mut stack = vec![oid.to_string()];
        while let Some(o) = stack.pop() {
            for e in &all {
                if e.ref_base.as_deref() == Some(o.as_str()) {
                    let k = oid_key_for_entry(e);
                    if scope.insert(k.clone()) {
                        stack.push(k);
                    }
                }
            }
        }
        self.resolve_branch(branch, Some(&scope));
        Ok(())
    }

    pub fn unpin(&self, branch: &str, oid: &str) {
        let c = self.store.conn.lock().unwrap();
        c.execute(
            "DELETE FROM pins WHERE branch=?1 AND oid=?2",
            params![branch, oid],
        )
        .unwrap();
        drop(c);
        let mut scope = BTreeSet::new();
        scope.insert(oid.to_string());
        self.resolve_branch(branch, Some(&scope));
    }

    pub fn resolved_content(&self, branch: &str, entry_id: i64) -> Option<(String, Vec<u8>)> {
        let res = self.store.resolution(branch, entry_id)?;
        if res.status != "resolved" {
            return None;
        }
        let sha = res.content_sha256?;
        let path = self.store.objects_dir().join(format!("{sha}.obj"));
        let bytes = std::fs::read(path).ok()?;
        Some((res.git_oid.unwrap_or_default(), bytes))
    }
}
