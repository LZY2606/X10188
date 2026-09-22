//! The analysis engine: import sources, resolve delta chains with budgets,
//! isolate bad objects, detect cycles, rank duplicate-oid candidates, and
//! recompute only affected subgraphs after new bases or pin changes.

use crate::error::{Error, Result};
use crate::git::{apply_delta, deflate_zlib, inflate_stream, parse_loose_body};
use crate::pack::{parse_idx, parse_pack, IdxEntry};
use crate::sha::sha1;
use crate::status::*;
use crate::store::Store;
use crate::types::{frame_object, git_object_id, hex_oid, parse_oid, ObjType, Oid20};
use rusqlite::{params, Connection};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub max_depth: u32,
    pub total_bytes: u64,
    pub per_object_ratio_num: u64,
    pub per_object_ratio_den: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            total_bytes: 64 * 1024 * 1024,
            per_object_ratio_num: 1,
            per_object_ratio_den: 4,
        }
    }
}

impl Budget {
    pub fn per_object_cap(&self) -> u64 {
        self.total_bytes * self.per_object_ratio_num / self.per_object_ratio_den
    }
}

#[derive(Clone, Debug)]
pub struct EntryRow {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    pub offset: i64,
    pub end_offset: i64,
    pub typ: String,
    pub declared_size: Option<i64>,
    pub inflated: Vec<u8>,
    pub zlib_len: Option<i64>,
    pub crc_computed: Option<i64>,
    pub crc_idx: Option<i64>,
    pub ofs_neg: Option<i64>,
    pub ref_base: Option<Oid20>,
    pub loose_oid: Option<Oid20>,
    pub claimed_oid: Option<Oid20>,
    pub computed_oid: Option<Oid20>,
    pub out_type: Option<String>,
    pub out_content: Vec<u8>,
    pub out_len: Option<i64>,
    pub status: i64,
    pub error: Option<String>,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StepRecord {
    pub step: i64,
    pub base_entry_id: Option<i64>,
    pub base_oid: Option<Oid20>,
    pub base_offset: Option<i64>,
    pub base_kind: Option<String>,
    pub range_start: i64,
    pub range_end: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub instructions: String,
    pub output_hash: Oid20,
    pub verified: bool,
}

pub struct Engine {
    pub store: Store,
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
    pub budget: Mutex<Budget>,
    pub graph_version: Mutex<i64>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Engine {
    pub fn new(data_dir: PathBuf) -> Result<Engine> {
        std::fs::create_dir_all(&data_dir)?;
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir)?;
        let store = Store::open(&data_dir.join("microscope.db"))?;
        let budget = engine_load_budget(&store).unwrap_or_default();
        let gv = store
            .get_meta("graph_version")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        Ok(Engine {
            store,
            data_dir,
            files_dir,
            budget: Mutex::new(budget),
            graph_version: Mutex::new(gv),
        })
    }

    pub fn set_budget(&self, b: Budget) -> Result<()> {
        *self.budget.lock().unwrap() = b;
        self.store
            .set_meta("budget_json", &serde_unavailable(&b))?;
        Ok(())
    }

    pub fn bump_graph(&self) -> Result<()> {
        let mut g = self.graph_version.lock().unwrap();
        *g += 1;
        self.store.set_meta("graph_version", &g.to_string())?;
        Ok(())
    }

    /// Total currently-accounted expanded bytes of resolved objects.
    pub fn used_bytes(&self) -> u64 {
        self.store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(out_len),0) FROM entries WHERE status=?1",
                params![RESOLVED],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u64
    }
}

fn serde_unavailable(b: &Budget) -> String {
    format!(
        "{},{},{},{}",
        b.max_depth, b.total_bytes, b.per_object_ratio_num, b.per_object_ratio_den
    )
}

fn engine_load_budget(store: &Store) -> Option<Budget> {
    let s = store.get_meta("budget_json")?;
    let p: Vec<u64> = s.split(',').filter_map(|x| x.parse().ok()).collect();
    if p.len() == 4 {
        Some(Budget {
            max_depth: p[0] as u32,
            total_bytes: p[1],
            per_object_ratio_num: p[2],
            per_object_ratio_den: p[3],
        })
    } else {
        None
    }
}

// Re-exported compression helper for the test pack builder living in tests.
pub fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    deflate_zlib(data)
}

/// Result of one import.
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub paired_with: Option<i64>,
    pub note: Option<String>,
    pub deduped: bool,
}

impl Engine {
    /// Import raw bytes under `filename`. Bytes are copied into the project
    /// data directory only.
    pub fn import_bytes(&self, filename: &str, data: &[u8]) -> Result<ImportReport> {
        let base = Path::new(filename)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());
        let hash = sha1(data);

        if let Some(existing) = self.source_by_content(&hash)? {
            return Ok(ImportReport {
                source_id: existing,
                kind: self
                    .conn()
                    .query_row("SELECT kind FROM sources WHERE id=?1", params![existing], |r| {
                        r.get::<_, String>(0)
                    })?,
                paired_with: None,
                note: Some("identical content already imported; deduplicated".into()),
                deduped: true,
            });
        }

        let stored_name = format!("{}-{}", hex_oid(&hash), base);
        let stored_rel = format!("files/{}", stored_name);
        std::fs::write(self.data_dir.join(&stored_rel), data)?;

        let kind = if data.len() >= 4 && &data[..4] == crate::pack::PACK_SIG {
            SRC_PACK
        } else if data.len() >= 4 && &data[..4] == crate::pack::IDX_SIG {
            SRC_IDX
        } else if parse_oid(&base.replace(".loose", "")).is_some() || looks_like_zlib(data) {
            SRC_LOOSE
        } else {
            SRC_UNKNOWN
        };

        let id = {
            let c = self.conn();
            c.execute(
                "INSERT INTO sources(kind,filename,stored_path,size,sha1,imported_at)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![kind, base, stored_rel, data.len() as i64, hash, now()],
            )?;
            c.last_insert_rowid()
        };

        let mut report = ImportReport {
            source_id: id,
            kind: kind.to_string(),
            paired_with: None,
            note: None,
            deduped: false,
        };

        match kind {
            SRC_PACK => self.import_pack(id, data, &mut report)?,
            SRC_IDX => self.import_idx(id, data, &mut report)?,
            SRC_LOOSE => self.import_loose(id, &base, data)?,
            _ => {}
        }

        self.bump_graph()?;
        Ok(report)
    }

    pub fn import_path(&self, path: &Path) -> Result<ImportReport> {
        let data = std::fs::read(path)?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        self.import_bytes(&name, &data)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.store.conn.lock().unwrap()
    }

    fn source_by_content(&self, h: &Oid20) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id FROM sources WHERE sha1=?1 ORDER BY id LIMIT 1",
                params![h],
                |r| r.get(0),
            )
            .ok())
    }

    fn import_loose(&self, id: i64, filename: &str, data: &[u8]) -> Result<()> {
        let name_stem = filename.trim_end_matches(".loose");
        let loose_oid = parse_oid(name_stem);
        let c = self.conn();
        match inflate_stream(data) {
            Ok(inf) => match parse_loose_body(&inf.out) {
                Ok((typ, payload)) => {
                    c.execute(
                        "INSERT INTO entries(source_id,kind,offset,end_offset,type,declared_size,
                           inflated,inflated_len,zlib_len,loose_oid,claimed_oid,claim_kind,
                           status,parse_error,updated_at)
                         VALUES(?1,'loose',0,?2,?3,?4,?5,?6,?7,?8,?9,'loose-name',0,NULL,?10)",
                        params![
                            id,
                            data.len() as i64,
                            typ.name(),
                            payload.len() as i64,
                            inf.out,
                            inf.out.len() as i64,
                            inf.consumed as i64,
                            loose_oid,
                            loose_oid
                        ],
                    )?;
                }
                Err(e) => {
                    c.execute(
                        "INSERT INTO entries(source_id,kind,offset,end_offset,type,inflated,
                           inflated_len,zlib_len,loose_oid,claimed_oid,claim_kind,
                           status,parse_error,updated_at)
                         VALUES(?1,'loose',0,?2,'unknown',?3,?4,?5,?6,?7,'loose-name',?8,?9,?10)",
                        params![
                            id,
                            data.len() as i64,
                            inf.out,
                            inf.out.len() as i64,
                            inf.consumed as i64,
                            loose_oid,
                            loose_oid,
                            ERROR,
                            format!("size/header deception: {e}"),
                            now()
                        ],
                    )?;
                }
            },
            Err(e) => {
                c.execute(
                    "INSERT INTO entries(source_id,kind,offset,end_offset,type,status,parse_error,updated_at)
                     VALUES(?1,'loose',0,?2,'unknown',?3,?4,?5)",
                    params![
                        id,
                        data.len() as i64,
                        ERROR,
                        format!("zlib failed halfway: {e}"),
                        now()
                    ],
                )?;
            }
        }
        Ok(())
    }
}

fn looks_like_zlib(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    (cmf & 0x0f) == 8 && ((cmf as u16) * 256 + flg as u16) % 31 == 0
}

impl Engine {
    fn import_pack(&self, id: i64, data: &[u8], report: &mut ImportReport) -> Result<()> {
        let parsed = parse_pack(data)?;
        let filename = self
            .conn()
            .query_row("SELECT filename FROM sources WHERE id=?1", params![id], |r| {
                r.get::<_, String>(0)
            })?;

        let idx_pair = self.find_idx_for(&filename, &parsed.computed_pack_sha)?;
        let mut pair_notes: Vec<String> = Vec::new();
        let mut idx_entries: Vec<IdxEntry> = Vec::new();
        let mut idx_meta: Option<(i64, i64, Option<i64>, String)> = None;

        if let Some((idx_id, idx)) = idx_pair {
            report.paired_with = Some(idx_id);
            idx_entries = idx.entries.clone();
            let fan_json = fanout_from(&idx.fanout);
            let idx_ver = idx.version as i64;
            let idx_sha_ok = idx.index_sha_ok as i64;
            idx_meta = Some((idx_id, idx_ver, Some(idx_sha_ok), fan_json));
            if idx.pack_sha != parsed.computed_pack_sha {
                pair_notes.push(format!(
                    "idx pack-sha {} does not match actual pack sha {}",
                    hex_oid(&idx.pack_sha),
                    hex_oid(&parsed.computed_pack_sha)
                ));
            }
            if !idx.index_sha_ok {
                pair_notes.push("idx file checksum mismatch".into());
            }
            if idx.fanout[255] as usize != parsed.objects.len() {
                pair_notes.push(format!(
                    "idx fanout object count {} != pack object count {}",
                    idx.fanout[255],
                    parsed.objects.len()
                ));
            }
            // Per-offset cross check: offsets present in idx but absent in pack.
            let pack_offsets: HashSet<i64> =
                parsed.objects.iter().map(|o| o.offset as i64).collect();
            for e in &idx.entries {
                if !pack_offsets.contains(&(e.offset as i64)) {
                    pair_notes.push(format!(
                        "idx names {} at offset {} which does not exist in pack",
                        hex_oid(&e.oid),
                        e.offset
                    ));
                }
            }
        } else {
            pair_notes.push("no matching .idx imported".into());
        }

        {
            let c = self.conn();
            c.execute(
                "UPDATE sources SET pack_version=?1,object_count=?2,pack_sha_claimed=?3,
                   pack_sha_computed=?4,pack_sha_ok=?5,pair_note=?6,
                   idx_version=?7,idx_sha_ok=?8,fanout=?9
                 WHERE id=?10",
                params![
                    parsed.version as i64,
                    parsed.objects.len() as i64,
                    parsed.declared_pack_sha.to_vec(),
                    parsed.computed_pack_sha.to_vec(),
                    parsed.trailer_ok as i64,
                    pair_notes.join("; "),
                    idx_meta.as_ref().map(|m| m.1),
                    idx_meta.as_ref().and_then(|m| m.2),
                    idx_meta.as_ref().map(|m| m.3.clone()),
                    id
                ],
            )?;
        }

        for (i, obj) in parsed.objects.iter().enumerate() {
            let end = if i + 1 < parsed.objects.len() {
                parsed.objects[i + 1].offset as i64
            } else {
                (data.len() - 20) as i64
            };
            let idx_hit = idx_entries.iter().find(|e| e.offset == obj.offset);
            let claimed = idx_hit.map(|e| e.oid);
            let crc_idx = idx_hit.and_then(|e| e.crc32).map(|v| v as i64);
            let crc_ok = crc_idx.map(|ci| (ci == obj.record_crc as i64) as i64);

            let mut parse_error = obj.parse_error.clone();
            let size_lie =
                obj.typ.is_base() && obj.declared_size as usize != obj.inflated.len();
            if size_lie {
                let se = format!(
                    "pack size deception: header declares {} inflated bytes, zlib yielded {}",
                    obj.declared_size,
                    obj.inflated.len()
                );
                parse_error = Some(match parse_error {
                    Some(existing) => format!("{existing}; {se}"),
                    None => se,
                });
            }
            let status = if parse_error.is_some() { ERROR } else { UNRESOLVED };
            let claim_kind = if idx_hit.is_some() { Some("idx") } else { None };

            let c = self.conn();
            c.execute(
                "INSERT INTO entries(source_id,kind,offset,end_offset,type,declared_size,
                   inflated,inflated_len,zlib_len,crc_computed,crc_idx,crc_ok,
                   ofs_neg,ref_base,claimed_oid,claim_kind,status,parse_error,updated_at)
                 VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                params![
                    id,
                    obj.offset as i64,
                    end,
                    obj.typ.name(),
                    obj.declared_size as i64,
                    obj.inflated,
                    obj.inflated.len() as i64,
                    obj.zlib_len as i64,
                    obj.record_crc as i64,
                    crc_idx,
                    crc_ok,
                    obj.ofs_neg.map(|v| v as i64),
                    obj.ref_base.map(|b| b.to_vec()),
                    claimed.map(|b| b.to_vec()),
                    claim_kind,
                    status,
                    parse_error,
                    now()
                ],
            )?;
        }

        if let Some(msg) = parsed.error {
            report.note = Some(format!("pack parsing stopped early: {msg}"));
        }
        if let Some((idx_id, _, _, _)) = idx_meta {
            self.refresh_idx_pair_note(idx_id)?;
        }
        Ok(())
    }

    fn import_idx(&self, id: i64, data: &[u8], report: &mut ImportReport) -> Result<()> {
        let parsed = parse_idx(data)?;
        let fan_json = fanout_from(&parsed.fanout);
        {
            let c = self.conn();
            c.execute(
                "UPDATE sources SET idx_version=?1,object_count=?2,pack_sha_claimed=?3,
                   idx_sha_ok=?4,fanout=?5 WHERE id=?6",
                params![
                    parsed.version as i64,
                    parsed.entries.len() as i64,
                    parsed.pack_sha.to_vec(),
                    parsed.index_sha_ok as i64,
                    fan_json,
                    id
                ],
            )?;
        }
        let filename = self
            .conn()
            .query_row("SELECT filename FROM sources WHERE id=?1", params![id], |r| {
                r.get::<_, String>(0)
            })?;
        match self.find_pack_for(&filename, &parsed.pack_sha)? {
            Some((pack_id, _, _)) => {
                report.paired_with = Some(pack_id);
                self.refresh_idx_pair_note(id)?;
            }
            None => {
                self.conn().execute(
                    "UPDATE sources SET pair_note='no matching .pack imported (index retained for fanout inspection)' WHERE id=?1",
                    params![id],
                )?;
            }
        }
        Ok(())
    }

    /// Locate the idx paired with a pack: prefer sha1 match, then basename match.
    fn find_idx_for(
        &self,
        pack_filename: &str,
        actual_pack_sha: &Oid20,
    ) -> Result<Option<(i64, crate::pack::ParsedIdx)>> {
        let rows: Vec<(i64, String, Vec<u8>)> = {
            let c = self.conn();
            let mut st = c.prepare(
                "SELECT id,filename,stored_path FROM sources WHERE kind='idx' ORDER BY id",
            )?;
            st.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?
        };
        let mut by_sha = None;
        let mut by_name = None;
        for (id, fname, spath) in rows {
            let bytes = std::fs::read(self.data_dir.join(&spath))?;
            if let Ok(idx) = parse_idx(&bytes) {
                if &idx.pack_sha == actual_pack_sha {
                    by_sha = Some((id, idx));
                    break;
                }
                if by_name.is_none() && same_basename(pack_filename, &fname) {
                    by_name = Some((id, idx));
                }
            }
        }
        Ok(by_sha.or(by_name))
    }

    fn find_pack_for(
        &self,
        idx_filename: &str,
        idx_pack_sha: &Oid20,
    ) -> Result<Option<(i64, Oid20, String)>> {
        let rows: Vec<(i64, String, Vec<u8>)> = {
            let c = self.conn();
            let mut st = c.prepare(
                "SELECT id,filename,stored_path FROM sources WHERE kind='pack' ORDER BY id",
            )?;
            st.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?
        };
        for (id, fname, spath) in rows {
            let bytes = std::fs::read(self.data_dir.join(&spath))?;
            if let Ok(pack) = parse_pack(&bytes) {
                if &pack.computed_pack_sha == idx_pack_sha {
                    return Ok(Some((id, pack.computed_pack_sha, fname)));
                }
            }
        }
        // fall back to basename pairing even when sha disagrees (mismatched evidence)
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT id,filename,stored_path FROM sources WHERE kind='pack' ORDER BY id",
        )?;
        let rows2: Vec<(i64, String, Vec<u8>)> = st
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        for (id, fname, spath) in rows2 {
            if same_basename(idx_filename, &fname) {
                let bytes = std::fs::read(self.data_dir.join(&spath))?;
                if let Ok(pack) = parse_pack(&bytes) {
                    return Ok(Some((id, pack.computed_pack_sha, fname)));
                }
            }
        }
        Ok(None)
    }

    fn refresh_idx_pair_note(&self, idx_id: i64) -> Result<()> {
        // The pack side owns the detailed pair note; mirror it on the idx.
        let note: Option<String> = self.conn().query_row(
            "SELECT s2.pair_note FROM sources s1 JOIN sources s2
               ON s2.pack_sha_computed = s1.pack_sha_claimed
             WHERE s1.id=?1 AND s2.kind='pack'",
            params![idx_id],
            |r| r.get(0),
        ).ok().flatten();
        if let Some(n) = note {
            self.conn().execute(
                "UPDATE sources SET pair_note=?1 WHERE id=?2",
                params![n, idx_id],
            )?;
        }
        Ok(())
    }
}

fn same_basename(a: &str, b: &str) -> bool {
    let stem = |f: &str| {
        Path::new(f)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    stem(a) == stem(b)
}

fn fanout_from(f: &[u32; 256]) -> String {
    f.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// ============================ delta resolution ============================

#[derive(Clone, Debug)]
pub struct ResolvedObj {
    pub out_type: ObjType,
    pub content: Vec<u8>,
    pub oid: Oid20,
    pub steps: Vec<StepRecord>,
}

#[derive(Clone, Debug)]
struct NodeResult {
    status: i64,
    error: Option<String>,
    obj: Option<ResolvedObj>,
    /// chain of entry ids from self down through bases (including self)
    chain: Vec<i64>,
}

struct Solver<'a> {
    engine: &'a Engine,
    budget: Budget,
    /// in-memory entry table loaded for this run
    entries: BTreeMap<i64, EntryRow>,
    /// by (source, offset)
    by_offset: HashMap<(i64, i64), i64>,
    /// pinned oid -> entry id
    pins: HashMap<Oid20, i64>,
    /// scratch results
    results: HashMap<i64, NodeResult>,
    /// global color for DFS: 0 white 1 gray 2 black
    color: HashMap<i64, u8>,
    /// bytes already counted toward total budget (pre-resolved)
    used: u64,
    /// ordered resolved ids during this run (for persistence)
    to_persist: Vec<i64>,
}

pub struct AnalyzeSummary {
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub cycle: usize,
    pub error: usize,
    pub used_bytes: u64,
    pub total_budget: u64,
    pub paused_reasons: Vec<(i64, String)>,
}

impl Engine {
    /// Full deterministic re-analysis. Candidate ranking is independent of
    /// import order: ties are broken by (source id, offset) only.
    pub fn analyze(&self) -> Result<AnalyzeSummary> {
        self.recompute(None)
    }

    /// Recompute only the dependency subgraph affected by the given seed entry
    /// ids (e.g. newly supplied bases). Everything else is reused from cache.
    pub fn recompute_subgraph(&self, seeds: &[i64]) -> Result<AnalyzeSummary> {
        self.recompute(Some(seeds))
    }

    fn load_entries(&self) -> Result<BTreeMap<i64, EntryRow>> {
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT id,source_id,kind,offset,end_offset,type,declared_size,
                    COALESCE(inflated,x''),inflated_len,COALESCE(zlib_len,0),
                    COALESCE(crc_computed,0),COALESCE(crc_idx,0),ofs_neg,
                    ref_base,loose_oid,claimed_oid,computed_oid,out_type,
                    COALESCE(out_content,x''),COALESCE(out_len,0),status,error,parse_error
             FROM entries ORDER BY id",
        )?;
        let rows = st.query_map([], row_to_entry)?;
        let mut map = BTreeMap::new();
        for r in rows {
            let e = r?;
            map.insert(e.id, e);
        }
        Ok(map)
    }

    fn load_pins(&self) -> Result<HashMap<Oid20, i64>> {
        let c = self.conn();
        let mut st = c.prepare("SELECT oid,entry_id FROM pins")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut m = HashMap::new();
        for r in rows {
            let (oid, id) = r?;
            if oid.len() == 20 {
                let mut a = [0u8; 20];
                a.copy_from_slice(&oid);
                m.insert(a, id);
            }
        }
        Ok(m)
    }

    fn recompute(&self, seeds: Option<&[i64]>) -> Result<AnalyzeSummary> {
        let budget = *self.budget.lock().unwrap();
        let entries = self.load_entries()?;
        let pins = self.load_pins()?;

        // Entries forced to recompute: explicit seeds, plus everything in their
        // reverse dependency closure (ref + ofs edges).
        let mut force: HashSet<i64> = HashSet::new();
        if let Some(seeds) = seeds {
            for s in seeds {
                force.insert(*s);
            }
            // grow closure iteratively
            let mut changed = true;
            while changed {
                changed = false;
                for (id, e) in &entries {
                    if force.contains(id) {
                        continue;
                    }
                    let points = matches_seed_dep(e, &force, &entries);
                    if points {
                        force.insert(*id);
                        changed = true;
                    }
                }
            }
        }

        let mut by_offset = HashMap::new();
        for (id, e) in &entries {
            by_offset.insert((e.source_id, e.offset), *id);
        }

        let mut used: u64 = 0;
        // Reset forced entries to unresolved; keep others' cached resolution.
        {
            let c = self.conn();
            for id in &force {
                c.execute(
                    "UPDATE entries SET status=0,error=NULL,out_type=NULL,
                        out_content=NULL,out_len=NULL,updated_at=?1 WHERE id=?2",
                    params![now(), id],
                )?;
                c.execute("DELETE FROM delta_steps WHERE entry_id=?1", params![id])?;
            }
        }

        let mut solver = Solver {
            engine: self,
            budget,
            entries,
            by_offset,
            pins,
            results: HashMap::new(),
            color: HashMap::new(),
            used: 0,
            to_persist: Vec::new(),
        };

        // count bytes of already-resolved (cached) objects; seed-reset ones
        // excluded because they were set unresolved above.
        for e in solver.entries.values() {
            if e.status == RESOLVED {
                if let Some(l) = e.out_len {
                    solver.used = solver.used.saturating_add(l.max(0) as u64);
                }
            }
        }

        // Pre-validate bases (loose header/oid and pack frame consistency) and
        // resolve all remaining ids in deterministic entry-id order.
        let ids: Vec<i64> = solver.entries.keys().copied().collect();
        for id in &ids {
            if solver.results.contains_key(id) {
                continue;
            }
            solver.resolve(*id, Vec::new(), 0)?;
        }

        // Persist computed results for freshly resolved/failed entries.
        solver.persist()?;

        // Recount final statuses directly from the DB for an authoritative view.
        let summary = self.summarize(budget);
        Ok(summary)
    }

    fn summarize(&self, budget: Budget) -> Result<AnalyzeSummary> {
        let c = self.conn();
        let mut counts = [0usize; 6];
        let mut st = c.prepare("SELECT status, COUNT(*) FROM entries GROUP BY status")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (s, n) = r?;
            let idx = match s {
                RESOLVED => 0,
                BLOCKED => 1,
                PAUSED => 2,
                CYCLE => 3,
                ERROR => 4,
                _ => 5,
            };
            counts[idx] += n as usize;
        }
        let used = c
            .query_row(
                "SELECT COALESCE(SUM(out_len),0) FROM entries WHERE status=?1",
                params![RESOLVED],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u64;
        let mut paused_reasons = Vec::new();
        let mut st2 = c.prepare("SELECT id,error FROM entries WHERE status=?1")?;
        let rows2 = st2.query_map(params![PAUSED], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        for r in rows2 {
            let (id, e) = r?;
            paused_reasons.push((id, e));
        }
        Ok(AnalyzeSummary {
            resolved: counts[0],
            blocked: counts[1],
            paused: counts[2],
            cycle: counts[3],
            error: counts[4],
            used_bytes: used,
            total_budget: budget.total_bytes,
            paused_reasons,
        })
    }
}

/// Does entry `e` have a base (ofs/ref) that resolves into the seed set?
fn matches_seed_dep(e: &EntryRow, force: &HashSet<i64>, entries: &BTreeMap<i64, EntryRow>) -> bool {
    match e.typ.as_str() {
        "ofs-delta" => {
            if let Some(neg) = e.ofs_neg {
                let base_off = e.offset - neg;
                if let Some(b) = entries
                    .values()
                    .find(|b| b.source_id == e.source_id && b.offset == base_off)
                {
                    return force.contains(&b.id);
                }
            }
            false
        }
        "ref-delta" => {
            if let Some(_base_oid) = e.ref_base {
                return entries.values().any(|cand| {
                    force.contains(&cand.id)
                        && cand.status == RESOLVED
                        && (Some(cand.id) == None)
                }) || ref_target_in(e, entries, force);
            }
            false
        }
        _ => false,
    }
}

fn ref_target_in(e: &EntryRow, entries: &BTreeMap<i64, EntryRow>, force: &HashSet<i64>) -> bool {
    // computed lazily without full ranking: if any forced entry claims or hashes
    // to the ref oid, this entry depends on it.
    let Some(oid) = e.ref_base else { return false };
    entries
        .values()
        .filter(|c| c.computed_oid == Some(oid) || c.claimed_oid == Some(oid))
        .any(|c| force.contains(&c.id))
}

impl<'a> Solver<'a> {
    fn e(&self, id: i64) -> &EntryRow {
        &self.entries[&id]
    }

    /// Recursive DFS. Depth is bounded by `budget.max_depth`, which also makes
    /// stack use finite. Cycle membership is taken from the current path.
    fn resolve(&mut self, id: i64, path: &[i64], depth: u32) -> Result<()> {
        if self.results.contains_key(&id) {
            return Ok(());
        }
        if let Some(pos) = path.iter().position(|x| *x == id) {
            let cyc: Vec<i64> = path[pos..].to_vec();
            let msg = format!(
                "delta cycle: {}",
                cyc.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            for nid in &cyc {
                self.results.insert(
                    *nid,
                    NodeResult {
                        status: CYCLE,
                        error: Some(msg.clone()),
                        obj: None,
                        chain: cyc.clone(),
                    },
                );
            }
            return Ok(());
        }

        let entry = self.entries[&id].clone();
        if entry.parse_error.is_some() {
            self.finish_failure(id, ERROR, entry.parse_error.clone().unwrap_or_default());
            return Ok(());
        }

        let is_delta = matches!(entry.typ.as_str(), "ofs-delta" | "ref-delta");
        if is_delta && depth + 1 > self.budget.max_depth {
            self.finish_failure(
                id,
                PAUSED,
                format!(
                    "delta depth budget exceeded (limit {}); retryable",
                    self.budget.max_depth
                ),
            );
            return Ok(());
        }

        if !is_delta {
            self.resolve_base(&entry);
            return Ok(());
        }

        // Locate the base (may be missing or ambiguous).
        let base_pick: std::result::Result<i64, (i64, String)> = match entry.typ.as_str() {
            "ofs-delta" => self.ofs_base_id(&entry).map_err(|m| (BLOCKED, m)),
            _ => self.ref_base_id(&entry).map_err(|m| (BLOCKED, m)),
        };
        let base_id = match base_pick {
            Ok(b) => b,
            Err((st, m)) => {
                self.finish_failure(id, st, m);
                return Ok(());
            }
        };

        let mut child_path = path.to_vec();
        child_path.push(id);
        self.resolve(base_id, &child_path, depth + 1)?;
        let base_res = match self.results.get(&base_id) {
            Some(r) => r.clone(),
            None => {
                self.finish_failure(
                    id,
                    BLOCKED,
                    "base could not be resolved".into(),
                );
                return Ok(());
            }
        };
        if base_res.status != RESOLVED {
            self.finish_from_base(id, base_res.status, base_res.error);
            return Ok(());
        }

        self.apply_chain(&entry, base_id, depth + 1)
    }

    fn finish_failure(&mut self, id: i64, status: i64, error: String) {
        self.results.insert(
            id,
            NodeResult {
                status,
                error: Some(error),
                obj: None,
                chain: vec![id],
            },
        );
    }

    fn finish_from_base(&mut self, id: i64, base_status: i64, base_error: Option<String>) {
        let (status, error) = if matches!(base_status, BLOCKED | PAUSED | CYCLE) {
            (
                BLOCKED,
                Some(format!(
                    "base unavailable ({}){}",
                    crate::status::name(base_status),
                    base_error.map(|e| format!(": {e}")).unwrap_or_default()
                )),
            )
        } else {
            (
                ERROR,
                Some(format!(
                    "base is {}: {}",
                    crate::status::name(base_status),
                    base_error.unwrap_or_default()
                )),
            )
        };
        self.results.insert(
            id,
            NodeResult {
                status,
                error,
                obj: None,
                chain: vec![id],
            },
        );
    }

    /// Resolve a non-delta entry and recompute its git object id.
    fn resolve_base(&mut self, entry: &EntryRow) {
        let typ = match ObjType::parse(&entry.typ) {
            Some(t) => t,
            None => {
                self.finish_failure(entry.id, ERROR, format!("bad type {}", entry.typ));
                return;
            }
        };
        let content = if entry.kind == "loose" {
            match payload_after_nul(&entry.inflated) {
                Ok((t, p)) => {
                    if t != typ {
                        self.finish_failure(
                            entry.id,
                            ERROR,
                            format!("loose type mismatch: {} vs {}", t.name(), typ.name()),
                        );
                        return;
                    }
                    p
                }
                Err(e) => {
                    self.finish_failure(entry.id, ERROR, e.to_string());
                    return;
                }
            }
        } else {
            entry.inflated.clone()
        };

        if let Some(decl) = entry.declared_size {
            if decl as usize != content.len() {
                self.finish_failure(
                    entry.id,
                    ERROR,
                    format!("size deception: declared {decl}, actual {}", content.len()),
                );
                return;
            }
        }

        let oid = git_object_id(typ, &content);
        let mismatch = entry.claimed_oid.filter(|c| *c != oid).map(|c| {
            format!(
                "object id mismatch: {} claims {}, recomputed {}",
                entry_label(entry),
                hex_oid(&c),
                hex_oid(&oid)
            )
        });
        let mut e = entry.clone();
        e.computed_oid = Some(oid);
        self.entries.insert(e.id, e);
        let status = if mismatch.is_some() { ERROR } else { RESOLVED };
        self.results.insert(
            entry.id,
            NodeResult {
                status,
                error: mismatch,
                obj: Some(ResolvedObj {
                    out_type: typ,
                    content,
                    oid,
                    steps: Vec::new(),
                }),
                chain: vec![entry.id],
            },
        );
    }
}


fn payload_after_nul(frame: &[u8]) -> Result<(ObjType, Vec<u8>)> {
    let nul = frame
        .iter()
        .position(|b| *b == 0)
        .ok_or("loose frame missing NUL")?;
    let header = std::str::from_utf8(&frame[..nul]).map_err(|_| "loose frame header utf8")?;
    let (t, l) = header.split_once(' ').ok_or("loose frame header malformed")?;
    let typ = ObjType::parse(t).ok_or("loose frame unknown type")?;
    let len: usize = l.parse().map_err(|_| "loose frame bad size")?;
    let body = &frame[nul + 1..];
    if len != body.len() {
        return Err(format!(
            "loose frame size deception: header {len}, body {}",
            body.len()
        )
        .into());
    }
    Ok((typ, body.to_vec()))
}

fn entry_label(e: &EntryRow) -> String {
    format!("#{} ({}@{})", e.id, e.source_id, e.offset)
}

impl<'a> Solver<'a> {
    /// Resolve an ofs-delta base: must point backwards within the same pack to
    /// an existing object header.
    fn ofs_base_id(&self, entry: &EntryRow) -> std::result::Result<i64, String> {
        let neg = entry
            .ofs_neg
            .ok_or_else(|| "ofs-delta missing negative offset".to_string())?;
        let base_off = entry.offset.checked_sub(neg).ok_or_else(|| {
            format!(
                "ofs distance {} underflows from offset {}",
                neg, entry.offset
            )
        })?;
        if base_off < 12 {
            return Err(format!("ofs-delta base offset {base_off} precedes pack header"));
        }
        match self.by_offset.get(&(entry.source_id, base_off)) {
            Some(id) => Ok(*id),
            None => Err(format!(
                "ofs-delta base at offset {base_off} not found in pack (distance {neg} overshoots object boundaries)"
            )),
        }
    }

    /// Rank candidates for a ref-delta base oid. The order never depends on
    /// import order: pinned branch wins, then correctness, source, offset.
    fn ref_base_id(&self, entry: &EntryRow) -> std::result::Result<i64, String> {
        let oid = entry
            .ref_base
            .ok_or_else(|| "ref-delta missing base oid".to_string())?;

        if let Some(pinned) = self.pins.get(&oid) {
            if self.entries.contains_key(pinned) {
                return Ok(*pinned);
            }
        }

        let mut ranked: Vec<(i64, i64, i64)> = Vec::new(); // (rank, source, id)
        for cand in self.entries.values() {
            let claimed_match = cand.claimed_oid == Some(oid);
            let computed_match = cand.computed_oid == Some(oid);
            if !claimed_match && !computed_match {
                continue;
            }
            // A claimed oid whose recomputation contradicts cannot serve.
            if claimed_match && cand.computed_oid.is_some() && cand.computed_oid != Some(oid) {
                continue;
            }
            let rank = match (computed_match, claimed_match) {
                (true, true) => 0,
                (true, false) => 1,
                (false, true) => 2,
                _ => 3,
            };
            ranked.push((rank, cand.source_id, cand.id));
        }
        ranked.sort_by_key(|(rank, src, id)| (*rank, *src, self.entries[id].offset, *id));

        if ranked.is_empty() {
            return Err(format!(
                "external base {} not found among imported objects",
                hex_oid(&oid)
            ));
        }
        let best = ranked[0].2;
        if ranked.len() > 1 && self.pins.get(&oid).is_none() {
            // Multiple sources of the same oid is a conflict; ranking still
            // proceeds deterministically, but the caller can pin a branch.
            let ids: Vec<String> = ranked
                .iter()
                .take(4)
                .map(|(_, _, id)| id.to_string())
                .collect();
            self.engine.note_conflict(oid, ranked.iter().map(|r| r.2).collect::<Vec<_>>());
            let _ = ids;
        }
        Ok(best)
    }

    /// Apply one delta level against an already-resolved base, checking size
    /// claims, budgets, and recomputing the output git object id.
    fn apply_chain(
        &mut self,
        entry: &EntryRow,
        base_id: i64,
        _depth: u32,
    ) -> Result<()> {
        let base_obj = self.results[&base_id]
            .obj
            .clone()
            .expect("resolved base carries object");
        let base_entry = self.entries[&base_id].clone();

        let delta_bytes: Vec<u8> = if entry.kind == "pack" {
            // ofs-delta inflate gives raw delta; ref-delta inflate has 20-byte
            // base name prefix consumed at parse time, so inflated is raw delta.
            entry.inflated.clone()
        } else {
            entry.inflated.clone()
        };

        // Per-object size cap is enforced against the delta header's promised
        // result size before committing output bytes.
        let promised = peek_delta_result_size(&delta_bytes).unwrap_or(0);
        let cap = self.budget.per_object_cap();
        if promised > cap {
            self.finish_failure(
                entry.id,
                PAUSED,
                format!(
                    "object would expand to {promised} bytes, exceeding single-object cap {cap} ({} of total budget); retryable",
                    ratio_text(self.budget)
                ),
            );
            return Ok(());
        }

        let applied = match apply_delta(&base_obj.content, &delta_bytes) {
            Ok(a) => a,
            Err(e) => {
                self.finish_failure(
                    entry.id,
                    ERROR,
                    format!("delta application failed: {e}"),
                );
                return Ok(());
            }
        };

        if applied.result_size > cap as usize {
            self.finish_failure(
                entry.id,
                PAUSED,
                format!(
                    "expanded object {} bytes exceeds single-object cap {cap}; retryable",
                    applied.result_size
                ),
            );
            return Ok(());
        }

        // Total expanded-byte budget: account this object's final output plus
        // its intermediate base bytes if the base chain is part of this object.
        let add = applied.result_size as u64;
        if self.used.saturating_add(add) > self.budget.total_bytes {
            self.finish_failure(
                entry.id,
                PAUSED,
                format!(
                    "total expansion budget {} bytes exhausted at +{} (used {}); retryable",
                    self.budget.total_bytes, add, self.used
                ),
            );
            return Ok(());
        }
        self.used = self.used.saturating_add(add);

        let out_oid = git_object_id(base_obj.out_type, &applied.out);

        // One detailed step record for this delta hop.
        let instr_json = encode_instructions(&applied.cmds);
        let n_copy = applied.cmds.iter().filter(|c| c.kind == "copy").count();
        let n_ins = applied.cmds.len() - n_copy;
        let step = StepRecord {
            step: (base_obj.steps.len() as i64) + 1,
            base_entry_id: Some(base_id),
            base_oid: Some(base_obj.oid),
            base_offset: Some(base_entry.offset),
            base_kind: Some(base_entry.typ.clone()),
            range_start: 0,
            range_end: delta_bytes.len() as i64,
            input_len: base_obj.content.len() as i64,
            output_len: applied.result_size as i64,
            instructions: format!(
                "{{\"copy\":{n_copy},\"insert\":{n_ins},\"delta_bytes\":{},\"ops\":{instr_json}}}",
                delta_bytes.len()
            ),
            output_hash: out_oid,
            verified: true,
        };

        let mut steps = base_obj.steps.clone();
        steps.push(step);

        let mut mismatch = None;
        if let Some(claimed) = entry.claimed_oid {
            if claimed != out_oid {
                mismatch = Some(format!(
                    "object id mismatch after reconstruction: {} claims {}, recomputed {}",
                    entry_label(entry),
                    hex_oid(&claimed),
                    hex_oid(&out_oid)
                ));
            }
        }
        let mut e = entry.clone();
        e.computed_oid = Some(out_oid);
        self.entries.insert(e.id, e);

        let status = if mismatch.is_some() { ERROR } else { RESOLVED };
        self.results.insert(
            entry.id,
            NodeResult {
                status,
                error: mismatch,
                obj: Some(ResolvedObj {
                    out_type: base_obj.out_type,
                    content: applied.out,
                    oid: out_oid,
                    steps,
                }),
                chain: {
                    let mut c = vec![entry.id];
                    c.extend_from_slice(&self.results[&base_id].chain);
                    c
                },
            },
        );
        Ok(())
    }
}

fn ratio_text(b: Budget) -> String {
    format!("{}/{}", b.per_object_ratio_num, b.per_object_ratio_den)
}

/// Read only the two leading varints (base size, result size) of a delta.
fn peek_delta_result_size(delta: &[u8]) -> std::result::Result<u64, ()> {
    let mut p = 0usize;
    let mut read = || -> std::result::Result<u64, ()> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = *delta.get(p).ok_or(())?;
            p += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(v)
    };
    let _ = read()?;
    read()
}

fn encode_instructions(cmds: &[crate::git::DeltaCmd]) -> String {
    let mut s = String::from("[");
    for (i, c) in cmds.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"op\":\"{}\",\"range\":[{},{}],\"off\":{},\"len\":{}}}",
            c.kind, c.cmd_start, c.cmd_end, c.src_off, c.src_len
        ));
    }
    s.push(']');
    s
}

impl<'a> Solver<'a> {
    /// Persist every node computed during this run. Cached nodes that were not
    /// recomputed keep their existing rows and step history.
    fn persist(&mut self) -> Result<()> {
        let results = std::mem::take(&mut self.results);
        let entries = std::mem::take(&mut self.entries);
        let c = self.engine.conn();
        for (id, r) in results {
            let entry = match entries.get(&id) {
                Some(e) => e.clone(),
                None => continue,
            };
            match (&r.obj, r.status) {
                (Some(obj), RESOLVED) => {
                    c.execute(
                        "UPDATE entries SET computed_oid=?1,out_type=?2,out_content=?3,
                           out_len=?4,status=?5,error=NULL,updated_at=?6 WHERE id=?7",
                        params![
                            obj.oid.to_vec(),
                            obj.out_type.name(),
                            obj.content,
                            obj.content.len() as i64,
                            RESOLVED,
                            now(),
                            id
                        ],
                    )?;
                    if !obj.steps.is_empty() {
                        c.execute("DELETE FROM delta_steps WHERE entry_id=?1", params![id])?;
                        for st in &obj.steps {
                            c.execute(
                                "INSERT INTO delta_steps(entry_id,step,base_entry_id,base_oid,
                                   base_offset,base_kind,delta_cmd_range_start,delta_cmd_range_end,
                                   input_len,output_len,instructions,output_hash,verified)
                                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                                params![
                                    id,
                                    st.step,
                                    st.base_entry_id,
                                    st.base_oid.map(|o| o.to_vec()),
                                    st.base_offset,
                                    st.base_kind,
                                    st.range_start,
                                    st.range_end,
                                    st.input_len,
                                    st.output_len,
                                    st.instructions,
                                    st.output_hash.to_vec(),
                                    st.verified as i64
                                ],
                            )?;
                        }
                    }
                }
                _ => {
                    c.execute(
                        "UPDATE entries SET computed_oid=?1,out_type=NULL,out_content=NULL,
                           out_len=NULL,status=?2,error=?3,updated_at=?4 WHERE id=?5",
                        params![
                            entry.computed_oid.map(|o| o.to_vec()),
                            r.status,
                            r.error,
                            now(),
                            id
                        ],
                    )?;
                    c.execute("DELETE FROM delta_steps WHERE entry_id=?1", params![id])?;
                }
            }
        }
        Ok(())
    }
}

impl EntryRow {
    pub fn source_id_i64(&self) -> i64 {
        self.source_id
    }
    pub fn payload(&self) -> Vec<u8> {
        self.inflated.clone()
    }
}

fn row_to_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    let blob20 = |v: Option<Vec<u8>>| -> Option<Oid20> {
        v.and_then(|b| {
            if b.len() == 20 {
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                Some(a)
            } else {
                None
            }
        })
    };
    Ok(EntryRow {
        id: r.get(0)?,
        source_id: r.get(1)?,
        kind: r.get(2)?,
        offset: r.get(3)?,
        end_offset: r.get(4)?,
        typ: r.get(5)?,
        declared_size: r.get(6)?,
        inflated: r.get::<_, Vec<u8>>(7)?,
        zlib_len: Some(r.get::<_, i64>(9)?),
        crc_computed: Some(r.get::<_, i64>(10)?),
        crc_idx: Some(r.get::<_, i64>(11)?),
        ofs_neg: r.get(12)?,
        ref_base: blob20(r.get(13)?),
        loose_oid: blob20(r.get(14)?),
        claimed_oid: blob20(r.get(15)?),
        computed_oid: blob20(r.get(16)?),
        out_type: r.get(17)?,
        out_content: r.get::<_, Vec<u8>>(18)?,
        out_len: Some(r.get::<_, i64>(19)?),
        status: r.get(20)?,
        error: r.get(21)?,
        parse_error: r.get(22)?,
    })
}

// ============================ query / branch / delete ============================

#[derive(Clone, Debug)]
pub struct CandidateInfo {
    pub entry_id: i64,
    pub source_id: i64,
    pub filename: String,
    pub offset: i64,
    pub kind: String,
    pub out_type: Option<String>,
    pub out_len: Option<i64>,
    pub status: i64,
    pub claimed_oid: Option<Oid20>,
    pub computed_oid: Option<Oid20>,
    pub pinned: bool,
}

#[derive(Clone, Debug)]
pub struct BlockingNode {
    pub entry_id: i64,
    pub source_id: i64,
    pub filename: String,
    pub offset: i64,
    pub typ: String,
    pub status: i64,
    pub error: Option<String>,
}

impl Engine {
    fn note_conflict(&self, oid: Oid20, entry_ids: Vec<i64>) {
        // Persist a lightweight conflict log into meta for the UI.
        let key = format!("conflict:{}", hex_oid(&oid));
        let val = entry_ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let _ = self.store.set_meta(&key, &val);
    }

    pub fn conflicts(&self) -> Vec<(Oid20, Vec<i64>)> {
        let c = self.conn();
        let mut st = match c.prepare("SELECT key,value FROM meta WHERE key LIKE 'conflict:%'") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .into_iter()
            .flatten();
        let mut out = Vec::new();
        for r in rows {
            if let Ok((k, v)) = r {
                if let Some(oid) = parse_oid(k.trim_start_matches("conflict:")) {
                    let ids = v.split(',').filter_map(|s| s.parse().ok()).collect();
                    out.push((oid, ids));
                }
            }
        }
        out
    }

    pub fn candidates_for(&self, oid: Oid20) -> Result<Vec<CandidateInfo>> {
        let pinned = self.load_pins()?;
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT e.id,e.source_id,s.filename,e.offset,e.type,e.out_type,e.out_len,e.status,
                    e.claimed_oid,e.computed_oid
             FROM entries e JOIN sources s ON s.id=e.source_id
             WHERE e.claimed_oid=?1 OR e.computed_oid=?1
             ORDER BY e.source_id, e.offset, e.id",
        )?;
        let rows = st.query_map(params![oid.to_vec()], |r| {
            let b = |v: rusqlite::Result<Option<Vec<u8>>>| -> Option<Oid20> {
                v.ok().flatten().and_then(|x| {
                    if x.len() == 20 {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&x);
                        Some(a)
                    } else {
                        None
                    }
                })
            };
            Ok(CandidateInfo {
                entry_id: r.get(0)?,
                source_id: r.get(1)?,
                filename: r.get(2)?,
                offset: r.get(3)?,
                kind: r.get(4)?,
                out_type: r.get(5)?,
                out_len: r.get(6)?,
                status: r.get(7)?,
                claimed_oid: b(r.get(8)),
                computed_oid: b(r.get(9)),
                pinned: pinned.get(&oid).copied() == Some(r.get::<_, i64>(0).unwrap_or(-1)),
            })
        })?;
        let mut v = Vec::new();
        for r in rows {
            v.push(r?);
        }
        for cand in &mut v {
            cand.pinned = pinned.get(&oid) == Some(&cand.entry_id);
        }
        Ok(v)
    }

    /// Pin a specific conflicting source for an oid, creating an analysis
    /// branch. Only the affected dependency subgraph is recomputed.
    pub fn pin(&self, oid: Oid20, entry_id: i64) -> Result<()> {
        let exists: bool = self.conn().query_row(
            "SELECT 1 FROM entries WHERE id=?1 AND (claimed_oid=?2 OR computed_oid=?2)",
            params![entry_id, oid.to_vec()],
            |_| Ok(()),
        ).is_ok();
        if !exists {
            return Err(format!("entry {entry_id} is not a candidate for {}", hex_oid(&oid)).into());
        }
        {
            let c = self.conn();
            c.execute(
                "INSERT INTO pins(oid,entry_id,created_at) VALUES(?1,?2,?3)
                 ON CONFLICT(oid) DO UPDATE SET entry_id=?2,created_at=?3",
                params![oid.to_vec(), entry_id, now()],
            )?;
        }
        self.bump_graph()?;
        // Dependents: any ref-delta naming this oid, plus their transitive chain.
        let affected = self.ref_closure_for_oid(oid)?;
        self.recompute(Some(&affected))?;
        Ok(())
    }

    pub fn unpin(&self, oid: Oid20) -> Result<()> {
        self.conn().execute("DELETE FROM pins WHERE oid=?1", params![oid.to_vec()])?;
        self.bump_graph()?;
        let affected = self.ref_closure_for_oid(oid)?;
        self.recompute(Some(&affected))?;
        Ok(())
    }

    fn ref_closure_for_oid(&self, oid: Oid20) -> Result<Vec<i64>> {
        let entries = self.load_entries()?;
        let mut seeds: HashSet<i64> = entries
            .values()
            .filter(|e| e.ref_base == Some(oid))
            .map(|e| e.id)
            .collect();
        // Transitive ofs/ref dependents.
        let mut changed = true;
        while changed {
            changed = false;
            for e in entries.values() {
                if seeds.contains(&e.id) {
                    continue;
                }
                let dep = match e.typ.as_str() {
                    "ofs-delta" => {
                        if let Some(neg) = e.ofs_neg {
                            let base_off = e.offset - neg;
                            entries
                                .values()
                                .any(|b| b.source_id == e.source_id && b.offset == base_off && seeds.contains(&b.id))
                        } else {
                            false
                        }
                    }
                    "ref-delta" => {
                        let Some(bo) = e.ref_base else { continue false };
                        let direct = entries
                            .values()
                            .any(|c| seeds.contains(&c.id) && (c.computed_oid == Some(bo) || c.claimed_oid == Some(bo)));
                        direct
                    }
                    _ => false,
                };
                if dep {
                    seeds.insert(e.id);
                    changed = true;
                }
            }
        }
        Ok(seeds.into_iter().collect())
    }

    /// List objects that still depend on a source; used as a guard before
    /// deleting its file. Returns candidate entries referencing the source.
    pub fn source_dependents(&self, source_id: i64) -> Result<Vec<BlockingNode>> {
        let c = self.conn();
        let mut st = c.prepare(
            "WITH RECURSIVE deps(id) AS (
                SELECT id FROM entries WHERE source_id=?1
                UNION
                SELECT e.id FROM entries e
                JOIN delta_steps ds ON ds.base_entry_id IN (SELECT id FROM deps)
                  AND ds.entry_id=e.id
             )
             SELECT e.id,e.source_id,s.filename,e.offset,e.type,e.status,e.error
             FROM entries e JOIN sources s ON s.id=e.source_id
             WHERE e.id IN deps ORDER BY e.id",
        )?;
        let rows = st.query_map(params![source_id], |r| {
            Ok(BlockingNode {
                entry_id: r.get(0)?,
                source_id: r.get(1)?,
                filename: r.get(2)?,
                offset: r.get(3)?,
                typ: r.get(4)?,
                status: r.get(5)?,
                error: r.get(6)?,
            })
        })?;
        let mut v = Vec::new();
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    /// Delete a source. By default this refuses while non-resolved objects or
    /// resolved deltas from other packs still depend on it. `force` bypasses.
    pub fn delete_source(&self, source_id: i64, force: bool) -> Result<Vec<BlockingNode>> {
        let local: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM entries WHERE source_id=?1",
            params![source_id],
            |r| r.get(0),
        )?;
        let external_dependents: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM delta_steps ds JOIN entries e ON e.id=ds.entry_id
             JOIN entries b ON b.id=ds.base_entry_id
             WHERE b.source_id=?1 AND e.source_id<>?1",
            params![source_id],
            |r| r.get(0),
        )?;
        let unresolved_local: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM entries WHERE source_id=?1 AND status<>?2",
            params![source_id, RESOLVED],
            |r| r.get(0),
        )?;
        let deps = self.source_dependents(source_id)?;
        if !force && (external_dependents > 0 || unresolved_local > 0) {
            return Err(Error::Msg(format!(
                "refusing delete: {} local objects ({} unresolved), {} external dependents still need this source",
                local, unresolved_local, external_dependents
            )));
        }
        let stored: String = self.conn().query_row(
            "SELECT stored_path FROM sources WHERE id=?1",
            params![source_id],
            |r| r.get(0),
        )?;
        {
            let c = self.conn();
            c.execute("DELETE FROM delta_steps WHERE entry_id IN (SELECT id FROM entries WHERE source_id=?1)", params![source_id])?;
            c.execute("DELETE FROM delta_steps WHERE base_entry_id IN (SELECT id FROM entries WHERE source_id=?1)", params![source_id])?;
            c.execute("DELETE FROM pins WHERE entry_id IN (SELECT id FROM entries WHERE source_id=?1)", params![source_id])?;
            c.execute("DELETE FROM entries WHERE source_id=?1", params![source_id])?;
            c.execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
        }
        let _ = std::fs::remove_file(self.data_dir.join(&stored));
        self.bump_graph()?;
        Ok(deps)
    }

    /// Blocking chain for an unresolved entry: walk base pointers until a root
    /// blocker (missing base / cycle / paused / errored object) is reached.
    pub fn blocking_chain(&self, entry_id: i64) -> Result<Vec<BlockingNode>> {
        let entries = self.load_entries()?;
        let mut chain = Vec::new();
        let mut cur = entry_id;
        let mut seen = HashSet::new();
        loop {
            let Some(e) = entries.get(&cur).cloned() else { break };
            let fname = self.source_filename(e.source_id).unwrap_or_default();
            chain.push(BlockingNode {
                entry_id: e.id,
                source_id: e.source_id,
                filename: fname.clone(),
                offset: e.offset,
                typ: e.typ.clone(),
                status: e.status,
                error: e.error.clone().or(e.parse_error.clone()),
            });
            if e.status == RESOLVED {
                break;
            }
            if !seen.insert(cur) {
                break;
            }
            let next = match e.typ.as_str() {
                "ofs-delta" => {
                    let Some(neg) = e.ofs_neg else { break };
                    let base_off = e.offset - neg;
                    entries
                        .values()
                        .find(|b| b.source_id == e.source_id && b.offset == base_off)
                        .map(|b| b.id)
                }
                "ref-delta" => {
                    let Some(oid) = e.ref_base else { break };
                    self.pick_base_for_chain(&entries, oid)
                }
                _ => None,
            };
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        Ok(chain)
    }

    fn pick_base_for_chain(
        &self,
        entries: &BTreeMap<i64, EntryRow>,
        oid: Oid20,
    ) -> Option<i64> {
        if let Some(p) = self.pins.get(&oid).or_else(|| {
            let p = self.load_pins().ok()?;
            p.get(&oid).copied()
        }) {
            return Some(p);
        }
        let mut best: Option<(i64, i64, i64)> = None;
        for c in entries.values() {
            let cm = c.computed_oid == Some(oid);
            let cl = c.claimed_oid == Some(oid);
            if !cm && !cl {
                continue;
            }
            if cl && c.computed_oid.is_some() && c.computed_oid != Some(oid) {
                continue;
            }
            let rank = match (cm, cl) {
                (true, true) => 0,
                (true, false) => 1,
                _ => 2,
            };
            let key = (rank, c.source_id, c.id);
            if best.map(|b| key < b).unwrap_or(true) {
                best = Some(key);
            }
        }
        best.map(|(_, _, id)| id)
    }

    pub fn source_filename(&self, id: i64) -> Option<String> {
        self.conn()
            .query_row("SELECT filename FROM sources WHERE id=?1", params![id], |r| {
                r.get(0)
            })
            .ok()
    }
}
