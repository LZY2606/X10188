use crate::budget::{BudgetHit, Budgets};
use crate::delta::{apply_delta, parse_delta, DeltaProgram};
use crate::hash::{object_id, sha1_bytes, sha1_hex};
use crate::idx::{parse_idx, IdxParse};
use crate::oid::Oid;
use crate::pack::{parse_pack, PackEntry, PackParse};
use crate::types::GitType;
use crate::zlib::inflate_all;
use rusqlite::params;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Blocked,
    Paused,
    Corrupt,
    Cycle,
}

impl Status {
    pub fn as_row(&self) -> &'static str {
        match self {
            Status::Ok => "resolved",
            Status::Blocked => "blocked",
            Status::Paused => "paused",
            Status::Corrupt => "corrupt",
            Status::Cycle => "cycle",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub at: String,
    pub mechanism: String,
    pub base: Option<String>,
    pub instr_range: Option<(usize, usize)>,
    pub op_count: Option<usize>,
    pub input_len: u64,
    pub output_len: u64,
    pub declared_size: u64,
    pub size_ok: bool,
    pub oid: Option<String>,
    pub oid_ok: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockLink {
    pub at: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Resolution {
    pub status: Status,
    pub oid: Option<Oid>,
    pub kind: Option<GitType>,
    #[serde(skip)]
    pub payload: Option<Rc<Vec<u8>>>,
    pub steps: Vec<Step>,
    pub blocked: Vec<BlockLink>,
    pub error: Option<String>,
    pub hit: Option<BudgetHit>,
    #[serde(skip)]
    pub base_key: Option<String>,
}

#[derive(Clone)]
struct Occ {
    key: String,
    source_id: i64,
    source_name: String,
    entry_id: Option<i64>,
    offset: u64,
    kind: GitType,
    size_declared: u64,
    compressed_len: u64,
    base_offset: Option<u64>,
    base_oid: Option<Oid>,
    inflated: Option<Vec<u8>>,
    parse_error: Option<String>,
    claimed_oid: Option<Oid>,
    crc_ok: Option<bool>,
    is_loose: bool,
}

struct Ctx<'a> {
    occs: HashMap<String, Occ>,
    by_offset: HashMap<(i64, u64), String>,
    budgets: Budgets,
    used_bytes: u64,
    memo_local: HashMap<String, Rc<Resolution>>,
    memo_persisted: &'a HashMap<String, Rc<Resolution>>,
    oid_index: HashMap<Oid, Vec<String>>,
    pins: HashMap<Oid, String>,
}

#[derive(Serialize, Default)]
pub struct AnalyzeReport {
    pub total: usize,
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub corrupt: usize,
    pub cycle: usize,
    pub recomputed: usize,
    pub memo_hits: usize,
    pub paused_details: Vec<serde_json::Value>,
    pub conflicts: Vec<String>,
}

#[derive(Serialize)]
pub struct ImportResult {
    pub filename: String,
    pub kind: String,
    pub ok: bool,
    pub detail: String,
    pub duplicate: bool,
}

pub struct Engine {
    pub db: Mutex<rusqlite::Connection>,
    pub data_dir: PathBuf,
    memo: Mutex<HashMap<String, Rc<Resolution>>>,
}

impl Engine {
    pub fn open(data_dir: PathBuf) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(data_dir.join("files")).ok();
        let conn = crate::db::open(&data_dir.join("microscope.db"))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Engine {
            db: Mutex::new(conn),
            data_dir,
            memo: Mutex::new(HashMap::new()),
        })
    }

    /// 导入一个文件：保留原始内容与 sha1，按内容识别类型并解析。
    pub fn import_file(&self, filename: &str, data: &[u8]) -> ImportResult {
        let db = self.db.lock().unwrap();
        let sha1 = sha1_hex(data);
        let exists: Option<i64> = db
            .query_row("SELECT id FROM sources WHERE sha1=?1", params![sha1], |r| r.get(0))
            .ok();
        if let Some(id) = exists {
            let old: String = db
                .query_row("SELECT filename FROM sources WHERE id=?1", params![id], |r| r.get(0))
                .unwrap_or_default();
            return ImportResult {
                filename: filename.to_string(),
                kind: "duplicate".to_string(),
                ok: true,
                detail: format!("内容与已导入文件 {old} 相同 (sha1 {sha1})"),
                duplicate: true,
            };
        }

        let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        let safe: String = base
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let stored = format!("files/{sha1}_{safe}");
        std::fs::write(self.data_dir.join(&stored), data).ok();

        let res = if data.starts_with(crate::pack::PACK_MAGIC) {
            self.import_pack(&db, base, &sha1, data, &stored)
        } else if data.len() >= 4 && &data[0..4] == crate::idx::IDX_MAGIC {
            self.import_idx(&db, base, &sha1, data, &stored)
        } else {
            match self.import_loose(&db, base, &sha1, data, &stored) {
                Ok(r) => r,
                Err(r) => self.import_unknown(&db, base, &sha1, data, &stored, r),
            }
        };
        drop(db);
        // 导入后增量重算（仅受影响子图 + 新对象）
        self.analyze(self.load_budgets());
        res
    }

    fn insert_source(
        &self,
        db: &rusqlite::Connection,
        filename: &str,
        kind: &str,
        sha1: &str,
        data: &[u8],
        stored: &str,
        link_checksum: Option<&str>,
        parse_json: &str,
    ) -> i64 {
        db.execute(
            "INSERT INTO sources(filename,kind,sha1,size,stored_path,link_checksum,imported_at,parse_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![filename, kind, sha1, data.len() as i64, stored, link_checksum, now_secs(), parse_json],
        )
        .unwrap();
        db.last_insert_rowid()
    }

    fn import_pack(
        &self,
        db: &rusqlite::Connection,
        filename: &str,
        sha1: &str,
        data: &[u8],
        stored: &str,
    ) -> ImportResult {
        // 若存在 checksum 配套的 index，用其偏移表帮助跳过坏条目
        let trailer_hex = if data.len() >= 20 {
            hex::encode(&data[data.len() - 20..])
        } else {
            String::new()
        };
        let idx = self
            .find_idx_for_checksum(db, &trailer_hex)
            .map(|(_, p)| p);
        let offsets = idx.as_ref().map(|p| {
            p.entries.iter().map(|e| e.offset).collect::<BTreeSet<_>>()
        });
        let parsed = parse_pack(data, offsets.as_ref());

        let summary = serde_json::json!({
            "header": parsed.header,
            "entry_count": parsed.entries.len(),
            "errors": parsed.errors,
            "pack_checksum": parsed.pack_checksum,
            "checksum_ok": parsed.checksum_ok,
            "idx_matched": idx.is_some(),
        });
        let source_id = self.insert_source(
            db,
            filename,
            "pack",
            sha1,
            data,
            stored,
            Some(&trailer_hex),
            &summary.to_string(),
        );
        for e in &parsed.entries {
            self.insert_pack_entry(db, source_id, e);
        }
        if let Some(p) = idx {
            self.apply_idx_claims(db, source_id, &p);
        }

        // 同文件名但 checksum 不配套的 index：记录证据
        let mismatches = self.find_mismatched_idx(db, filename);
        let mut detail = format!(
            "{} 个对象, 校验和 {}",
            parsed.entries.len(),
            match parsed.checksum_ok {
                Some(true) => "通过",
                Some(false) => "不通过",
                None => "未知",
            }
        );
        if !parsed.errors.is_empty() {
            detail = format!("{detail}; {} 个解析错误", parsed.errors.len());
        }
        if let Some(p) = idx {
            detail = format!("{detail}; 已与配套 index 关联 (fanout_ok={})", p.fanout_ok);
        }
        if !mismatches.is_empty() {
            detail = format!("{detail}; 警告: index {mismatches:?} 与本 pack 不配套");
        }
        ImportResult {
            filename: filename.to_string(),
            kind: "pack".to_string(),
            ok: true,
            detail,
            duplicate: false,
        }
    }

    fn find_idx_for_checksum(
        &self,
        db: &rusqlite::Connection,
        checksum: &str,
    ) -> Option<(i64, IdxParse)> {
        let mut stmt = db
            .prepare("SELECT id, parse_json FROM sources WHERE kind='idx' AND link_checksum=?1")
            .ok()?;
        let rows: Vec<(i64, String)> = stmt
            .query_map(params![checksum], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok()?
            .filter_map(|r| r.ok())
            .collect();
        for (id, json) in rows {
            if let Some(p) = serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|_| {
                    // 重新从磁盘解析，保证拿到完整结构
                    self.reparse_idx(db, id)
                })
            {
                return Some((id, p));
            }
        }
        None
    }

    fn reparse_idx(&self, db: &rusqlite::Connection, id: i64) -> Option<IdxParse> {
        let path: String = db
            .query_row("SELECT stored_path FROM sources WHERE id=?1", params![id], |r| r.get(0))
            .ok()?;
        let data = std::fs::read(self.data_dir.join(&path)).ok()?;
        parse_idx(&data).ok()
    }

    fn find_mismatched_idx(&self, db: &rusqlite::Connection, pack_name: &str) -> Vec<String> {
        let stem = pack_name.trim_end_matches(".pack");
        let mut out = Vec::new();
        let mut stmt = db
            .prepare("SELECT filename FROM sources WHERE kind='idx'")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for n in names {
            if n.trim_end_matches(".idx") == stem {
                out.push(n);
            }
        }
        out
    }

    fn insert_pack_entry(
        &self,
        db: &rusqlite::Connection,
        source_id: i64,
        e: &PackEntry,
    ) -> i64 {
        db.execute(
            "INSERT INTO pack_entries(source_id,idx,offset,end_offset,kind,size_declared,
                base_offset,base_distance,base_oid,inflated,delta_base_size,delta_result_size,
                crc32,parse_error)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                source_id,
                e.index as i64,
                e.offset as i64,
                e.end_offset as i64,
                e.kind.as_str(),
                e.size_declared as i64,
                e.base_offset.map(|v| v as i64),
                e.base_distance.map(|v| v as i64),
                e.base_oid.map(|o| o.to_hex()),
                e.inflated,
                e.delta_base_size.map(|v| v as i64),
                e.delta_result_size.map(|v| v as i64),
                e.crc32 as i64,
                e.parse_error,
            ],
        )
        .unwrap();
        db.last_insert_rowid()
    }

    /// 用配套 index 补全 claimed oid 与 CRC 校验结果
    fn apply_idx_claims(&self, db: &rusqlite::Connection, pack_source: i64, idx: &IdxParse) {
        for row in &idx.entries {
            db.execute(
                "UPDATE pack_entries SET claimed_oid=?1, idx_crc32=?2,
                    crc_ok=(crc32=?2)
                 WHERE source_id=?3 AND offset=?4",
                params![
                    row.oid.to_hex(),
                    row.crc32 as i64,
                    pack_source,
                    row.offset as i64
                ],
            )
            .unwrap();
        }
    }

    fn import_idx(
        &self,
        db: &rusqlite::Connection,
        filename: &str,
        sha1: &str,
        data: &[u8],
        stored: &str,
    ) -> ImportResult {
        match parse_idx(data) {
            Ok(p) => {
                let fanout_sample: Vec<u32> = p
                    .fanout
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i % 32 == 0 || *i == 255)
                    .map(|(_, v)| *v)
                    .collect();
                let summary = serde_json::json!({
                    "version": p.version,
                    "entry_count": p.entries.len(),
                    "fanout_final": p.fanout[255],
                    "fanout_sample": fanout_sample,
                    "fanout_ok": p.fanout_ok,
                    "pack_checksum": p.pack_checksum,
                    "idx_checksum": p.idx_checksum,
                    "checksum_ok": p.checksum_ok,
                    "entries": p.entries,
                });
                let id = self.insert_source(
                    db,
                    filename,
                    "idx",
                    sha1,
                    data,
                    stored,
                    Some(&p.pack_checksum),
                    &summary.to_string(),
                );
                // 若 pack 已导入，立即关联
                let mut detail = format!(
                    "{} 个条目, fanout_ok={}, 校验和 {}",
                    p.entries.len(),
                    p.fanout_ok,
                    if p.checksum_ok { "通过" } else { "不通过" }
                );
                if let Some(pack_id) = self.find_pack_for_checksum(db, &p.pack_checksum) {
                    self.apply_idx_claims(db, pack_id, &p);
                    detail = format!("{detail}; 已与 pack 关联");
                } else {
                    detail = format!("{detail}; 暂未找到配套 pack，等待导入");
                }
                ImportResult {
                    filename: filename.to_string(),
                    kind: "idx".to_string(),
                    ok: true,
                    detail,
                    duplicate: false,
                }
            }
            Err(e) => ImportResult {
                filename: filename.to_string(),
                kind: "idx".to_string(),
                ok: false,
                detail: format!("index 解析失败，已隔离保存: {e}"),
                duplicate: false,
            },
        }
    }

    fn find_pack_for_checksum(
        &self,
        db: &rusqlite::Connection,
        checksum: &str,
    ) -> Option<i64> {
        db.query_row(
            "SELECT id FROM sources WHERE kind='pack' AND link_checksum=?1",
            params![checksum],
            |r| r.get(0),
        )
        .ok()
    }

    fn import_loose(
        &self,
        db: &rusqlite::Connection,
        filename: &str,
        sha1: &str,
        data: &[u8],
        stored: &str,
    ) -> Result<ImportResult, String> {
        let (raw, consumed) = inflate_all(data).map_err(|e| e.to_string())?;
        let nul = raw
            .iter()
            .position(|&b| b == 0)
            .ok_or("缺少 loose 对象头 NUL")?;
        let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "对象头不是 UTF-8")?;
        let mut parts = header.split(' ');
        let type_name = parts.next().ok_or("对象头缺少类型")?;
        let size: u64 = parts
            .next()
            .ok_or("对象头缺少大小")?
            .parse()
            .map_err(|_| "对象头大小非数字")?;
        let kind = GitType::from_str(type_name).ok_or_else(|| format!("未知对象类型 {type_name}"))?;
        let payload = &raw[nul + 1..];
        let parse_error = if payload.len() as u64 != size {
            Some(format!(
                "大小欺骗: 头部声明 {size}, 实际 payload {} 字节",
                payload.len()
            ))
        } else {
            None
        };
        let trailing = data.len() - consumed;
        let trailing_note = if trailing > 0 {
            Some(format!("zlib 流后有 {trailing} 字节尾随数据"))
        } else {
            None
        };
        let computed = object_id(kind, payload);
        let stem = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        let compact: String = stem.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let claimed = if compact.len() >= 40 {
            Oid::from_hex(&compact[..40])
        } else {
            None
        };
        let summary = serde_json::json!({
            "kind": kind.as_str(),
            "size_declared": size,
            "actual_size": payload.len(),
            "size_ok": parse_error.is_none(),
            "trailing_bytes": trailing_note,
            "claimed_oid": claimed.map(|o| o.to_hex()),
            "computed_oid": computed.to_hex(),
            "oid_ok": claimed.map(|c| c == computed),
            "parse_error": parse_error,
        });
        let id = self.insert_source(
            db,
            filename,
            "loose",
            sha1,
            data,
            stored,
            None,
            &summary.to_string(),
        );
        db.execute(
            "INSERT INTO loose_objects(source_id,kind,size_declared,payload,claimed_oid,computed_oid,parse_error)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                id,
                kind.as_str(),
                size as i64,
                payload,
                claimed.map(|o| o.to_hex()),
                computed.to_hex(),
                parse_error,
            ],
        )
        .unwrap();
        let mut detail = format!(
            "loose {} {} 字节, oid={}",
            kind.as_str(),
            payload.len(),
            computed.short()
        );
        if let Some(note) = trailing_note {
            detail = format!("{detail}; {note}");
        }
        if let Some(err) = &parse_error {
            detail = format!("{detail}; {err}");
        }
        Ok(ImportResult {
            filename: filename.to_string(),
            kind: "loose".to_string(),
            ok: parse_error.is_none(),
            detail,
            duplicate: false,
        })
    }

    fn import_unknown(
        &self,
        db: &rusqlite::Connection,
        filename: &str,
        sha1: &str,
        data: &[u8],
        reason: String,
    ) -> ImportResult {
        let summary = serde_json::json!({ "error": reason, "size": data.len() });
        self.insert_source(
            db,
            filename,
            "unknown",
            sha1,
            data,
            stored,
            None,
            &summary.to_string(),
        );
        ImportResult {
            filename: filename.to_string(),
            kind: "unknown".to_string(),
            ok: false,
            detail: format!("无法识别的文件格式，已隔离保存: {reason}"),
            duplicate: false,
        }
    }

    pub fn load_budgets(&self) -> Budgets {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT value FROM meta WHERE key='budgets'", [], |r| r.get::<_, String>(0))
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default()
    }
}

// ============================ 还原引擎 ============================

impl Engine {
    fn load_occs(&self) -> Vec<Occ> {
        let db = self.db.lock().unwrap();
        let mut occs = Vec::new();
        {
            let mut stmt = db
                .prepare(
                    "SELECT pe.id, pe.source_id, s.filename, pe.offset, pe.end_offset, pe.kind,
                            pe.size_declared, pe.base_offset, pe.base_oid, pe.inflated,
                            pe.parse_error, pe.claimed_oid, pe.crc_ok
                     FROM pack_entries pe JOIN sources s ON s.id=pe.source_id",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    let inflated: Option<Vec<u8>> = r.get(9)?;
                    let end: i64 = r.get(4)?;
                    let off: i64 = r.get(3)?;
                    let declared: i64 = r.get(6)?;
                    let kind: String = r.get(5)?;
                    let base_oid: Option<String> = r.get(8)?;
                    let claimed: Option<String> = r.get(11)?;
                    let crc_ok: Option<i64> = r.get(12)?;
                    Ok(Occ {
                        key: format!("e:{}", r.get::<_, i64>(0)?),
                        source_id: r.get(1)?,
                        source_name: r.get(2)?,
                        entry_id: Some(r.get(0)?),
                        offset: off as u64,
                        kind: GitType::from_str(&kind).unwrap_or(GitType::Blob),
                        size_declared: declared as u64,
                        compressed_len: (end - off).max(1) as u64,
                        base_offset: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                        base_oid: base_oid.and_then(|s| Oid::from_hex(&s)),
                        inflated,
                        parse_error: r.get(10)?,
                        claimed_oid: claimed.and_then(|s| Oid::from_hex(&s)),
                        crc_ok: crc_ok.map(|v| v != 0),
                        is_loose: false,
                    })
                })
                .unwrap();
            for r in rows.flatten() {
                occs.push(r);
            }
        }
        {
            let mut stmt = db
                .prepare(
                    "SELECT lo.source_id, s.filename, lo.kind, lo.size_declared, lo.payload,
                            lo.parse_error, lo.claimed_oid
                     FROM loose_objects lo JOIN sources s ON s.id=lo.source_id",
                )
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    let payload: Option<Vec<u8>> = r.get(4)?;
                    let kind: Option<String> = r.get(2)?;
                    let size: Option<i64> = r.get(3)?;
                    let claimed: Option<String> = r.get(6)?;
                    Ok(Occ {
                        key: format!("l:{}", r.get::<_, i64>(0)?),
                        source_id: r.get(0)?,
                        source_name: r.get(1)?,
                        entry_id: None,
                        offset: 0,
                        kind: GitType::from_str(kind.as_deref().unwrap_or("blob"))
                            .unwrap_or(GitType::Blob),
                        size_declared: size.unwrap_or(0) as u64,
                        compressed_len: payload.as_ref().map(|p| p.len() as i64).unwrap_or(1).max(1)
                            as u64,
                        base_offset: None,
                        base_oid: None,
                        inflated: payload,
                        parse_error: r.get(5)?,
                        claimed_oid: claimed.and_then(|s| Oid::from_hex(&s)),
                        crc_ok: None,
                        is_loose: true,
                    })
                })
                .unwrap();
            for r in rows.flatten() {
                occs.push(r);
            }
        }
        occs
    }

    fn pins_for_branch(&self, branch_id: Option<i64>) -> HashMap<Oid, String> {
        let db = self.db.lock().unwrap();
        let row: Option<String> = if let Some(id) = branch_id {
            db.query_row("SELECT pins_json FROM branches WHERE id=?1", params![id], |r| r.get(0))
                .ok()
        } else {
            None
        };
        let json: serde_json::Value = row
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({}));
        let mut pins = HashMap::new();
        if let serde_json::Value::Object(map) = json {
            for (oid, occ) in map {
                if let Some(occ) = occ.as_str() {
                    if let Some(o) = Oid::from_hex(&oid) {
                        pins.insert(o, occ.to_string());
                    }
                }
            }
        }
        pins
    }

    /// 运行一次还原分析；Ok 结果跨调用记忆，blocked/paused/corrupt 每次重算，
    /// 因此补入 base 后只实际重算受影响的依赖子图。
    pub fn analyze(&self, budgets: Budgets) -> AnalyzeReport {
        self.analyze_with_pins(budgets, None, false)
    }

    fn analyze_with_pins(
        &self,
        budgets: Budgets,
        branch_id: Option<i64>,
        persist: bool,
    ) -> AnalyzeReport {
        let occs = self.load_occs();
        let pins = self.pins_for_branch(branch_id);

        let mut occ_map: HashMap<String, Occ> = HashMap::new();
        let mut by_offset: HashMap<(i64, u64), String> = HashMap::new();
        let mut oid_index: HashMap<Oid, Vec<String>> = HashMap::new();
        for o in &occs {
            occ_map.insert(o.key.clone(), o.clone());
            if !o.is_loose {
                by_offset.insert((o.source_id, o.offset), o.key.clone());
            }
            if let Some(c) = o.claimed_oid {
                oid_index.entry(c).or_default().push(o.key.clone());
            }
        }
        let persisted = self.memo.lock().unwrap().clone();

        let mut ordered: Vec<String> = occ_map.keys().cloned().collect();
        ordered.sort_by(|a, b| {
            let oa = &occ_map[a];
            let ob = &occ_map[b];
            oa.source_name
                .cmp(&ob.source_name)
                .then(oa.offset.cmp(&ob.offset))
                .then(oa.key.cmp(&ob.key))
        });

        let mut ctx = Ctx {
            occs: occ_map,
            by_offset,
            budgets,
            used_bytes: 0,
            memo_local: HashMap::new(),
            memo_persisted: &persisted,
            oid_index: oid_index.clone(),
            pins,
        };

        let mut memo_hits = 0usize;
        let mut recomputed = 0usize;
        let mut results: Vec<(String, Rc<Resolution>)> = Vec::new();

        // 多趟定点：delta 还原出新 oid 后，可能解锁后续 ref-delta
        for _pass in 0..8 {
            let mut progress = false;
            results.clear();
            for key in &ordered {
                let hit_persisted = ctx.memo_persisted.contains_key(key);
                let res = resolve(&mut ctx, key, &mut Vec::new());
                if hit_persisted {
                    memo_hits += 0; // 每趟只统计一次，下面统一去重
                }
                results.push((key.clone(), res));
            }
            // 把新还原出的 oid 加入索引
            for (key, res) in &results {
                if let Some(oid) = res.oid {
                    let list = ctx.oid_index.entry(oid).or_default();
                    if !list.contains(key) {
                        list.push(key.clone());
                        progress = true;
                    }
                }
            }
            if !progress {
                break;
            }
        }

        // 统计 + 去重（每条 occ 最终只看一次）
        let mut seen = HashSet::new();
        let mut report = AnalyzeReport {
            total: results.len(),
            ..Default::default()
        };
        let mut final_map: HashMap<String, Rc<Resolution>> = HashMap::new();
        for (key, res) in &results {
            if !seen.insert(key.clone()) {
                continue;
            }
            final_map.insert(key.clone(), res.clone());
            if ctx.memo_persisted.contains_key(key) {
                memo_hits += 1;
            } else if res.status == Status::Ok {
                recomputed += 1;
            }
            match res.status {
                Status::Ok => report.resolved += 1,
                Status::Blocked => report.blocked += 1,
                Status::Paused => {
                    report.paused += 1;
                    report.paused_details.push(serde_json::json!({
                        "occ": key,
                        "reason": res.error,
                        "hit": res.hit,
                        "retry_hint": "提高 budgets 后重试 analyze，已保存可恢复的中间状态",
                    }));
                }
                Status::Corrupt => report.corrupt += 1,
                Status::Cycle => report.cycle += 1,
            }
        }

        if persist {
            self.persist_results(&final_map, &ordered, &ctx, budgets, &mut report);
        }
        report
    }
}

// ============================ 递归还原 ============================

fn label_of(occ: &Occ) -> String {
    if occ.is_loose {
        format!("loose {}", occ.source_name)
    } else {
        format!("pack {} @0x{:x}", occ.source_name, occ.offset)
    }
}

fn resolve(ctx: &mut Ctx, key: &str, stack: &mut Vec<String>) -> Rc<Resolution> {
    if let Some(r) = ctx.memo_local.get(key) {
        return r.clone();
    }
    if let Some(r) = ctx.memo_persisted.get(key) {
        return r.clone();
    }
    if stack.iter().any(|k| k == key) {
        let mut chain = stack.clone();
        chain.push(key.to_string());
        return Rc::new(Resolution {
            status: Status::Cycle,
            error: Some(format!("delta 形成环: {}", chain.join(" -> "))),
            blocked: vec![BlockLink {
                at: key.to_string(),
                reason: "delta 依赖环，无法还原".to_string(),
            }],
            ..Default::default()
        });
    }
    let occ = match ctx.occs.get(key).cloned() {
        Some(o) => o,
        None => {
            return Rc::new(Resolution {
                status: Status::Blocked,
                error: Some(format!("候选来源 {key} 已不存在")),
                ..Default::default()
            });
        }
    };
    let res = resolve_occ(ctx, &occ, stack);
    // Blocked 不入本地记忆：补入 base 后下一趟可自动解锁
    if res.status != Status::Blocked {
        ctx.memo_local.insert(key.to_string(), res.clone());
    }
    res
}

fn resolve_occ(ctx: &mut Ctx, occ: &Occ, stack: &mut Vec<String>) -> Rc<Resolution> {
    let label = label_of(occ);

    if let Some(err) = &occ.parse_error {
        return Rc::new(Resolution {
            status: Status::Corrupt,
            error: Some(format!("{label}: {err}")),
            blocked: vec![BlockLink { at: label.clone(), reason: err.clone() }],
            ..Default::default()
        });
    }

    match occ.kind {
        GitType::Commit | GitType::Tree | GitType::Blob | GitType::Tag => {
            build_undeltified(ctx, occ, &label)
        }
        GitType::OfsDelta => resolve_ofs_delta(ctx, occ, &label, stack),
        GitType::RefDelta => resolve_ref_delta(ctx, occ, &label, stack),
    }
}

fn check_ratio_pause(occ: &Occ, output_len: usize, label: &str) -> Option<Resolution> {
    let ratio = output_len as f64 / occ.compressed_len.max(1) as f64;
    if ratio > occ_max_ratio_placeholder() {
        // 真实比较在调用点用 ctx.budgets，这里占位不会被执行
        let _ = ratio;
        return None;
    }
    None
}
fn occ_max_ratio_placeholder() -> f64 {
    f64::INFINITY
}

fn build_undeltified(ctx: &mut Ctx, occ: &Occ, label: &str) -> Rc<Resolution> {
    let payload = match &occ.inflated {
        Some(p) => Rc::new(p.clone()),
        None => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: 缺少解压数据")),
                blocked: vec![BlockLink { at: label.to_string(), reason: "无解压数据".into() }],
                ..Default::default()
            });
        }
    };

    if let Some(p) = budget_gate(ctx, occ, &payload, label) {
        return Rc::new(p);
    }

    let oid = object_id(occ.kind, &payload);
    let oid_ok = occ.claimed_oid.map(|c| c == oid).unwrap_or(true);
    let step = Step {
        at: label.clone(),
        mechanism: "object".to_string(),
        base: None,
        instr_range: None,
        op_count: None,
        input_len: occ.compressed_len,
        output_len: payload.len() as u64,
        declared_size: occ.size_declared,
        size_ok: payload.len() as u64 == occ.size_declared,
        oid: Some(oid.to_hex()),
        oid_ok,
    };
    Rc::new(Resolution {
        status: Status::Ok,
        oid: Some(oid),
        kind: Some(occ.kind),
        payload: Some(payload),
        steps: vec![step],
        ..Default::default()
    })
}

/// 预算闸门：比例、总展开字节。返回 Some(paused) 表示暂停。
fn budget_gate(ctx: &mut Ctx, occ: &Occ, payload: &[u8], label: &str) -> Option<Resolution> {
    let ratio = payload.len() as f64 / occ.compressed_len.max(1) as f64;
    if ratio > ctx.budgets.max_ratio {
        return Some(paused(
            label,
            BudgetHit::Ratio { ratio, max: ctx.budgets.max_ratio },
            None,
        ));
    }
    if ctx.used_bytes + payload.len() as u64 > ctx.budgets.max_total_bytes {
        return Some(paused(
            label,
            BudgetHit::TotalBytes { used: ctx.used_bytes, max: ctx.budgets.max_total_bytes },
            None,
        ));
    }
    ctx.used_bytes += payload.len() as u64;
    None
}

fn paused(label: &str, hit: BudgetHit, chain: Option<Vec<BlockLink>>) -> Resolution {
    Resolution {
        status: Status::Paused,
        hit: Some(hit.clone()),
        error: Some(hit.message()),
        blocked: chain.unwrap_or_else(|| vec![BlockLink {
            at: label.to_string(),
            reason: hit.message(),
        }]),
        ..Default::default()
    }
}

fn resolve_ofs_delta(ctx: &mut Ctx, occ: &Occ, label: &str, stack: &mut Vec<String>) -> Rc<Resolution> {
    if stack.len() as u32 >= ctx.budgets.max_depth {
        return Rc::new(paused(
            label,
            BudgetHit::Depth { depth: stack.len() as u32, max: ctx.budgets.max_depth },
            None,
        ));
    }
    let base_offset = match occ.base_offset {
        Some(o) => o,
        None => {
            return Rc::new(Resolution {
                status: Status::Blocked,
                error: Some(format!("{label}: ofs-delta 距离越界 (offset underflow)")),
                blocked: vec![BlockLink {
                    at: label.to_string(),
                    reason: "ofs-delta 距离越界，base 偏移在 pack 起点之前".into(),
                }],
                ..Default::default()
            });
        }
    };
    let base_key = match ctx.by_offset.get(&(occ.source_id, base_offset)) {
        Some(k) => k.clone(),
        None => {
            return Rc::new(Resolution {
                status: Status::Blocked,
                error: Some(format!("{label}: 缺少 ofs base @0x{base_offset:x}")),
                blocked: vec![BlockLink {
                    at: label.to_string(),
                    reason: format!("base @0x{base_offset:x} 不在同一 pack 内"),
                }],
                ..Default::default()
            });
        }
    };
    stack.push(occ.key.clone());
    let base = resolve(ctx, &base_key, stack);
    stack.pop();

    let base_payload = match base.status {
        Status::Ok => base.payload.clone().unwrap(),
        Status::Paused => {
            return Rc::new(paused(label, base.hit.clone().unwrap(), Some(base.blocked.clone())));
        }
        other => {
            let reason = match other {
                Status::Cycle => format!("base {base_key} 位于 delta 环上"),
                Status::Corrupt => format!("base {} 损坏: {}", base_key, base.error.clone().unwrap_or_default()),
                _ => format!("base {base_key} 未还原: {}", base.error.clone().unwrap_or_default()),
            };
            let mut links = base.blocked.clone();
            links.push(BlockLink { at: label.to_string(), reason: reason.clone() });
            return Rc::new(Resolution {
                status: if other == Status::Cycle { Status::Cycle } else { Status::Blocked },
                error: Some(format!("{label}: {reason}")),
                blocked: links,
                base_key: Some(base_key),
                ..Default::default()
            });
        }
    };

    let delta_data = occ.inflated.clone().unwrap_or_default();
    let prog = match parse_delta(&delta_data) {
        Ok(p) => p,
        Err(e) => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: {e}")),
                blocked: vec![BlockLink { at: label.to_string(), reason: e.to_string() }],
                base_key: Some(base_key),
                ..Default::default()
            });
        }
    };
    let payload = match apply_delta(&base_payload, &prog) {
        Ok(p) => Rc::new(p),
        Err(e) => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: {e}")),
                blocked: vec![BlockLink { at: label.to_string(), reason: e.to_string() }],
                base_key: Some(base_key),
                ..Default::default()
            });
        }
    };

    if let Some(p) = budget_gate(ctx, occ, &payload, label) {
        return Rc::new(p);
    }

    let kind = base.kind.unwrap_or(GitType::Blob);
    let oid = object_id(kind, &payload);
    let step = delta_step(
        label,
        "ofs-delta",
        Some(format!("@0x{base_offset:x}")),
        &delta_data,
        &prog,
        base_payload.len() as u64,
        payload.len() as u64,
        oid,
    );
    let mut steps = base.steps.clone();
    steps.push(step);
    Rc::new(Resolution {
        status: Status::Ok,
        oid: Some(oid),
        kind: Some(kind),
        payload: Some(payload),
        steps,
        base_key: Some(base_key),
        ..Default::default()
    })
}

fn delta_step(
    label: &str,
    mechanism: &str,
    base_desc: Option<String>,
    delta_data: &[u8],
    prog: &DeltaProgram,
    input_len: u64,
    output_len: u64,
    oid: Oid,
) -> Step {
    let span = prog
        .op_spans
        .first()
        .copied()
        .map(|(s, _)| s)
        .unwrap_or(0);
    let end = prog.op_spans.last().map(|(_, e)| *e).unwrap_or(delta_data.len());
    Step {
        at: label.to_string(),
        mechanism: mechanism.to_string(),
        base: base_desc,
        instr_range: Some((span, end)),
        op_count: Some(prog.ops.len()),
        input_len,
        output_len,
        declared_size: prog.result_size,
        size_ok: output_len == prog.result_size && input_len == prog.base_size,
        oid: Some(oid.to_hex()),
        oid_ok: true,
    }
}

fn resolve_ref_delta(ctx: &mut Ctx, occ: &Occ, label: &str, stack: &mut Vec<String>) -> Rc<Resolution> {
    if stack.len() as u32 >= ctx.budgets.max_depth {
        return Rc::new(paused(
            label,
            BudgetHit::Depth { depth: stack.len() as u32, max: ctx.budgets.max_depth },
            None,
        ));
    }
    let base_oid = match occ.base_oid {
        Some(o) => o,
        None => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: ref-delta 缺少 base oid")),
                blocked: vec![BlockLink {
                    at: label.to_string(),
                    reason: "ref-delta 无 base oid".into(),
                }],
                ..Default::default()
            });
        }
    };

    let mut candidates: Vec<String> = ctx.oid_index.get(&base_oid).cloned().unwrap_or_default();
    if let Some(pinned) = ctx.pins.get(&base_oid) {
        candidates.retain(|k| k == pinned);
    }
    candidates.sort_by(|a, b| rank_key(ctx, a, base_oid).cmp(&rank_key(ctx, b, base_oid)));
    candidates.dedup();

    if candidates.is_empty() {
        return Rc::new(Resolution {
            status: Status::Blocked,
            error: Some(format!("{label}: 缺少外部 base {base_oid}")),
            blocked: vec![BlockLink {
                at: label.to_string(),
                reason: format!("缺少外部 base {base_oid}，等待补入"),
            }],
            ..Default::default()
        });
    }

    let mut failures = Vec::new();
    let mut saw_pause = None;
    for base_key in &candidates {
        stack.push(occ.key.clone());
        let base = resolve(ctx, base_key, stack);
        stack.pop();
        if base.status == Status::Ok {
            return finish_ref_delta(ctx, occ, label, base_oid, base_key.clone(), &base, stack);
        }
        if base.status == Status::Paused && saw_pause.is_none() {
            saw_pause = Some(base.clone());
        }
        failures.push((base_key.clone(), base.clone()));
    }
    if let Some(p) = saw_pause {
        return Rc::new(paused(label, p.hit.clone().unwrap(), Some(p.blocked.clone())));
    }
    let mut links = vec![BlockLink {
        at: label.to_string(),
        reason: format!("全部 {} 个 base 候选均无法还原 {}", failures.len(), base_oid),
    }];
    let mut detail = String::new();
    for (k, r) in &failures {
        detail.push_str(&format!("候选 {k}: {}; ", r.error.clone().unwrap_or_default()));
        links.extend(r.blocked.clone());
    }
    Rc::new(Resolution {
        status: Status::Blocked,
        error: Some(format!("{label}: {detail}")),
        blocked: links,
        ..Default::default()
    })
}

fn rank_key(ctx: &Ctx, key: &str, want_oid: Oid) -> (u8, u8, i8, String, u64) {
    let occ = &ctx.occs[key];
    let verified = match ctx.memo_local.get(key).or_else(|| ctx.memo_persisted.get(key)) {
        Some(r) if r.oid == Some(want_oid) => 0,
        _ => 1,
    };
    let loose = if occ.is_loose { 0 } else { 1 };
    let crc = match occ.crc_ok {
        Some(true) => 0,
        None => 1,
        Some(false) => 2,
    };
    (verified, loose, crc, occ.source_name.clone(), occ.offset)
}

fn finish_ref_delta(
    ctx: &mut Ctx,
    occ: &Occ,
    label: &str,
    base_oid: Oid,
    base_key: String,
    base: &Rc<Resolution>,
    _stack: &mut Vec<String>,
) -> Rc<Resolution> {
    let base_payload = base.payload.clone().unwrap();
    let delta_data = occ.inflated.clone().unwrap_or_default();
    let prog = match parse_delta(&delta_data) {
        Ok(p) => p,
        Err(e) => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: {e}")),
                blocked: vec![BlockLink { at: label.to_string(), reason: e.to_string() }],
                base_key: Some(base_key),
                ..Default::default()
            });
        }
    };
    let payload = match apply_delta(&base_payload, &prog) {
        Ok(p) => Rc::new(p),
        Err(e) => {
            return Rc::new(Resolution {
                status: Status::Corrupt,
                error: Some(format!("{label}: {e}")),
                blocked: vec![BlockLink { at: label.to_string(), reason: e.to_string() }],
                base_key: Some(base_key),
                ..Default::default()
            });
        }
    };
    if let Some(p) = budget_gate(ctx, occ, &payload, label) {
        return Rc::new(p);
    }
    let kind = base.kind.unwrap_or(GitType::Blob);
    let oid = object_id(kind, &payload);
    let step = delta_step(
        label,
        "ref-delta",
        Some(base_oid.to_hex()),
        &delta_data,
        &prog,
        base_payload.len() as u64,
        payload.len() as u64,
        oid,
    );
    let mut steps = base.steps.clone();
    steps.push(step);
    Rc::new(Resolution {
        status: Status::Ok,
        oid: Some(oid),
        kind: Some(kind),
        payload: Some(payload),
        steps,
        base_key: Some(base_key),
        ..Default::default()
    })
}

// ============================ 持久化与候选 ============================

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn persist_results(
        &self,
        final_map: &HashMap<String, Rc<Resolution>>,
        _ordered: &[String],
        ctx: &Ctx,
        budgets: Budgets,
        report: &mut AnalyzeReport,
    ) {
        let mut db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO meta(key,value) VALUES('budgets',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![serde_json::to_string(&budgets).unwrap()],
        )
        .unwrap();

        // 按 oid 分组 Ok 结果，选排名最高的 occ 作为主内容
        let mut by_oid: HashMap<Oid, Vec<(String, Rc<Resolution>)>> = HashMap::new();
        for (key, res) in final_map {
            if res.status == Status::Ok {
                if let Some(oid) = res.oid {
                    by_oid.entry(oid).or_default().push((key.clone(), res.clone()));
                }
            }
        }

        let tx = db.transaction().unwrap();
        for (oid, mut group) in by_oid {
            group.sort_by(|(a, _), (b, _)| {
                rank_key(ctx, a, oid).cmp(&rank_key(ctx, b, oid))
            });
            let (best_key, best) = group.first().unwrap().clone();
            let occ = &ctx.occs[&best_key];
            let payload = best.payload.clone().unwrap();
            // 删除之前留下的未解析占位
            for (k, _) in &group {
                tx.execute("DELETE FROM objects WHERE oid=?1", params![format!("unresolved:{k}")])
                    .unwrap();
            }
            tx.execute(
                "INSERT INTO objects(oid,kind,size,status,content,steps_json,blocked_json,error,occ_key,updated_at)
                 VALUES(?1,?2,?3,'resolved',?4,?5,'[]',NULL,?6,?7)
                 ON CONFLICT(oid) DO UPDATE SET
                   kind=excluded.kind,size=excluded.size,status='resolved',content=excluded.content,
                   steps_json=excluded.steps_json,blocked_json='[]',error=NULL,
                   occ_key=excluded.occ_key,updated_at=excluded.updated_at",
                params![
                    oid.to_hex(),
                    best.kind.unwrap_or(GitType::Blob).as_str(),
                    payload.len() as i64,
                    payload.as_ref().clone(),
                    serde_json::to_string(&best.steps).unwrap(),
                    best_key,
                    now_secs(),
                ],
            )
            .unwrap();

            // 候选与校验结果
            for (key, res) in &group {
                let o = &ctx.occs[key];
                let oid_ok = o.claimed_oid.map(|c| c == oid).unwrap_or(true);
                self.upsert_candidate(
                    &tx,
                    oid,
                    key,
                    o,
                    o.claimed_oid.map(|c| c == oid).unwrap_or(false) as i64,
                    oid_ok as i64,
                );
                // claimed oid 与重算 oid 不符：另存一条未验证候选作为冲突证据
                if let Some(claimed) = o.claimed_oid {
                    if claimed != oid {
                        self.upsert_candidate(&tx, claimed, key, o, 1, 0);
                    }
                }
                // delta 依赖边（供增量重算 / DAG）
                if o.kind.is_delta() {
                    tx.execute("DELETE FROM edges WHERE parent=?1", params![oid.to_hex()])
                        .unwrap();
                    let base_oid = if o.kind == GitType::RefDelta {
                        o.base_oid
                    } else {
                        res.base_key
                            .as_ref()
                            .and_then(|k| final_map.get(k))
                            .and_then(|r| r.oid)
                    };
                    if let Some(bo) = base_oid {
                        tx.execute(
                            "INSERT OR IGNORE INTO edges(parent,child) VALUES(?1,?2)",
                            params![oid.to_hex(), bo.to_hex()],
                        )
                        .unwrap();
                    }
                }
            }
        }

        // 未还原对象：隔离展示，附阻塞链，绝不写入半成品 content
        for (key, res) in final_map {
            if res.status == Status::Ok {
                continue;
            }
            let occ = &ctx.occs[key];
            if let Some(claimed) = occ.claimed_oid {
                self.upsert_candidate(&tx, claimed, key, occ, 1, 0);
            }
            let row_oid = occ
                .claimed_oid
                .map(|o| o.to_hex())
                .unwrap_or_else(|| format!("unresolved:{key}"));
            let existing: Option<String> = tx
                .query_row("SELECT status FROM objects WHERE oid=?1", params![row_oid], |r| {
                    r.get(0)
                })
                .ok();
            if existing.as_deref() == Some("resolved") {
                continue; // 同名 oid 已有可验证来源
            }
            tx.execute(
                "INSERT INTO objects(oid,kind,size,status,content,steps_json,blocked_json,error,occ_key,updated_at)
                 VALUES(?1,NULL,NULL,?2,NULL,?3,?4,?5,?6,?7)
                 ON CONFLICT(oid) DO UPDATE SET
                   status=excluded.status,content=NULL,steps_json=excluded.steps_json,
                   blocked_json=excluded.blocked_json,error=excluded.error,
                   occ_key=excluded.occ_key,updated_at=excluded.updated_at",
                params![
                    row_oid,
                    res.status.as_row(),
                    serde_json::to_string(&res.steps).unwrap_or_else(|_| "[]".into()),
                    serde_json::to_string(&res.blocked).unwrap_or_else(|_| "[]".into()),
                    res.error,
                    key,
                    now_secs(),
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();

        // 更新跨调用记忆（仅 Ok），使下次分析跳过未受影响对象
        let mut memo = self.memo.lock().unwrap();
        for (key, res) in final_map {
            if res.status == Status::Ok {
                memo.insert(key.clone(), res.clone());
            }
        }
        drop(memo);

        // 冲突：同一 oid 多个来源，或 claimed 但 hash 不匹配
        let mut stmt = db
            .prepare(
                "SELECT oid, COUNT(*) c,
                        SUM(CASE WHEN claimed=1 AND verified=0 THEN 1 ELSE 0 END) bad
                 FROM candidates GROUP BY oid",
            )
            .unwrap();
        let conflicts: Vec<String> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .filter(|(_, count, bad)| *count > 1 || *bad > 0)
            .map(|(oid, count, bad)| format!("{oid} (候选 {count} 个, 未验证 {bad} 个)"))
            .collect();
        report.conflicts = conflicts;
    }

    fn upsert_candidate(
        &self,
        tx: &rusqlite::Transaction,
        oid: Oid,
        key: &str,
        occ: &Occ,
        claimed: i64,
        verified: i64,
    ) {
        tx.execute(
            "INSERT INTO candidates(oid,occ_key,source_id,source_name,entry_id,offset,claimed,verified,crc_ok)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(oid,occ_key) DO UPDATE SET claimed=excluded.claimed,
                verified=excluded.verified,crc_ok=excluded.crc_ok",
            params![
                oid.to_hex(),
                key,
                occ.source_id,
                occ.source_name,
                occ.entry_id,
                occ.offset as i64,
                claimed,
                verified,
                occ.crc_ok.map(|b| b as i64),
            ],
        )
        .unwrap();
    }
}

// ============================ 查询 / 删除 / 分支 ============================

#[derive(Serialize)]
pub struct ObjectRow {
    pub oid: String,
    pub kind: Option<String>,
    pub size: Option<i64>,
    pub status: String,
    pub error: Option<String>,
    pub candidate_count: i64,
    pub conflict: bool,
}

#[derive(Serialize)]
pub struct CandidateRow {
    pub id: i64,
    pub oid: String,
    pub occ_key: String,
    pub source_id: i64,
    pub source_name: String,
    pub offset: i64,
    pub claimed: bool,
    pub verified: bool,
    pub crc_ok: Option<bool>,
}

#[derive(Serialize)]
pub struct ObjectDetail {
    pub oid: String,
    pub status: String,
    pub kind: Option<String>,
    pub size: Option<i64>,
    pub steps: serde_json::Value,
    pub blocked: serde_json::Value,
    pub error: Option<String>,
    pub candidates: Vec<CandidateRow>,
    pub preview_kind: Option<String>,
    pub preview: Option<String>,
    pub bases: Vec<String>,
}

#[derive(Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub sha1: String,
    pub size: i64,
    pub imported_at: String,
    pub parse: serde_json::Value,
}

#[derive(Serialize)]
pub struct Dependent {
    pub oid: String,
    pub status: String,
    pub direct: bool,
    pub reason: String,
}

impl Engine {
    pub fn list_objects(&self) -> Vec<ObjectRow> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT o.oid, o.kind, o.size, o.status, o.error,
                        (SELECT COUNT(*) FROM candidates c WHERE c.oid=o.oid) AS cnt,
                        (SELECT COUNT(*) FROM candidates c WHERE c.oid=o.oid
                           AND ((c.claimed=1 AND c.verified=0) OR c.crc_ok=0)) AS bad
                 FROM objects o ORDER BY o.status DESC, o.oid ASC",
            )
            .unwrap();
        stmt.query_map([], |r| {
            let cnt: i64 = r.get(5)?;
            let bad: i64 = r.get(6)?;
            Ok(ObjectRow {
                oid: r.get(0)?,
                kind: r.get(1)?,
                size: r.get(2)?,
                status: r.get(3)?,
                error: r.get(4)?,
                candidate_count: cnt,
                conflict: cnt > 1 || bad > 0,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn object_detail(&self, oid: &str) -> Option<ObjectDetail> {
        let db = self.db.lock().unwrap();
        let row: (Option<String>, Option<i64>, String, String, String, Option<String>) = db
            .query_row(
                "SELECT kind,size,status,steps_json,blocked_json,error FROM objects WHERE oid=?1",
                params![oid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok()?;
        let content: Option<Vec<u8>> = db
            .query_row("SELECT content FROM objects WHERE oid=?1", params![oid], |r| r.get(0))
            .ok()
            .flatten();
        let (preview_kind, preview) = content.map(preview_of).unzip();
        let candidates = self.candidates_of(&db, oid);
        let mut bases = Vec::new();
        let mut es = db.prepare("SELECT child FROM edges WHERE parent=?1").unwrap();
        if let Ok(rows) = es.query_map(params![oid], |r| r.get::<_, String>(0)) {
            bases = rows.flatten().collect();
        }
        Some(ObjectDetail {
            oid: oid.to_string(),
            kind: row.0,
            size: row.1,
            status: row.2,
            steps: serde_json::from_str(&row.3).unwrap_or(serde_json::json!([])),
            blocked: serde_json::from_str(&row.4).unwrap_or(serde_json::json!([])),
            error: row.5,
            candidates,
            preview_kind: preview_kind.flatten(),
            preview: preview.flatten(),
            bases,
        })
    }

    fn candidates_of(&self, db: &rusqlite::Connection, oid: &str) -> Vec<CandidateRow> {
        let mut stmt = db
            .prepare(
                "SELECT id,oid,occ_key,source_id,source_name,offset,claimed,verified,crc_ok
                 FROM candidates WHERE oid=?1
                 ORDER BY verified DESC,
                          CASE WHEN occ_key LIKE 'l:%' THEN 0 ELSE 1 END,
                          COALESCE(crc_ok,1) DESC, source_name ASC, offset ASC",
            )
            .unwrap();
        stmt.query_map(params![oid], |r| {
            let crc: Option<i64> = r.get(8)?;
            Ok(CandidateRow {
                id: r.get(0)?,
                oid: r.get(1)?,
                occ_key: r.get(2)?,
                source_id: r.get(3)?,
                source_name: r.get(4)?,
                offset: r.get(5)?,
                claimed: r.get::<_, i64>(6)? != 0,
                verified: r.get::<_, i64>(7)? != 0,
                crc_ok: crc.map(|v| v != 0),
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn list_sources(&self) -> Vec<SourceRow> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT id,filename,kind,sha1,size,imported_at,parse_json FROM sources ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            let j: String = r.get(6)?;
            Ok(SourceRow {
                id: r.get(0)?,
                filename: r.get(1)?,
                kind: r.get(2)?,
                sha1: r.get(3)?,
                size: r.get(4)?,
                imported_at: r.get(5)?,
                parse: serde_json::from_str(&j).unwrap_or(serde_json::json!({})),
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn source_detail(&self, id: i64) -> Option<serde_json::Value> {
        let db = self.db.lock().unwrap();
        let (filename, kind, parse_json): (String, String, String) = db
            .query_row(
                "SELECT filename,kind,parse_json FROM sources WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok()?;
        let mut v: serde_json::Value = serde_json::from_str(&parse_json).unwrap_or(serde_json::json!({}));
        if kind == "pack" {
            let mut stmt = db
                .prepare(
                    "SELECT idx,offset,end_offset,kind,size_declared,base_offset,base_oid,
                            crc32,claimed_oid,idx_crc32,crc_ok,parse_error,delta_base_size,delta_result_size
                     FROM pack_entries WHERE source_id=?1 ORDER BY offset",
                )
                .unwrap();
            let entries: Vec<serde_json::Value> = stmt
                .query_map(params![id], |r| {
                    Ok(serde_json::json!({
                        "index": r.get::<_, i64>(0)?,
                        "offset": r.get::<_, i64>(1)?,
                        "end_offset": r.get::<_, i64>(2)?,
                        "kind": r.get::<_, String>(3)?,
                        "size": r.get::<_, i64>(4)?,
                        "base_offset": r.get::<_, Option<i64>>(5)?,
                        "base_oid": r.get::<_, Option<String>>(6)?,
                        "crc32": r.get::<_, i64>(7)?,
                        "claimed_oid": r.get::<_, Option<String>>(8)?,
                        "idx_crc32": r.get::<_, Option<i64>>(9)?,
                        "crc_ok": r.get::<_, Option<i64>>(10)?,
                        "parse_error": r.get::<_, Option<String>>(11)?,
                        "delta_base_size": r.get::<_, Option<i64>>(12)?,
                        "delta_result_size": r.get::<_, Option<i64>>(13)?,
                    }))
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            v["entries"] = serde_json::json!(entries);
        }
        v["filename"] = serde_json::json!(filename);
        v["kind"] = serde_json::json!(kind);
        Some(v)
    }

    pub fn dag(&self) -> serde_json::Value {
        let db = self.db.lock().unwrap();
        let mut edges_out = Vec::new();
        let mut stmt = db.prepare("SELECT parent,child FROM edges ORDER BY parent,child").unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(serde_json::json!({ "from": r.get::<_, String>(0)?, "to": r.get::<_, String>(1)? }))
            })
            .unwrap();
        for r in rows.flatten() {
            edges_out.push(r);
        }
        serde_json::json!({ "edges": edges_out })
    }
}

fn preview_of(data: Vec<u8>) -> (String, String) {
    let is_text = data
        .iter()
        .take(4096)
        .all(|&b| b == b'\n' || b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b));
    if is_text {
        let s = String::from_utf8_lossy(&data).chars().take(4096).collect();
        ("text".to_string(), s)
    } else {
        let mut s = String::new();
        for (i, b) in data.iter().take(512).enumerate() {
            if i % 16 == 0 {
                s.push_str(&format!("{i:08x}  "));
            }
            s.push_str(&format!("{b:02x} "));
            if i % 16 == 15 {
                s.push('\n');
            }
        }
        ("hex".to_string(), s)
    }
}

impl Engine {
    /// 删除前列出仍依赖该源文件的对象（直接 + 传递）
    pub fn dependents(&self, source_id: i64) -> Vec<Dependent> {
        let db = self.db.lock().unwrap();
        let mut direct = Vec::new();
        let mut stmt = db
            .prepare("SELECT DISTINCT oid FROM candidates WHERE source_id=?1")
            .unwrap();
        let rows = stmt.query_map(params![source_id], |r| r.get::<_, String>(0)).unwrap();
        for r in rows.flatten() {
            direct.push(r);
        }
        // delta 边反向闭包
        let mut closure: HashSet<String> = direct.iter().cloned().collect();
        let mut frontier = closure.clone();
        loop {
            if frontier.is_empty() {
                break;
            }
            let mut next = HashSet::new();
            let mut stmt = db.prepare("SELECT parent FROM edges WHERE child=?1").unwrap();
            for child in &frontier {
                if let Ok(rows) = stmt.query_map(params![child], |r| r.get::<_, String>(0)) {
                    for p in rows.flatten() {
                        if closure.insert(p.clone()) {
                            next.insert(p);
                        }
                    }
                }
            }
            frontier = next;
        }
        let mut out = Vec::new();
        for oid in closure {
            let status: String = db
                .query_row("SELECT status FROM objects WHERE oid=?1", params![oid], |r| r.get(0))
                .unwrap_or_else(|_| "unknown".to_string());
            let direct_hit = direct.contains(&oid);
            out.push(Dependent {
                reason: if direct_hit {
                    "该源直接包含此对象".to_string()
                } else {
                    "delta 依赖链传递依赖".to_string()
                },
                direct: direct_hit,
                oid,
                status,
            });
        }
        out.sort_by(|a, b| b.direct.cmp(&a.direct).then(a.oid.cmp(&b.oid)));
        out
    }

    pub fn delete_source(&self, source_id: i64, force: bool) -> Result<Vec<Dependent>, String> {
        let deps = self.dependents(source_id);
        if !force && !deps.is_empty() {
            return Err(format!("仍有 {} 个对象依赖该源文件", deps.len()));
        }

        let mut memo = self.memo.lock().unwrap();
        let occ_keys: Vec<String> = deps.iter().map(|_| String::new()).collect();
        drop(occ_keys);
        // 失效该源的所有 occ 记忆，以及受影响子图对象
        let occs = self.load_occs();
        let bad_keys: HashSet<String> = occs
            .iter()
            .filter(|o| o.source_id == source_id)
            .map(|o| o.key.clone())
            .collect();
        for k in &bad_keys {
            memo.remove(k);
        }
        drop(memo);

        let affected_oids: HashSet<String> = deps.iter().map(|d| d.oid.clone()).collect();
        {
            let mut db = self.db.lock().unwrap();
            for oid in &affected_oids {
                db.execute("DELETE FROM objects WHERE oid=?1", params![oid]).unwrap();
                db.execute("DELETE FROM edges WHERE parent=?1 OR child=?1", params![oid, oid])
                    .unwrap();
            }
            db.execute("DELETE FROM candidates WHERE source_id=?1", params![source_id])
                .unwrap();
            let stored: Option<String> = db
                .query_row("SELECT stored_path FROM sources WHERE id=?1", params![source_id], |r| {
                    r.get(0)
                })
                .ok();
            db.execute("DELETE FROM sources WHERE id=?1", params![source_id]).unwrap();
            if let Some(p) = stored {
                std::fs::remove_file(self.data_dir.join(p)).ok();
            }
        }
        self.analyze(self.load_budgets());
        Ok(deps)
    }

    pub fn list_branches(&self) -> Vec<serde_json::Value> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT id,name,pins_json FROM branches ORDER BY id").unwrap();
        stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "pins": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(2)?)
                    .unwrap_or(serde_json::json!({})),
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn create_branch(&self, name: &str) -> i64 {
        let db = self.db.lock().unwrap();
        db.execute("INSERT INTO branches(name) VALUES(?1)", params![name]).unwrap();
        db.last_insert_rowid()
    }

    /// 在分析分支中固定某个冲突 oid 的候选来源
    pub fn pin_candidate(&self, branch_id: i64, oid: &str, occ_key: &str) -> Result<(), String> {
        let _ = Oid::from_hex(oid).ok_or("oid 格式错误")?;
        let db = self.db.lock().unwrap();
        let json: String = db
            .query_row("SELECT pins_json FROM branches WHERE id=?1", params![branch_id], |r| {
                r.get(0)
            })
            .map_err(|_| "分支不存在".to_string())?;
        let mut pins: serde_json::Value =
            serde_json::from_str(&json).unwrap_or(serde_json::json!({}));
        pins[oid] = serde_json::json!(occ_key);
        db.execute(
            "UPDATE branches SET pins_json=?1 WHERE id=?2",
            params![pins.to_string(), branch_id],
        )
        .unwrap();
        Ok(())
    }

    pub fn unpin(&self, branch_id: i64, oid: &str) {
        let db = self.db.lock().unwrap();
        if let Ok(json) = db.query_row(
            "SELECT pins_json FROM branches WHERE id=?1",
            params![branch_id],
            |r| r.get::<_, String>(0),
        ) {
            let mut pins: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::json!({}));
            if let Some(obj) = pins.as_object_mut() {
                obj.remove(oid);
            }
            db.execute(
                "UPDATE branches SET pins_json=?1 WHERE id=?2",
                params![pins.to_string(), branch_id],
            )
            .ok();
        }
    }

    /// 临时在固定分支上还原（不写库），用于对比分析分支
    pub fn branch_view(&self, branch_id: i64, budgets: Budgets) -> AnalyzeReport {
        self.analyze_with_pins(budgets, Some(branch_id), false)
    }
}
