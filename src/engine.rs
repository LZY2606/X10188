//! 分析引擎：导入文件、维护候选图、驱动解析器、持久化结果，
//! 并在补入 base 后只重算受影响的依赖子图。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

use crate::db;
use crate::gitobj::hash_object;
use crate::index::{parse_index, verify_index_against_pack};
use crate::loose::{oid_from_relpath, parse_loose};
use crate::models::*;
use crate::oid::{ObjType, Oid};
use crate::pack::parse_pack;
use crate::resolver::{self, Graph};

/// 一次（重新）解析运行的汇总。
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct RunSummary {
    pub recomputed: usize,
    pub resolved: usize,
    pub blocked: usize,
    pub error: usize,
    pub paused: usize,
    pub cycle: usize,
    pub total_spent: u64,
}

pub struct Engine {
    pub data_dir: PathBuf,
    pub conn: Mutex<Connection>,
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Engine {
    pub fn open(data_dir: impl AsRef<Path>) -> std::io::Result<Engine> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(data_dir.join("sources"))?;
        std::fs::create_dir_all(data_dir.join("loose"))?;
        std::fs::create_dir_all(data_dir.join("tmp"))?;
        let db_path = data_dir.join("microscope.db");
        let conn = db::open(db_path.to_str().unwrap())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(Engine {
            data_dir,
            conn: Mutex::new(conn),
        })
    }

    // ---------- 导入 ----------

    /// 导入一个文件。`kind` 为 pack/idx/loose；`rel` 为 loose 对象的逻辑相对路径
    /// （形如 ab/cdef...38hex），pack/idx 可传原始文件名。
    pub fn import_bytes(&self, kind: &str, rel: &str, bytes: &[u8]) -> Result<i64, String> {
        let kind = SourceKind::parse(kind);
        let sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(bytes))
        };

        let (stored_rel, file_name) = match kind {
            SourceKind::Loose => {
                let oid = oid_from_relpath(rel)
                    .ok_or_else(|| "loose 相对路径应为 <2hex>/<38hex>".to_string())?;
                let stored = format!("loose/{}/{}", &oid.hex()[..2], &oid.hex()[2..]);
                (stored, rel.rsplit('/').next().unwrap_or(rel).to_string())
            }
            _ => {
                let stem = rel.rsplit('/').next().unwrap_or(rel);
                let safe: String = stem
                    .chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
                            ch
                        } else {
                            '_'
                        }
                    })
                    .collect();
                (format!("sources/{sha256:.16}-{safe}"), safe)
            }
        };

        let abs = self.data_dir.join(&stored_rel);
        std::fs::create_dir_all(abs.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&abs, bytes).map_err(|e| e.to_string())?;

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        // 去重：相同 rel_path 已存在则替换（重新导入同名源）。
        let existed: Option<i64> = tx
            .query_row(
                "SELECT id FROM sources WHERE rel_path=?1",
                rusqlite::params![stored_rel],
                |r| r.get(0),
            )
            .ok();
        if let Some(id) = existed {
            tx.execute("DELETE FROM sources WHERE id=?1", rusqlite::params![id])
                .map_err(|e| e.to_string())?;
        }
        tx.execute(
            "INSERT INTO sources(kind,file_name,rel_path,size,sha256,imported_at) \
             VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                kind.as_str(),
                file_name,
                stored_rel,
                bytes.len() as i64,
                sha256,
                now_ts()
            ],
        )
        .map_err(|e| e.to_string())?;
        let source_id = tx.last_insert_rowid();

        match kind {
            SourceKind::Pack => {
                let parsed = parse_pack(&file_name, bytes);
                self.store_pack(&tx, source_id, &parsed)?;
            }
            SourceKind::Idx => {
                let parsed = parse_index(&file_name, bytes);
                self.store_idx(&tx, source_id, &parsed)?;
            }
            SourceKind::Loose => {
                let oid = oid_from_relpath(rel).unwrap();
                let parsed = parse_loose(&file_name, oid, bytes);
                self.store_loose(&tx, source_id, &parsed)?;
            }
        }

        tx.commit().map_err(|e| e.to_string())?;
        drop(conn);

        // 导入后：重新配套 idx/pack，并增量重算。
        self.repair_pairing();
        self.incremental_resolve();
        Ok(source_id)
    }

    fn store_pack(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        parsed: &crate::pack::PackParsed,
    ) -> Result<(), String> {
        tx.execute(
            "UPDATE sources SET trailer_ok=?1, parse_error=?2 WHERE id=?3",
            rusqlite::params![
                parsed.trailer_ok as i64,
                parsed.error,
                source_id
            ],
        )
        .map_err(|e| e.to_string())?;
        for e in &parsed.entries {
            let obj_type = e.obj_type;
            let actual_oid = if e.ok && !matches!(obj_type, ObjType::OfsDelta | ObjType::RefDelta) {
                Some(Oid(hash_object(obj_type, &e.payload)).hex())
            } else {
                None
            };
            tx.execute(
                "INSERT INTO candidates(source_id,kind,entry_index,pack_offset,\
                 entry_range_start,entry_range_end,zlib_range_start,zlib_range_end,\
                 actual_oid,obj_type,declared_size,inflated_len,ofs_base_offset,ref_base_oid,\
                 entry_crc32,payload_b64,parse_error,parse_ok) \
                 VALUES(?1,'pack_entry',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                rusqlite::params![
                    source_id,
                    e.index as i64,
                    e.offset as i64,
                    e.entry_range.0 as i64,
                    e.entry_range.1 as i64,
                    e.zlib_range.0 as i64,
                    e.zlib_range.1 as i64,
                    actual_oid,
                    e.obj_type.name(),
                    e.declared_size as i64,
                    e.inflated_len as i64,
                    e.ofs_base_offset.map(|v| v as i64),
                    e.ref_base_oid.map(|o| o.hex()),
                    e.entry_crc32 as i64,
                    base64_encode(&e.payload),
                    e.error,
                    e.ok as i64,
                ],
            )
            .map_err(|e2| e2.to_string())?;
        }
        Ok(())
    }

    fn store_idx(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        parsed: &crate::index::IndexParsed,
    ) -> Result<(), String> {
        tx.execute(
            "UPDATE sources SET parse_error=?1, trailer_ok=?2 WHERE id=?3",
            rusqlite::params![parsed.error, parsed.index_sha_ok as i64, source_id],
        )
        .map_err(|e| e.to_string())?;
        // index 自身不产生对象候选；配套阶段按 pack_sha 找到 pack，
        // 再把 claimed_oid 与 CRC 结果写回 pack 候选。
        Ok(())
    }

    fn store_loose(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        parsed: &crate::loose::LooseParsed,
    ) -> Result<(), String> {
        let ty = parsed.obj_type.map(|t| t.name()).unwrap_or("blob");
        tx.execute(
            "INSERT INTO candidates(source_id,kind,claimed_oid,actual_oid,obj_type,\
             declared_size,inflated_len,payload_b64,parse_error,parse_ok) \
             VALUES(?1,'loose',?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![
                source_id,
                parsed.claimed_oid.hex(),
                parsed.computed_oid.map(|o| o.hex()),
                ty,
                parsed.content.len() as i64,
                parsed.content.len() as i64,
                base64_encode(&parsed.content),
                parsed.error,
                parsed.ok as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ---------- base64（标准字母表，payload 入库不依赖系统工具）----------

pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Option<i32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as i32),
            b'a'..=b'z' => Some((c - b'a' + 26) as i32),
            b'0'..=b'9' => Some((c - b'0' + 52) as i32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() != 4 {
            return Err("base64 长度不是 4 的倍数".to_string());
        }
        let mut buf = [0i32; 4];
        let mut pad = 0;
        for i in 0..4 {
            if chunk[i] == b'=' {
                buf[i] = 0;
                pad += 1;
            } else {
                buf[i] = val(chunk[i]).ok_or_else(|| "base64 非法字符".to_string())?;
            }
        }
        let n = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad == 0 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

const BASE64_PAD: () = ();

fn type_from_name(s: &str) -> ObjType {
    match s {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "tag" => ObjType::Tag,
        "ofs-delta" => ObjType::OfsDelta,
        "ref-delta" => ObjType::RefDelta,
        _ => ObjType::Blob,
    }
}

impl Engine {
    /// 重新配套 index 与 pack，写回 pack 候选的 claimed_oid 与 CRC 结果。
    pub fn repair_pairing(&self) {
        let mut conn = self.conn.lock().unwrap();
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(_) => return,
        };
        // 先清空 pack 候选来自 index 的声称与 CRC。
        let _ = tx.execute(
            "UPDATE candidates SET claimed_oid=NULL, crc_ok=NULL WHERE kind='pack_entry'",
            [],
        );
        let _ = tx.execute(
            "UPDATE sources SET paired_pack_rel=NULL, pack_sha_match=NULL WHERE kind='idx'",
            [],
        );

        let packs: Vec<(i64, String, String)> = tx
            .prepare("SELECT id,file_name,rel_path FROM sources WHERE kind='pack'")
            .unwrap()
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        let idxs: Vec<(i64, String, String)> = tx
            .prepare("SELECT id,file_name,rel_path FROM sources WHERE kind='idx'")
            .unwrap()
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();

        for (idx_id, idx_name, idx_rel) in &idxs {
            let idx_bytes = match std::fs::read(self.data_dir.join(idx_rel)) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mut index = parse_index(idx_name, &idx_bytes);
            let mut matched = false;
            for (pack_id, pack_name, pack_rel) in &packs {
                let pack_bytes = match std::fs::read(self.data_dir.join(pack_rel)) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let pack = parse_pack(pack_name, &pack_bytes);
                // 配套以 index 记录的 pack_sha 为准；即使 pack trailer 损坏，
                // 仍能识别它“本来应配套”的 index，并把不匹配作为证据展示。
                if pack.computed_pack_sha != index.pack_sha {
                    continue;
                }
                matched = true;
                let ranges: HashMap<u64, (u64, u64)> = pack
                    .entries
                    .iter()
                    .map(|e| (e.offset, e.entry_range))
                    .collect();
                let problems = verify_index_against_pack(&mut index, &pack_bytes, &ranges);
                let _ = tx.execute(
                    "UPDATE sources SET paired_pack_rel=?1, pack_sha_match=1 WHERE id=?2",
                    rusqlite::params![pack_rel, idx_id],
                );
                for e in &index.entries {
                    let crc_ok = e.crc_matches_pack.map(|v| v as i64);
                    let _ = tx.execute(
                        "UPDATE candidates SET claimed_oid=?1, crc_ok=?2 \
                         WHERE source_id=?3 AND kind='pack_entry' AND pack_offset=?4",
                        rusqlite::params![e.oid.hex(), crc_ok, pack_id, e.pack_offset as i64],
                    );
                }
                if !problems.is_empty() {
                    let msg = problems
                        .iter()
                        .map(|(oid, why)| format!("{}: {why}", oid.short()))
                        .collect::<Vec<_>>()
                        .join("; ");
                    append_source_error(&tx, *idx_id, &format!("index/pack CRC 或偏移不一致：{msg}"));
                }
                break;
            }
            if !matched {
                let _ = tx.execute(
                    "UPDATE sources SET pack_sha_match=0 WHERE id=?1",
                    rusqlite::params![idx_id],
                );
                append_source_error(&tx, *idx_id, "index 与任何已导入 pack 都不配套（pack SHA 不匹配）");
            }
        }
        let _ = tx.commit();
    }

    fn load_candidates(&self, conn: &Connection) -> HashMap<i64, Candidate> {
        let mut map = HashMap::new();
        let mut stmt = conn
            .prepare(
                "SELECT id,source_id,kind,entry_index,pack_offset,entry_range_start,entry_range_end,\
                 zlib_range_start,zlib_range_end,claimed_oid,actual_oid,obj_type,declared_size,\
                 inflated_len,ofs_base_offset,ref_base_oid,entry_crc32,crc_ok,payload_b64,\
                 parse_error,parse_ok FROM candidates WHERE kind IN ('pack_entry','loose')",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                let kind_s: String = r.get(2)?;
                let payload_s: String = r.get(18).unwrap_or_default();
                let claimed: Option<String> = r.get(9).unwrap_or(None);
                let actual: Option<String> = r.get(10).unwrap_or(None);
                let refoid: Option<String> = r.get(15).unwrap_or(None);
                let crc: Option<i64> = r.get(16).unwrap_or(None);
                let crc_ok: Option<i64> = r.get(17).unwrap_or(None);
                Ok(Candidate {
                    id: r.get(0)?,
                    source_id: r.get(1)?,
                    kind: if kind_s == "loose" {
                        CandidateKind::Loose
                    } else {
                        CandidateKind::PackEntry
                    },
                    entry_index: r.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                    pack_offset: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    entry_range: pair_opt(r.get(5)?, r.get(6)?),
                    zlib_range: pair_opt(r.get(7)?, r.get(8)?),
                    claimed_oid: claimed.and_then(|s| Oid::from_hex(&s)),
                    actual_oid: actual.and_then(|s| Oid::from_hex(&s)),
                    obj_type: type_from_name(&r.get::<_, String>(11)?),
                    declared_size: r.get::<_, Option<i64>>(12)?.unwrap_or(0) as u64,
                    inflated_len: r.get::<_, Option<i64>>(13)?.unwrap_or(0) as usize,
                    ofs_base_offset: r.get::<_, Option<i64>>(14)?.map(|v| v as u64),
                    ref_base_oid: refoid.and_then(|s| Oid::from_hex(&s)),
                    entry_crc32: crc.map(|v| v as u32),
                    crc_ok: crc_ok.map(|v| v != 0),
                    payload: base64_decode(&payload_s).unwrap_or_default(),
                    parse_error: r.get(19).unwrap_or(None),
                    parse_ok: r.get::<_, i64>(20)? != 0,
                })
            })
            .unwrap();
        for row in rows.flatten() {
            map.insert(row.id, row);
        }
        map
    }

    pub fn get_budget(&self) -> Budget {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT max_depth,total_budget,per_object_cap,per_object_ratio FROM budgets WHERE id=1",
            [],
            |r| {
                Ok(Budget {
                    max_depth: r.get::<_, i64>(0)? as u64,
                    total_budget: r.get::<_, i64>(1)? as u64,
                    per_object_cap: r.get::<_, i64>(2)? as u64,
                    per_object_ratio: r.get::<_, i64>(3)? as u64,
                })
            },
        )
        .unwrap_or_default()
    }

    pub fn set_budget(&self, b: Budget) {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE budgets SET max_depth=?1,total_budget=?2,per_object_cap=?3,per_object_ratio=?4 WHERE id=1",
            rusqlite::params![
                b.max_depth as i64,
                b.total_budget as i64,
                b.per_object_cap as i64,
                b.per_object_ratio as i64
            ],
        )
        .unwrap();
    }
}

fn pair_opt(a: Option<i64>, b: Option<i64>) -> Option<(u64, u64)> {
    match (a, b) {
        (Some(x), Some(y)) => Some((x as u64, y as u64)),
        _ => None,
    }
}

fn append_source_error(tx: &rusqlite::Transaction, id: i64, msg: &str) {
    let existing: Option<String> = tx
        .query_row("SELECT parse_error FROM sources WHERE id=?1", rusqlite::params![id], |r| {
            r.get(0)
        })
        .ok()
        .flatten();
    let merged = match existing {
        Some(old) if !old.is_empty() => format!("{old}; {msg}"),
        _ => msg.to_string(),
    };
    let _ = tx.execute(
        "UPDATE sources SET parse_error=?1 WHERE id=?2",
        rusqlite::params![merged, id],
    );
}

impl Engine {
    fn pins_for(&self, conn: &Connection, branch: &str) -> HashMap<Oid, i64> {
        let mut m = HashMap::new();
        if let Ok(mut st) = conn.prepare("SELECT oid,candidate_id FROM pins WHERE branch_id=?1") {
            let rows = st
                .query_map(rusqlite::params![branch], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .unwrap();
            for row in rows.flatten() {
                if let Some(o) = Oid::from_hex(&row.0) {
                    m.insert(o, row.1);
                }
            }
        }
        m
    }

    fn branches(&self, conn: &Connection) -> Vec<String> {
        let mut out = vec!["default".to_string()];
        if let Ok(mut st) = conn.prepare("SELECT id FROM branches WHERE id<>'default'") {
            let rows = st.query_map([], |r| r.get::<_, String>(0)).unwrap();
            for r in rows.flatten() {
                out.push(r);
            }
        }
        out
    }

    /// 全量重新解析所有候选（用于预算变化、pin 变化等“非局部”事件）。
    pub fn full_resolve(&self) -> RunSummary {
        self.resolve_scoped(None)
    }

    /// 增量解析：只重算受影响依赖子图。`new_oids` 为本次补入候选能提供的
    /// ref base oid 集合；`new_packs` 为可能满足 ofs 边的 pack source。
    fn incremental_resolve(&self) {
        let conn = self.conn.lock().unwrap();
        let candidates = self.load_candidates(&conn);
        let graph = Graph::build(&candidates);

        // 找出当前仍未 resolved 的候选（缺 base / paused / cycle / error-传递）。
        let mut unresolved: HashSet<i64> = HashSet::new();
        {
            let mut st = conn
                .prepare("SELECT candidate_id FROM resolutions WHERE status<>'resolved'")
                .unwrap();
            let rows = st
                .query_map([], |r| r.get::<_, i64>(0))
                .unwrap();
            for r in rows.flatten() {
                unresolved.insert(r);
            }
            // 全新候选（从未解析）也纳入。
            let mut st2 = conn
                .prepare(
                    "SELECT c.id FROM candidates c WHERE c.kind IN ('pack_entry','loose') \
                     AND NOT EXISTS(SELECT 1 FROM resolutions r WHERE r.candidate_id=c.id AND r.branch_id='default')",
                )
                .unwrap();
            let rows2 = st2.query_map([], |r| r.get::<_, i64>(0)).unwrap();
            for r in rows2.flatten() {
                unresolved.insert(r);
            }
        }

        // 反向边：candidate -> 依赖它的 delta 候选。
        let mut reverse: HashMap<i64, Vec<i64>> = HashMap::new();
        for (id, c) in candidates.iter() {
            if let Some(base) = self.base_target(&graph, c) {
                reverse.entry(base).or_default().push(*id);
            }
        }

        // 受影响集合：从未解析候选出发，沿“当前候选所依赖的链”只有在
        // 新 base 可能满足时才扩展；简单且正确的做法是求 unresolved 的
        // 反向传递闭包中“当前仍无法解析的节点”。resolved 节点不在闭包内，
        // 因此补入 base 不会重算已经成功的对象。
        let mut affected: HashSet<i64> = HashSet::new();
        let mut stack: Vec<i64> = unresolved.iter().copied().collect();
        while let Some(id) = stack.pop() {
            if !affected.insert(id) {
                continue;
            }
            // 向上找：谁依赖我？
            if let Some(deps) = reverse.get(&id) {
                for &dep in deps {
                    let dep_unresolved = unresolved.contains(&dep)
                        || !resolution_is_resolved(&conn, dep);
                    if dep_unresolved {
                        stack.push(dep);
                    }
                }
            }
        }
        drop(graph);
        drop(candidates);
        self.resolve_scoped(Some(affected));
    }

    fn base_target(&self, graph: &Graph, c: &Candidate) -> Option<i64> {
        match c.obj_type {
            ObjType::OfsDelta => {
                let target = c.ofs_base_offset?;
                graph.by_pack_offset.get(&(c.source_id, target)).copied()
            }
            ObjType::RefDelta => {
                let oid = c.ref_base_oid?;
                graph.by_oid.get(&oid).and_then(|v| v.first().copied())
            }
            _ => None,
        }
    }

    fn resolve_scoped(&self, scope: Option<HashSet<i64>>) -> RunSummary {
        let mut conn = self.conn.lock().unwrap();
        let candidates = self.load_candidates(&conn);
        let graph = Graph::build(&candidates);
        let budget = self.get_budget();
        let branches = self.branches(&conn);

        let ids: Vec<i64> = {
            let mut v: Vec<i64> = candidates.keys().copied().collect();
            v.sort_unstable();
            v
        };

        let mut summary = RunSummary::default();
        let tx = conn.transaction().unwrap();

        for branch in &branches {
            let pins = self.pins_for(&tx, branch);
            // 全局预算在每次运行内统一核算：作用域外已解析对象的输出计入基线，
            // 作用域内新解析对象按最终输出字节计费一次。
            let mut run_spent: u64 = 0;
            let mut baseline_spent: u64 = 0;
            let mut charged: HashSet<i64> = HashSet::new();
            {
                let mut st = tx
                    .prepare(
                        "SELECT candidate_id,out_len FROM resolutions \
                         WHERE branch_id=?1 AND status='resolved'",
                    )
                    .unwrap();
                let rows = st
                    .query_map(rusqlite::params![branch], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1).unwrap_or(0) as u64))
                    })
                    .unwrap();
                for row in rows.flatten() {
                    if scope.as_ref().map(|set| !set.contains(&row.0)).unwrap_or(false) {
                        baseline_spent = baseline_spent.saturating_add(row.1);
                        charged.insert(row.0);
                    }
                }
            }

            for &id in &ids {
                if let Some(set) = &scope {
                    if !set.contains(&id) {
                        continue;
                    }
                }
                let node = resolver::resolve_candidate(
                    &graph,
                    id,
                    budget,
                    baseline_spent.saturating_add(run_spent),
                    &pins,
                    &charged,
                );
                if node.status == ResolveStatus::Resolved && charged.insert(id) {
                    run_spent = run_spent.saturating_add(node.out_len);
                }
                self.persist_resolution(&tx, branch, &node, id);
                match node.status {
                    ResolveStatus::Resolved => summary.resolved += 1,
                    ResolveStatus::Blocked => summary.blocked += 1,
                    ResolveStatus::Error => summary.error += 1,
                    ResolveStatus::Paused => summary.paused += 1,
                    ResolveStatus::Cycle => summary.cycle += 1,
                }
                summary.recomputed += 1;
            }
            summary.total_spent = baseline_spent.saturating_add(run_spent);
        }
        tx.commit().unwrap();
        summary
    }

    fn persist_resolution(
        &self,
        tx: &rusqlite::Transaction,
        branch: &str,
        node: &resolver::ResolvedNode,
        candidate_id: i64,
    ) {
        let blocked_json = serde_json::to_string(&node.blocked_chain).unwrap_or_else(|_| "[]".into());
        tx.execute(
            "INSERT INTO resolutions(branch_id,candidate_id,status,actual_oid,out_type,out_len,\
             chain_len,error,blocked_chain,budget_total,updated_at) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
             ON CONFLICT(branch_id,candidate_id) DO UPDATE SET \
             status=excluded.status,actual_oid=excluded.actual_oid,out_type=excluded.out_type,\
             out_len=excluded.out_len,chain_len=excluded.chain_len,error=excluded.error,\
             blocked_chain=excluded.blocked_chain,budget_total=excluded.budget_total,\
             updated_at=excluded.updated_at",
            rusqlite::params![
                branch,
                candidate_id,
                node.status.as_str(),
                node.actual_oid.map(|o| o.hex()),
                node.out_type.map(|t| t.name()),
                node.out_len as i64,
                node.chain_len as i64,
                node.error,
                blocked_json,
                node.spent as i64,
                now_ts()
            ],
        )
        .unwrap();
        let rid = tx.last_insert_rowid();
        tx.execute("DELETE FROM delta_steps WHERE resolution_id=?1", rusqlite::params![rid])
            .unwrap();
        for st in &node.steps {
            tx.execute(
                "INSERT INTO delta_steps(resolution_id,step,base_candidate_id,base_oid,\
                 instr_start,instr_end,input_len,output_len,check_ok,detail) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    rid,
                    st.step as i64,
                    st.base_candidate_id,
                    st.base_oid.map(|o| o.hex()),
                    st.instr_start as i64,
                    st.instr_end as i64,
                    st.input_len as i64,
                    st.output_len as i64,
                    st.check_ok as i64,
                    st.detail
                ],
            )
            .unwrap();
        }
    }
}

fn resolution_is_resolved(conn: &Connection, id: i64) -> bool {
    conn.query_row(
        "SELECT status FROM resolutions WHERE candidate_id=?1 AND branch_id='default'",
        rusqlite::params![id],
        |r| r.get::<_, String>(0),
    )
    .map(|s| s == "resolved")
    .unwrap_or(false)
}

// ===== 分支 / pin / 删除依赖 / 状态查询 =====

impl Engine {
    /// 创建分析分支并固定若干冲突来源。
    pub fn create_branch(&self, id: &str, note: &str, pins: &HashMap<Oid, i64>) -> Result<(), String> {
        if id == "default" || id.is_empty() {
            return Err("分支 id 不能为空或保留名 default".to_string());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO branches(id,created_at,note) VALUES(?1,?2,?3)",
            rusqlite::params![id, now_ts(), note],
        )
        .map_err(|e| e.to_string())?;
        for (oid, cid) in pins {
            tx.execute(
                "INSERT OR REPLACE INTO pins(branch_id,oid,candidate_id) VALUES(?1,?2,?3)",
                rusqlite::params![id, oid.hex(), cid],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        drop(conn);
        // pin 改变可能影响解析：对新分支做全量解析。
        self.full_resolve();
        Ok(())
    }

    /// 删除源文件前，返回仍依赖该源的候选信息。
    /// 返回 (可安全删除, 依赖描述列表)。
    pub fn delete_preview(&self, source_id: i64) -> (bool, Vec<DepInfo>) {
        let conn = self.conn.lock().unwrap();
        let mut deps = Vec::new();
        let mut stmt = conn
            .prepare(
                "SELECT c.id,c.obj_type,c.pack_offset,r.status,r.actual_oid \
                 FROM candidates c LEFT JOIN resolutions r \
                 ON r.candidate_id=c.id AND r.branch_id='default' \
                 WHERE c.source_id=?1 AND c.kind IN ('pack_entry','loose') ORDER BY c.id",
            )
            .unwrap();
        let rows = stmt
            .query_map(rusqlite::params![source_id], |r| {
                Ok(DepInfo {
                    candidate_id: r.get(0)?,
                    obj_type: r.get::<_, String>(1).unwrap_or_default(),
                    pack_offset: r.get::<_, Option<i64>>(2).unwrap_or(None),
                    status: r.get::<_, Option<String>>(3).unwrap_or(Some("new".into())).unwrap_or("new".into()),
                    actual_oid: r.get::<_, Option<String>>(4).unwrap_or(None),
                })
            })
            .unwrap();
        for row in rows.flatten() {
            deps.push(row);
        }
        // 还可能有其他源中的 ref-delta 依赖本源提供的 oid。
        let mut stmt2 = conn
            .prepare(
                "SELECT DISTINCT c2.id,c2.obj_type,c2.pack_offset, \
                 COALESCE(r2.status,'new'),r2.actual_oid FROM candidates c \
                 JOIN candidates c2 ON c2.ref_base_oid IN ( \
                   SELECT claimed_oid FROM candidates WHERE source_id=?1 AND claimed_oid IS NOT NULL \
                   UNION SELECT actual_oid FROM candidates WHERE source_id=?1 AND actual_oid IS NOT NULL \
                 ) AND c2.source_id<>?1 \
                 LEFT JOIN resolutions r2 ON r2.candidate_id=c2.id AND r2.branch_id='default'",
            )
            .unwrap();
        let rows2 = stmt2
            .query_map(rusqlite::params![source_id], |r| {
                Ok(DepInfo {
                    candidate_id: r.get(0)?,
                    obj_type: r.get::<_, String>(1).unwrap_or_default(),
                    pack_offset: r.get::<_, Option<i64>>(2).unwrap_or(None),
                    status: r.get::<_, String>(3).unwrap_or_else(|_| "new".into()),
                    actual_oid: r.get::<_, Option<String>>(4).unwrap_or(None),
                })
            })
            .unwrap();
        for row in rows2.flatten() {
            deps.push(row);
        }
        let _ = &deps;
        // 仅当没有任何 resolved 对象依赖时允许直接删除（UI 仍展示全部依赖）。
        let has_resolved = deps.iter().any(|d| d.status == "resolved");
        (!has_resolved, deps)
    }

    /// 真正删除源文件及其候选（级联 resolution/step）。
    pub fn delete_source(&self, source_id: i64, force: bool) -> Result<DeleteResult, String> {
        let (safe, deps) = self.delete_preview(source_id);
        if !safe && !force {
            return Ok(DeleteResult {
                deleted: false,
                dependents: deps,
                message: "仍有已还原对象依赖该源文件，已阻止删除（force=true 可强制）".into(),
            });
        }
        let rel: String = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT rel_path FROM sources WHERE id=?1",
                rusqlite::params![source_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?
        };
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction().map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM sources WHERE id=?1", rusqlite::params![source_id])
                .map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        let _ = std::fs::remove_file(self.data_dir.join(&rel));
        // 删除可能改变 ref 可达性：重新配套并增量解析。
        self.repair_pairing();
        self.incremental_resolve();
        Ok(DeleteResult {
            deleted: true,
            dependents: deps,
            message: format!("已删除源 {rel}"),
        })
    }

    /// 预算暂停后重试：沿用当前预算重新解析。
    pub fn resume(&self) -> RunSummary {
        self.full_resolve()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DepInfo {
    pub candidate_id: i64,
    pub obj_type: String,
    pub pack_offset: Option<i64>,
    pub status: String,
    pub actual_oid: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeleteResult {
    pub deleted: bool,
    pub dependents: Vec<DepInfo>,
    pub message: String,
}
