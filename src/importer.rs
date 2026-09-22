//! 导入器：把 pack / idx / loose 原始文件保存进数据目录，
//! 解析后写入 SQLite，并构建确定性的候选排序与 delta DAG 边。

use crate::git::{idx, loose, pack, GitType};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn sha256_hex(buf: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(buf);
    hex::encode(h.finalize())
}

pub fn detect_kind(filename: &str, buf: &[u8]) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") || (buf.len() >= 4 && &buf[..4] == b"PACK") {
        "pack"
    } else if lower.ends_with(".idx")
        || (buf.len() >= 8 && &buf[..4] == [0xff, b't', b'O', b'c'])
    {
        "idx"
    } else {
        "loose"
    }
}

pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub errors: Vec<String>,
}

pub struct DataDir {
    pub root: PathBuf,
    pub files: PathBuf,
    pub blobs: PathBuf,
}

impl DataDir {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let files = root.join("files");
        let blobs = root.join("blobs");
        std::fs::create_dir_all(&files)?;
        std::fs::create_dir_all(&blobs)?;
        Ok(Self {
            root: root.to_path_buf(),
            files,
            blobs,
        })
    }

    pub fn blob_path(&self, branch: &str, oid_hex: &str) -> PathBuf {
        self.blobs.join(format!("{branch}__{oid_hex}.bin"))
    }

    pub fn file_path(&self, source_id: i64, filename: &str) -> PathBuf {
        let safe: String = filename
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
            .collect();
        self.files.join(format!("{source_id}__{safe}"))
    }
}

/// 主导入入口：按内容识别类型并落库。返回 (source_id, kind, errors)。
pub fn import_file(
    conn: &mut Connection,
    dir: &DataDir,
    filename: &str,
    buf: &[u8],
) -> rusqlite::Result<ImportReport> {
    let kind = detect_kind(filename, buf);
    let tx = conn.transaction()?;
    let fingerprint = sha256_hex(buf);
    // 完全相同内容重复导入：直接复用（不产生重复 source）
    if let Ok(sid) = tx.query_row(
        "SELECT id FROM sources WHERE sha256=?1",
        params![fingerprint],
        |r| r.get::<_, i64>(0),
    ) {
        let k: String = tx.query_row("SELECT kind FROM sources WHERE id=?1", params![sid], |r| r.get(0))?;
        tx.commit()?;
        return Ok(ImportReport {
            source_id: sid,
            kind: k,
            errors: vec![format!("内容已存在，复用 source #{sid}")],
        });
    }

    tx.execute(
        "INSERT INTO sources(kind,filename,path,sha256,size,parse_status,parse_errors)
         VALUES(?1,?2,?3,?4,?5,'pending','[]')",
        params![kind, filename, "", fingerprint, buf.len() as i64],
    )?;
    let source_id = tx.last_insert_rowid();
    let dst = dir.file_path(source_id, filename);
    std::fs::write(&dst, buf).map_err(rusqlite::Error::from)?;
    let rel = dst
        .strip_prefix(&dir.root)
        .unwrap_or(&dst)
        .to_string_lossy()
        .to_string();
    tx.execute("UPDATE sources SET path=?1 WHERE id=?2", params![rel, source_id])?;

    let errors = match kind {
        "pack" => import_pack(&tx, dir, source_id, buf),
        "idx" => import_idx(&tx, source_id, buf),
        _ => import_loose(&tx, source_id, filename, buf),
    };

    let status = if errors.is_empty() { "ok" } else { "error" };
    tx.execute(
        "UPDATE sources SET parse_status=?1, parse_errors=?2 WHERE id=?3",
        params![status, serde_json::to_string(&errors).unwrap_or_default(), source_id],
    )?;
    tx.commit()?;

    // pack 与 idx 的配套 CRC 校验（无论哪个先导入都要做）
    if kind == "pack" || kind == "idx" {
        let mut conn2 = conn;
        cross_check_pack_idx(&mut conn2, dir)?;
    }

    Ok(ImportReport {
        source_id,
        kind: kind.to_string(),
        errors,
    })
}

fn kind_label(k: &pack::EntryKind) -> &'static str {
    match k {
        pack::EntryKind::Base(GitType::Commit) => "commit",
        pack::EntryKind::Base(GitType::Tree) => "tree",
        pack::EntryKind::Base(GitType::Blob) => "blob",
        pack::EntryKind::Base(GitType::Tag) => "tag",
        pack::EntryKind::OfsDelta { .. } => "ofs_delta",
        pack::EntryKind::RefDelta { .. } => "ref_delta",
    }
}

fn import_pack(
    tx: &rusqlite::Transaction,
    _dir: &DataDir,
    source_id: i64,
    buf: &[u8],
) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let pf = pack::parse_pack(buf);
    tx.execute(
        "UPDATE sources SET version=?1, object_count=?2, trailer_ok=?3, pack_checksum=?4 WHERE id=?5",
        params![
            pf.version as i64,
            pf.count as i64,
            pf.trailer_ok as i64,
            hex::encode(pf.trailer_actual),
            source_id
        ],
    )
    .unwrap();
    errors.extend(pf.file_errors.iter().cloned());

    for e in &pf.entries {
        let (ofs_neg, ref_base) = match &e.kind {
            pack::EntryKind::OfsDelta { negative_offset } => (Some(*negative_offset as i64), None),
            pack::EntryKind::RefDelta { base_oid } => (None, Some(hex::encode(base_oid))),
            _ => (None, None),
        };
        tx.execute(
            "INSERT INTO entries(source_id,kind,ordinal,header_offset,data_offset,end_offset,
                 declared_size,inflated_size,ofs_negative,ref_base_oid,problem,overshoot,undershoot,resynced)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                source_id,
                kind_label(&e.kind),
                e.ordinal as i64,
                e.header_offset as i64,
                e.data_offset as i64,
                e.end_offset as i64,
                e.declared_size as i64,
                e.inflated.as_ref().map(|v| v.len() as i64),
                ofs_neg,
                ref_base,
                e.problem,
                e.overshoot as i64,
                e.undershoot as i64,
                e.resynced as i64
            ],
        )
        .unwrap();
    }

    // ofs-delta 边：负偏移必须精确落在本 pack 某对象头起点，否则越界（阻塞证据）
    for e in &pf.entries {
        let pack::EntryKind::OfsDelta { negative_offset } = &e.kind else {
            continue;
        };
        let target = (e.data_offset as i64) - (*negative_offset as i64);
        if target < 12 || target as usize >= buf.len() - 20 {
            record_entry_problem(tx, source_id, e.ordinal,
                &format!("ofs-delta 负偏移 {} 越界（base 偏移 {target} 不在 pack 范围内）", negative_offset));
            continue;
        }
        let base = pf.entries.iter().find(|b| b.header_offset == target as u64);
        match base {
            Some(b) => {
                let child = entry_pk(tx, source_id, e.ordinal);
                let parent = entry_pk(tx, source_id, b.ordinal);
                tx.execute(
                    "INSERT OR IGNORE INTO deps(child_entry_id,parent_entry_id,dep_kind) VALUES(?1,?2,'ofs')",
                    params![child, parent],
                )
                .unwrap();
            }
            None => record_entry_problem(tx, source_id, e.ordinal,
                &format!("ofs-delta 指向 {target}，但该偏移不是任何对象头起点（越界/损坏）")),
        }
    }

    // ref-delta 边：同包内 base 优先；外部 base 在还原器里用候选表解析
    for e in &pf.entries {
        let pack::EntryKind::RefDelta { base_oid } = &e.kind else {
            continue;
        };
        if let Some(b) = pf
            .entries
            .iter()
            .find(|b| matches!(&b.kind, pack::EntryKind::Base(_)))
        {
            // 同包 base 的 oid 此刻未知（未还原），真正解析在 resolver；
            // 但如果是 ref->同包，base oid 只有还原后才能比对，这里不建边。
            let _ = b;
        }
        let _ = base_oid;
    }
    errors
}

fn record_entry_problem(
    tx: &rusqlite::Transaction,
    source_id: i64,
    ordinal: usize,
    msg: &str,
) {
    tx.execute(
        "UPDATE entries SET problem = COALESCE(problem,'') || ?1 WHERE source_id=?2 AND ordinal=?3",
        params![format!("；{msg}"), source_id, ordinal as i64],
    )
    .unwrap();
}

fn entry_pk(tx: &rusqlite::Transaction, source_id: i64, ordinal: usize) -> i64 {
    tx.query_row(
        "SELECT id FROM entries WHERE source_id=?1 AND ordinal=?2",
        params![source_id, ordinal as i64],
        |r| r.get(0),
    )
    .unwrap()
}

fn import_idx(tx: &rusqlite::Transaction, source_id: i64, buf: &[u8]) -> Vec<String> {
    let mut errors = Vec::new();
    match idx::parse_idx(buf) {
        Ok(idxf) => {
            tx.execute(
                "UPDATE sources SET version=?1,object_count=?2,pack_checksum=?3,parse_status='ok' WHERE id=?4",
                params![
                    idxf.version as i64,
                    idxf.count as i64,
                    hex::encode(idxf.pack_checksum),
                    source_id
                ],
            )
            .unwrap();
            errors.extend(idxf.errors.iter().cloned());
            // index 的 oid/offset/crc 以“候选注释”形式登记：
            // 存成虚拟 entries 不合适，改为把信息挂到匹配 pack 的 entries 上（cross_check 里做）。
            errors
        }
        Err(e) => {
            tx.execute(
                "UPDATE sources SET parse_status='error' WHERE id=?1",
                params![source_id],
            )
            .unwrap();
            vec![format!("index 解析失败: {e}")]
        }
    }
}

fn import_loose(
    tx: &rusqlite::Transaction,
    source_id: i64,
    filename: &str,
    buf: &[u8],
) -> Vec<String> {
    let mut errors = Vec::new();
    match loose::parse_loose(buf) {
        Ok(obj) => {
            let oid = loose::recompute_oid(&obj);
            let oid_hex = hex::encode(oid);
            // 路径形式 ab/cdef... 时，用路径里声称的 oid 做“来源 oid”
            let claimed = filename
                .trim_start_matches('/')
                .replace('/', "");
            let claimed = if claimed.len() == 40 && claimed.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(claimed)
            } else {
                None
            };
            tx.execute(
                "INSERT INTO entries(source_id,kind,ordinal,header_offset,data_offset,end_offset,
                     declared_size,inflated_size,problem,overshoot,undershoot,loose_path_oid)
                 VALUES(?1,?2,0,NULL,NULL,NULL,?3,?4,?5,?6,0,?7)",
                params![
                    source_id,
                    obj.t.name(),
                    obj.declared_size as i64,
                    obj.content.len() as i64,
                    obj.problem,
                    obj.size_spoof as i64,
                    claimed
                ],
            )
            .unwrap();
            let entry_id = tx.last_insert_rowid();
            if let Some(c) = claimed.as_ref() {
                if c != &oid_hex {
                    errors.push(format!(
                        "loose 路径声称 {c}，重算 object id 为 {oid_hex}（不一致）"
                    ));
                }
            }
            if obj.size_spoof {
                errors.push(obj.problem.clone().unwrap_or_default());
            }
            insert_candidate(tx, &oid_hex, entry_id, source_id);
            errors
        }
        Err(e) => {
            tx.execute(
                "INSERT INTO entries(source_id,kind,ordinal,declared_size,problem)
                 VALUES(?1,'blob',0,0,?2)",
                params![source_id, e],
            )
            .unwrap();
            vec![e]
        }
    }
}

/// 候选排序（确定性，与导入顺序无关）：
/// 1) 候选条目无问题优先；2) source id 小（先导入）；3) ordinal；4) oid/entry id
pub fn recompute_ranks(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    // 每个 oid 的候选按规则编号
    let oids: Vec<String> = {
        let mut stmt = tx.prepare("SELECT DISTINCT oid FROM candidates")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for oid in oids {
        let mut rows: Vec<(i64, i64, i64, Option<String>)> = {
            let mut stmt = tx.prepare(
                "SELECT c.id, c.entry_id, c.source_id, e.problem
                 FROM candidates c JOIN entries e ON e.id=c.entry_id
                 WHERE c.oid=?1
                 ORDER BY (e.problem IS NULL) DESC, c.source_id, e.ordinal, c.id",
            )?;
            let mapped = stmt.query_map(params![oid], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<String>>(3)?))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.sort_by(|a, b| {
            let pa = a.3.is_some();
            let pb = b.3.is_some();
            pa.cmp(&pb).then(a.2.cmp(&b.2)).then_with(|| {
                // ordinal 在 SQL 已排，这里稳定即可
                a.0.cmp(&b.0)
            })
        });
        for (rank, (cid, _, _, _)) in rows.iter().enumerate() {
            tx.execute(
                "UPDATE candidates SET rank=?1, is_dominant=?2 WHERE id=?3",
                params![rank as i64, if rank == &0 { 1 } else { 0 }, cid],
            )?;
        }
    }
    Ok(())
}

pub fn insert_candidate(
    tx: &rusqlite::Transaction,
    oid_hex: &str,
    entry_id: i64,
    source_id: i64,
) {
    // rank 先置 0，随后统一重算
    tx.execute(
        "INSERT OR IGNORE INTO candidates(oid,entry_id,source_id,rank) VALUES(?1,?2,?3,0)",
        params![oid_hex, entry_id, source_id],
    )
    .unwrap();
}

/// pack ↔ index 配套校验：
/// - index 的 pack_checksum 必须等于某 pack 的 trailer（否则“不配套”）
/// - 每个 (oid,offset) 与 pack 条目偏移对齐；CRC32 覆盖“对象头+压缩数据”
fn cross_check_pack_idx(conn: &mut Connection, dir: &DataDir) -> rusqlite::Result<()> {
    // 清空旧校验结果（幂等：重新配对）
    conn.execute("UPDATE entries SET crc_index=NULL, crc_calc=NULL, crc_ok=NULL", [])?;

    let packs: Vec<(i64, String, String)> = {
        let mut s = conn.prepare(
            "SELECT id, pack_checksum, path FROM sources WHERE kind='pack'",
        )?;
        let rows = s.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let idxs: Vec<(i64, String, String)> = {
        let mut s = conn.prepare(
            "SELECT id, pack_checksum, path FROM sources WHERE kind='idx'",
        )?;
        let rows = s.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let tx = conn.transaction()?;
    for (idx_id, idx_packsum, idx_path) in &idxs {
        let idx_buf = std::fs::read(dir.root.join(idx_path)).map_err(rusqlite::Error::from)?;
        let idxf = match idx::parse_idx(&idx_buf) {
            Ok(f) => f,
            Err(e) => {
                append_source_error(&tx, *idx_id, &format!("index 无法解析，跳过配对: {e}"));
                continue;
            }
        };

        let matched = packs.iter().find(|(_, pack_trailer, _)| pack_trailer == idx_packsum);
        let Some((pack_id, _, pack_path)) = matched else {
            append_source_error(
                &tx,
                *idx_id,
                "index 与任何 pack 都不配套（pack_checksum 无法匹配）",
            );
            continue;
        };
        let pack_buf = std::fs::read(dir.root.join(pack_path)).map_err(rusqlite::Error::from)?;
        let pf = pack::parse_pack(&pack_buf);

        // 偏移对齐 + CRC
        for ie in &idxf.entries {
            let crc_calc = if let Some(pe) = pf.entries.iter().find(|e| e.header_offset == ie.offset)
            {
                let calc = idx::crc_of_entry(&pack_buf, pe.header_offset, pe.end_offset);
                let crc_ok = if idxf.version == 2 {
                    Some(calc == ie.crc)
                } else {
                    None
                };
                tx.execute(
                    "UPDATE entries
                       SET crc_index=?1, crc_calc=?2, crc_ok=?3
                     WHERE source_id=?4 AND ordinal=?5",
                    params![
                        if idxf.version == 2 { Some(ie.crc as i64) } else { None },
                        calc as i64,
                        crc_ok.map(|v| v as i64),
                        pack_id,
                        pe.ordinal as i64
                    ],
                )?;
                if crc_ok == Some(false) {
                    append_source_error(
                        &tx,
                        *pack_id,
                        &format!(
                            "对象 {} (offset={}) CRC32 不匹配：index={:08x} 实算={:08x}",
                            hex::encode(ie.oid),
                            ie.offset,
                            ie.crc,
                            calc
                        ),
                    );
                }
                Some(pe)
            } else {
                append_source_error(
                    &tx,
                    *idx_id,
                    &format!(
                        "index 对象 {} 的偏移 {} 未对齐任何 pack 对象头（不配套/损坏）",
                        hex::encode(ie.oid),
                        ie.offset
                    ),
                );
                None
            };
            let _ = crc_calc;
        }

        append_source_info(&tx, *idx_id, &format!("已与 pack source #{pack_id} 配套"));
    }
    tx.commit()?;
    Ok(())
}

fn append_source_error(tx: &rusqlite::Transaction, id: i64, msg: &str) {
    let mut errors: Vec<String> = tx
        .query_row("SELECT parse_errors FROM sources WHERE id=?1", params![id], |r| {
            r.get::<_, String>(0)
        })
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if !errors.iter().any(|e| e == msg) {
        errors.push(msg.to_string());
    }
    tx.execute(
        "UPDATE sources SET parse_errors=?1, parse_status='error' WHERE id=?2",
        params![serde_json::to_string(&errors).unwrap_or_default(), id],
    )
    .unwrap();
}

fn append_source_info(tx: &rusqlite::Transaction, id: i64, msg: &str) {
    let mut errors: Vec<String> = tx
        .query_row("SELECT parse_errors FROM sources WHERE id=?1", params![id], |r| {
            r.get::<_, String>(0)
        })
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if !errors.iter().any(|e| e == msg) {
        errors.push(msg.to_string());
    }
    tx.execute(
        "UPDATE sources SET parse_errors=?1 WHERE id=?2",
        params![serde_json::to_string(&errors).unwrap_or_default(), id],
    )
    .unwrap();
}
