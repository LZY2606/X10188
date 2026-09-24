use crate::hash;
use crate::idx;
use crate::loose;
use crate::model::{BaseRef, ObjType};
use crate::pack;
use crate::store::Db;
use rusqlite::params;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct IngestReport {
    pub source_id: i64,
    pub kind: String,
    pub fingerprint: String,
    pub dedup: bool,
    pub candidates: usize,
    pub notes: Vec<String>,
}

fn detect_kind(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[0..4] == b"PACK" {
        "pack"
    } else if bytes.len() >= 4 && &bytes[0..4] == b"\xfftOc" {
        "idx"
    } else {
        "loose"
    }
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect()
}

/// Import one file: persist bytes, parse it, insert candidates, then cross-check
/// every known (pack, idx) pair.
pub fn ingest(db: &Db, data_dir: &Path, name: &str, bytes: &[u8]) -> Result<IngestReport, String> {
    let fingerprint = hash::content_fingerprint(bytes);
    {
        let conn = db.conn.lock().unwrap();
        let existing: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, name FROM sources WHERE fingerprint=?1",
                params![fingerprint],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        if let Some((id, existing_name)) = existing {
            return Ok(IngestReport {
                source_id: id,
                kind: String::new(),
                fingerprint,
                dedup: true,
                candidates: 0,
                notes: vec![format!("内容与已导入文件 {existing_name} (#{id}) 完全相同，已跳过")],
            });
        }
    }

    let kind = detect_kind(bytes).to_string();
    let source_id = db.insert_source(name, &kind, &fingerprint, bytes.len() as i64);

    // persist raw input inside the project data directory
    let dir = data_dir.join("sources");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建数据目录失败: {e}"))?;
    let stored = dir.join(format!("{source_id}-{}", safe_name(name)));
    std::fs::write(&stored, bytes).map_err(|e| format!("写入源文件失败: {e}"))?;

    let mut notes = Vec::new();
    let mut candidate_count = 0usize;

    match kind.as_str() {
        "pack" => {
            candidate_count = import_pack(db, source_id, bytes, &mut notes);
        }
        "idx" => {
            import_idx(db, source_id, bytes, &mut notes);
        }
        _ => {
            candidate_count = import_loose(db, source_id, bytes, &mut notes);
        }
    }

    // Cross-check every (pack, idx) pair after every import, so import order
    // does not matter.
    cross_check_all(db, data_dir, &mut notes);

    Ok(IngestReport {
        source_id,
        kind,
        fingerprint,
        dedup: false,
        candidates: candidate_count,
        notes,
    })
}

fn insert_candidate(
    db: &Db,
    source_id: i64,
    offset: u64,
    obj_type: ObjType,
    declared_size: u64,
    data_offset: u64,
    compressed_len: u64,
    raw_len: u64,
    base: &Option<BaseRef>,
    crc32: u32,
    payload: Option<&[u8]>,
    error: Option<&str>,
) -> i64 {
    let (base_kind, base_ofs, base_ref) = match base {
        None => ("none", None, None),
        Some(BaseRef::Ofs(o)) => ("ofs", Some(*o as i64), None),
        Some(BaseRef::Ref(o)) => ("ref", None, Some(o.clone())),
    };
    let status = if error.is_some() { "error" } else { "pending" };
    let conn = db.conn.lock().unwrap();
    conn.execute(
        r#"INSERT INTO candidates
           (source_id, "offset", obj_type, declared_size, data_offset, compressed_len, raw_len,
            base_kind, base_ofs, base_ref, status, error, crc32, depth)
           VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,0)"#,
        params![
            source_id,
            offset as i64,
            obj_type.name(),
            declared_size as i64,
            data_offset as i64,
            compressed_len as i64,
            raw_len as i64,
            base_kind,
            base_ofs,
            base_ref,
            status,
            error,
            crc32 as i64,
        ],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    if let Some(p) = payload {
        conn.execute(
            "INSERT INTO contents(candidate_id, payload) VALUES(?1,?2)",
            params![id, p],
        )
        .unwrap();
    }
    id
}

fn import_pack(db: &Db, source_id: i64, bytes: &[u8], notes: &mut Vec<String>) -> usize {
    let parsed = pack::parse_pack(bytes, &[]);
    if let Some(f) = &parsed.fatal {
        notes.push(format!("pack 解析告警: {f}"));
    }
    if !parsed.trailer_ok {
        notes.push(format!(
            "pack trailer SHA1 校验失败（offset {} 起的 20 字节不匹配）",
            parsed.trailer_offset.unwrap_or(0)
        ));
    }
    let mut n = 0;
    for obj in &parsed.objects {
        let mut error = obj.error.clone();
        if error.is_none() {
            if let Some(p) = &obj.payload {
                if p.len() as u64 != obj.declared_size {
                    error = Some(format!(
                        "大小欺骗：对象头声明 {} 字节，zlib 实际还原 {} 字节",
                        obj.declared_size,
                        p.len()
                    ));
                }
            }
        }
        insert_candidate(
            db,
            source_id,
            obj.offset,
            obj.obj_type,
            obj.declared_size,
            obj.data_offset,
            obj.compressed_len,
            obj.raw_len,
            &obj.base,
            obj.crc32,
            obj.payload.as_deref(),
            error.as_deref(),
        );
        n += 1;
    }
    if parsed.unlocated > 0 {
        notes.push(format!("{} 个声明对象因前序错误未能定位，未建立候选", parsed.unlocated));
    }
    n
}

fn import_idx(db: &Db, source_id: i64, bytes: &[u8], notes: &mut Vec<String>) {
    let parsed = idx::parse_idx(bytes);
    if let Some(f) = &parsed.fatal {
        notes.push(format!("index 解析失败: {f}"));
        return;
    }
    if parsed.idx_checksum_ok == Some(false) {
        notes.push("index 自身 SHA1 校验失败".to_string());
    }
    let conn = db.conn.lock().unwrap();
    for e in &parsed.entries {
        let bucket = usize::from_str_radix(&e.oid[0..2], 16).unwrap_or(0);
        conn.execute(
            r#"INSERT INTO idx_entries(source_id, oid, crc32, "offset", fanout_bucket, fanout_cumulative)
               VALUES(?1,?2,?3,?4,?5,?6)"#,
            params![
                source_id,
                e.oid,
                e.crc32 as i64,
                e.offset as i64,
                bucket as i64,
                parsed.fanout[bucket] as i64,
            ],
        )
        .unwrap();
    }
}

fn import_loose(db: &Db, source_id: i64, bytes: &[u8], notes: &mut Vec<String>) -> usize {
    match loose::parse_loose(bytes) {
        Ok(obj) => {
            let mut error = None;
            if obj.content.len() as u64 != obj.declared_size {
                error = Some(format!(
                    "大小欺骗：loose header 声明 {} 字节，实际 {} 字节",
                    obj.declared_size,
                    obj.content.len()
                ));
            }
            insert_candidate(
                db,
                source_id,
                0,
                obj.obj_type,
                obj.declared_size,
                0,
                obj.compressed_len as u64,
                obj.compressed_len as u64,
                &None,
                0,
                Some(&obj.content),
                error,
            );
            1
        }
        Err(e) => {
            notes.push(format!("loose 对象解析失败，未建立候选: {e}"));
            0
        }
    }
}

fn stem(name: &str) -> String {
    let p = Path::new(name);
    p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| name.to_string())
}

/// Read persisted bytes for a source.
fn source_bytes(data_dir: &Path, source_id: i64, name: &str) -> Option<Vec<u8>> {
    let p = data_dir.join("sources").join(format!("{source_id}-{}", safe_name(name)));
    std::fs::read(p).ok()
}

/// Pair every index with a pack (matching stem, otherwise unique pack), and
/// verify offsets / CRCs / checksums.
fn cross_check_all(db: &Db, data_dir: &Path, notes: &mut Vec<String>) {
    let sources = db.list_sources();
    let packs: Vec<&crate::store::SourceRow> = sources.iter().filter(|s| s.kind == "pack").collect();
    let idxs: Vec<&crate::store::SourceRow> = sources.iter().filter(|s| s.kind == "idx").collect();
    if packs.is_empty() || idxs.is_empty() {
        return;
    }

    for ix in &idxs {
        let idx_bytes = match source_bytes(data_dir, ix.id, &ix.name) {
            Some(b) => b,
            None => continue,
        };
        let parsed_idx = idx::parse_idx(&idx_bytes);

        // choose the pack to cross-check against
        let chosen: Option<&crate::store::SourceRow> = {
            let same_stem = packs.iter().find(|p| stem(&p.name) == stem(&ix.name)).copied();
            same_stem.or_else(|| if packs.len() == 1 { Some(packs[0]) } else { None })
        };
        let Some(pk) = chosen else {
            notes.push(format!(
                "index {} (#{}) 找不到配套 pack（同名 stem 或唯一 pack）",
                ix.name, ix.id
            ));
            continue;
        };
        let pack_bytes = match source_bytes(data_dir, pk.id, &pk.name) {
            Some(b) => b,
            None => continue,
        };
        let parsed_pack = pack::parse_pack(&pack_bytes, &[]);

        // checksum linkage
        if let (Some(idx_pack_sum), Some(trailer_at)) =
            (&parsed_idx.pack_checksum, parsed_pack.trailer_offset)
        {
            let trailer_hex = hash::hex(&pack_bytes[trailer_at as usize..trailer_at as usize + 20]);
            if *idx_pack_sum != trailer_hex {
                notes.push(format!(
                    "index 与 pack 不配套：index 记录的 pack 校验和 {} 与 pack #{self} trailer {}",
                    idx_pack_sum,
                    trailer_hex,
                    self = pk.id
                ));
            }
        }

        let entries = db.idx_entries_for(ix.id);
        // map offsets -> pack objects
        let mut extra_notes = Vec::new();
        let mut matched_offsets = std::collections::HashSet::new();
        for (oid, crc, offset, _bucket, _cum) in &entries {
            let crc = *crc as u32;
            let offset = *offset as u64;
            let Some(obj) = parsed_pack.objects.iter().find(|o| o.offset == offset) else {
                extra_notes.push(format!(
                    "index 与 pack 不配套：offset {offset} (oid {oid}) 在 pack #{} 中没有对象边界",
                    pk.id
                ));
                continue;
            };
            matched_offsets.insert(offset);

            // attach idx crc to the matching candidate and compare
            let conn = db.conn.lock().unwrap();
            let cid: Option<i64> = conn
                .query_row(
                    "SELECT id FROM candidates WHERE source_id=?1 AND \"offset\"=?2",
                    params![pk.id, offset as i64],
                    |r| r.get(0),
                )
                .ok();
            drop(conn);
            let Some(cid) = cid else { continue };
            {
                let conn = db.conn.lock().unwrap();
                conn.execute(
                    "UPDATE candidates SET idx_crc32=?1 WHERE id=?2",
                    params![crc as i64, cid],
                )
                .unwrap();
            }
            if obj.crc32 != crc {
                let msg = format!("错误 CRC：index 记录 0x{crc:08x}，pack 实算 0x{actual:08x}", actual = obj.crc32);
                mark_error(db, cid, &msg);
                extra_notes.push(format!("候选 #{} ({oid}): {msg}", cid));
            }
            if let Some(actual_oid) = resolved_oid(db, cid) {
                if actual_oid != *oid {
                    extra_notes.push(format!(
                        "index 与 pack 不配套：候选 #{} 重算 oid {actual_oid} 与 index {oid} 不一致",
                        cid
                    ));
                }
            }
        }
        for obj in &parsed_pack.objects {
            if !matched_offsets.contains(&obj.offset) {
                extra_notes.push(format!(
                    "pack #{} offset {} 的对象未出现在 index 中",
                    pk.id, obj.offset
                ));
            }
        }
        for n in extra_notes {
            notes.push(n);
        }
    }
}

fn mark_error(db: &Db, candidate_id: i64, msg: &str) {
    let conn = db.conn.lock().unwrap();
    // keep the candidate isolated; append to existing evidence
    conn.execute(
        "UPDATE candidates SET status='error',
            error = CASE WHEN error IS NULL THEN ?1 ELSE error || ' | ' || ?1 END
         WHERE id=?2 AND status != 'error'",
        params![msg, candidate_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE candidates SET error = COALESCE(error,'') || CASE WHEN error='' THEN ?1 ELSE ' | ' || ?1 END
         WHERE id=?2 AND status='error'",
        params![msg, candidate_id],
    )
    .unwrap();
}

fn resolved_oid(db: &Db, candidate_id: i64) -> Option<String> {
    let conn = db.conn.lock().unwrap();
    conn.query_row(
        "SELECT oid FROM candidates WHERE id=?1 AND status='resolved'",
        params![candidate_id],
        |r| r.get(0),
    )
    .ok()
    .flatten()
}

/// Convenience: stored file path for a source.
pub fn stored_path(data_dir: &Path, source_id: i64, name: &str) -> PathBuf {
    data_dir
        .join("sources")
        .join(format!("{source_id}-{}", safe_name(name)))
}
