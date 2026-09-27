//! 源文件导入：自动识别 pack / idx / loose，保留内容摘要与原始偏移。

use crate::db;
use crate::git::{self, ObjType};
use sha2::{Digest, Sha256};

pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub objects_added: usize,
    pub paired_pack: Option<i64>,
    pub errors: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn detect_kind(data: &[u8], _filename: &str) -> Option<&'static str> {
    if data.len() >= 4 && &data[..4] == b"PACK" {
        return Some("pack");
    }
    if data.len() >= 8
        && &data[..4] == &[0xff, 0x74, 0x4f, 0x63]
        && &data[4..8] == 2u32.to_be_bytes()
    {
        return Some("idx");
    }
    if data.len() >= 2 && (data[0] & 0x0f) == 0x08 && git::loose::parse(data).is_ok() {
        return Some("loose");
    }
    None
}

pub fn import(
    conn: &mut rusqlite::Connection,
    data_dir: &std::path::Path,
    filename: &str,
    data: &[u8],
) -> rusqlite::Result<ImportReport> {
    let _ = data_dir;
    let kind = detect_kind(data, filename)
        .ok_or_else(|| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "无法识别的文件格式",
            )))
        })?
        .to_string();
    let digest = sha256_hex(data);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let rel = format!("{}/{}", kind, filename);

    if let Ok(id) = conn.query_row(
        "SELECT id FROM sources WHERE path=?1 AND sha256=?2",
        rusqlite::params![rel, digest],
        |row| row.get::<_, i64>(0),
    ) {
        return Ok(ImportReport {
            source_id: id,
            kind,
            objects_added: 0,
            paired_pack: None,
            errors: vec!["重复导入，已忽略".to_string()],
        });
    }

    conn.execute(
        "INSERT INTO sources(kind, filename, path, bytes, sha256, imported_at) VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![kind, filename, rel, data, digest, now],
    )?;
    let source_id = conn.last_insert_rowid();

    let mut report = ImportReport {
        source_id,
        kind: kind.clone(),
        objects_added: 0,
        paired_pack: None,
        errors: Vec::new(),
    };

    match kind.as_str() {
        "pack" => import_pack(conn, source_id, data, &mut report)?,
        "idx" => import_idx(conn, source_id, data, &mut report)?,
        "loose" => import_loose(conn, source_id, filename, data, &mut report)?,
        _ => {}
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn insert_object(
    conn: &rusqlite::Connection,
    source_id: i64,
    offset: u64,
    kind: ObjType,
    declared: u64,
    claimed: Option<&str>,
    inflated: Option<&[u8]>,
    zs: Option<usize>,
    ze: Option<usize>,
    errs: &[String],
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO objects(source_id, offset, kind_code, declared_size, claimed_oid, raw_inflated, zlib_start, zlib_end, parse_errors)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            source_id,
            offset as i64,
            kind as i64,
            declared as i64,
            claimed,
            inflated,
            zs.map(|v| v as i64),
            ze.map(|v| v as i64),
            serde_json::to_string(errs).unwrap()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn source_filename(conn: &rusqlite::Connection, source_id: i64) -> String {
    conn.query_row(
        "SELECT filename FROM sources WHERE id=?1",
        [source_id],
        |row| row.get(0),
    )
    .unwrap_or_default()
}

fn import_pack(
    conn: &mut rusqlite::Connection,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    let pf = match git::pack::parse(data) {
        Ok(pf) => pf,
        Err(e) => {
            report.errors.push(format!("pack 解析失败: {}", e));
            return Ok(());
        }
    };
    report.errors.extend(pf.errors.clone());

    let trailer_hex = pf.trailer_sha.map(hex::encode);
    let stem = source_filename(conn, source_id);
    let stem = stem.trim_end_matches(".pack");

    let idx_row: Option<(i64, Vec<u8>)> = conn
        .prepare("SELECT id, bytes FROM sources WHERE kind='idx'")?
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .flatten()
        .find(|(_, bytes)| {
            git::idx::parse(bytes)
                .ok()
                .map(|idx| idx.pack_sha.map(hex::encode) == trailer_hex)
                .unwrap_or(false)
        })
        .or_else(|| {
            conn.prepare("SELECT id, bytes FROM sources WHERE kind='idx'")
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
                .flatten()
                .find(|(id, _)| source_filename(conn, *id).trim_end_matches(".idx") == stem)
        });

    let parsed_idx = idx_row
        .as_ref()
        .and_then(|(_, b)| git::idx::parse(b).ok());
    if let Some((id, _)) = &idx_row {
        report.paired_pack = Some(*id);
    }
    if let Some(pi) = &parsed_idx {
        report.errors.extend(pi.errors.clone());
        let ranges: Vec<(u64, usize, usize)> = pf
            .entries
            .iter()
            .map(|e| (e.offset, e.zlib_start, e.zlib_end))
            .collect();
        for (off, expect, actual) in git::idx::verify_crcs(pi, data, &ranges) {
            report.errors.push(format!(
                "CRC mismatch @pack offset {}: idx={:08x} actual={:08x}",
                off, expect, actual
            ));
        }
    }

    for e in &pf.entries {
        let claimed = parsed_idx
            .as_ref()
            .and_then(|pi| pi.entries.iter().find(|ie| ie.offset == e.offset))
            .map(|ie| hex::encode(ie.oid));
        let oid = insert_object(
            conn,
            source_id,
            e.offset,
            e.kind,
            e.declared_size,
            claimed.as_deref(),
            e.inflated.as_deref(),
            Some(e.zlib_start),
            Some(e.zlib_end),
            &e.errors,
        )?;
        if let Some(base) = e.ofs_base {
            conn.execute(
                "INSERT INTO delta_edges(object_id, ref_type, base_offset, base_oid) VALUES(?1,'ofs',?2,NULL)",
                rusqlite::params![oid, base as i64],
            )?;
        }
        if let Some(bo) = e.ref_base {
            conn.execute(
                "INSERT INTO delta_edges(object_id, ref_type, base_offset, base_oid) VALUES(?1,'ref',NULL,?2)",
                rusqlite::params![oid, hex::encode(bo)],
            )?;
        }
        report.objects_added += 1;
    }

    if let Some(pi) = &parsed_idx {
        let known: std::collections::HashSet<u64> =
            pf.entries.iter().map(|e| e.offset).collect();
        for ie in &pi.entries {
            if !known.contains(&ie.offset) {
                report.errors.push(format!(
                    "index 与 pack 不配套：idx 登记偏移 {} (oid {}) 在 pack 中不存在",
                    ie.offset,
                    hex::encode(ie.oid)
                ));
            }
        }
    }
    let _ = db::migrate;
    Ok(())
}

fn import_idx(
    conn: &mut rusqlite::Connection,
    _source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    let idx = match git::idx::parse(data) {
        Ok(v) => v,
        Err(e) => {
            report.errors.push(format!("idx 解析失败: {}", e));
            return Ok(());
        }
    };
    report.errors.extend(idx.errors);
    Ok(())
}

fn import_loose(
    conn: &mut rusqlite::Connection,
    source_id: i64,
    filename: &str,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    let lo = match git::loose::parse(data) {
        Ok(v) => v,
        Err(e) => {
            report.errors.push(format!("loose 解析失败: {}", e));
            return Ok(());
        }
    };
    report.errors.extend(lo.errors.clone());
    let computed = git::git_object_id(lo.kind, &lo.content);
    let claimed = loose_path_oid(filename).unwrap_or_else(|| hex::encode(computed));
    insert_object(
        conn,
        source_id,
        0,
        lo.kind,
        lo.declared_size,
        Some(&claimed),
        Some(&lo.content),
        None,
        None,
        &lo.errors,
    )?;
    report.objects_added += 1;
    Ok(())
}

pub fn loose_path_oid(filename: &str) -> Option<String> {
    let cleaned = filename.replace('\\', "/");
    let parts: Vec<&str> = cleaned.split('/').collect();
    if parts.len() >= 2 {
        let dir = parts[parts.len() - 2];
        let name = parts[parts.len() - 1];
        if dir.len() == 2 && name.len() == 38 {
            let candidate = format!("{}{}", dir, name);
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate);
            }
        }
    }
    None
}
