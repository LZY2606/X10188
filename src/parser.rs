use crate::db::{now_secs, Store};
use crate::gitcore::*;
use crate::model::Declared;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub candidates: i64,
    pub warnings: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn detect_kind(filename: &str, data: &[u8]) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if data.starts_with(b"PACK") && data.len() >= 8 {
        return "pack";
    }
    if data.len() >= 8 && data[0] == 0xff && data[1] == 0x74 {
        return "idx";
    }
    if lower.ends_with(".pack") {
        return "pack";
    }
    if lower.ends_with(".idx") {
        return "idx";
    }
    "loose"
}

pub fn import_file(store: &Store, filename: &str, data: &[u8]) -> Result<ImportReport, String> {
    let kind = detect_kind(filename, data).to_string();
    let sha = sha256_hex(data);
    let db = store.conn.lock().unwrap();
    let existing: Option<i64> = db
        .query_row(
            "SELECT id FROM sources WHERE sha256=?1",
            params![sha],
            |r| r.get(0),
        )
        .ok();
    if let Some(id) = existing {
        return Ok(ImportReport {
            source_id: id,
            kind,
            candidates: 0,
            warnings: vec!["duplicate import ignored".into()],
        });
    }
    drop(db);

    let db = store.conn.lock().unwrap();
    db.execute(
        "INSERT INTO sources(filename, kind, sha256, size, imported_at, data_path)
         VALUES(?1,'unknown',?2,?3,?4,'')",
        params![filename, sha, data.len() as i64, now_secs()],
    )
    .map_err(|e| e.to_string())?;
    let source_id = db.last_insert_rowid();
    drop(db);

    let path = store.source_path(source_id);
    std::fs::write(&path, data).map_err(|e| e.to_string())?;

    let mut report = ImportReport {
        source_id,
        kind: kind.clone(),
        candidates: 0,
        warnings: Vec::new(),
    };

    let result = match kind.as_str() {
        "pack" => parse_pack(store, source_id, data, &mut report),
        "idx" => parse_idx(store, source_id, data, &mut report),
        _ => parse_loose(store, source_id, data, &mut report),
    };

    let db = store.conn.lock().unwrap();
    match result {
        Ok(()) => {
            db.execute(
                "UPDATE sources SET kind=?1, parse_status='ok' WHERE id=?2",
                params![kind, source_id],
            )
            .ok();
        }
        Err((status, err)) => {
            db.execute(
                "UPDATE sources SET kind=?1, parse_status=?2, parse_error=?3 WHERE id=?4",
                params![kind, status, err, source_id],
            )
            .ok();
            report.warnings.push(format!("{}: {}", status, err));
        }
    }
    drop(db);

    // best-effort pairing with any counterpart already imported
    let pairing_warnings = pair_packs(store);
    report.warnings.extend(pairing_warnings);
    let count = candidate_count(store, source_id);
    report.candidates = count;
    Ok(report)
}

fn candidate_count(store: &Store, source_id: i64) -> i64 {
    let db = store.conn.lock().unwrap();
    db.query_row(
        "SELECT COUNT(*) FROM candidates WHERE source_id=?1",
        params![source_id],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

fn parse_loose(
    store: &Store,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> Result<(), (String, String)> {
    let inf = match inflate_at(data, 0, None, HARD_LIMIT) {
        Ok(r) => r,
        Err(e) => return Err(("corrupt".into(), e.message())),
    };
    let nul = inf
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| ("corrupt".to_string(), "loose object missing header".into()))?;
    let header = std::str::from_utf8(&inf.data[..nul])
        .map_err(|_| ("corrupt".to_string(), "loose header not utf8".to_string()))?;
    let mut parts = header.split(' ');
    let type_name = parts
        .next()
        .ok_or_else(|| ("corrupt".to_string(), "loose missing type".to_string()))?;
    let size_str = parts
        .next()
        .ok_or_else(|| ("corrupt".to_string(), "loose missing size".to_string()))?;
    let declared: u64 = size_str
        .parse()
        .map_err(|_| ("corrupt".to_string(), "loose bad size".to_string()))?;
    let obj_type = crate::model::ObjType::parse(type_name)
        .ok_or_else(|| ("corrupt".to_string(), format!("loose bad type {}", type_name)))?;
    let content = &inf.data[nul + 1..];
    let parse_status;
    let parse_error;
    if content.len() as u64 != declared {
        parse_status = "size_spoof".to_string();
        parse_error = Some(format!(
            "loose size spoof: header {}, actual {}",
            declared,
            content.len()
        ));
    } else {
        parse_status = "ok".to_string();
        parse_error = None;
    }
    let oid = git_oid(obj_type.name(), content);
    let db = store.conn.lock().unwrap();
    db.execute(
        "UPDATE sources SET kind='loose' WHERE id=?1",
        params![source_id],
    )
    .map_err(|e| ("db".to_string(), e.to_string()))?;
    db.execute(
        "INSERT INTO candidates
         (source_id, origin, pack_offset, declared_type, declared_size, inflated_size,
          hdr_start, hdr_end, zdata_start, zdata_end, oid, parse_status, parse_error, evidence)
         VALUES(?1,'loose',NULL,?2,?3,?4,0,0,0,?5,?6,?7,?8,?9)",
        params![
            source_id,
            obj_type.name(),
            declared as i64,
            inf.data.len() as i64,
            inf.consumed as i64,
            oid,
            parse_status,
            parse_error,
            format!("zlib consumed {} of {} bytes", inf.consumed, data.len())
        ],
    )
    .map_err(|e| ("db".to_string(), e.to_string()))?;
    let cid = db.last_insert_rowid();
    drop(db);
    store.write_payload(cid, content).ok();
    let _ = report;
    Ok(())
}

const HARD_LIMIT: u64 = 128 * 1024 * 1024;

struct RawEntry {
    hdr_start: usize,
    hdr_end: usize,
    zdata_start: usize,
    zdata_end: usize,
    declared: Declared,
    declared_size: u64,
    base_ofs: Option<i64>,
    base_oid: Option<String>,
    payload: Vec<u8>,
    status: String,
    error: Option<String>,
}

fn parse_pack(
    store: &Store,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> Result<(), (String, String)> {
    if data.len() < 12 {
        return Err(("corrupt".into(), "pack shorter than 12-byte header".into()));
    }
    if &data[0..4] != b"PACK" {
        return Err(("corrupt".into(), "missing PACK magic".into()));
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if version != 2 {
        return Err(("unsupported".into(), format!("pack version {} unsupported", version)));
    }
    let mut pos = 12usize;
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut fatal: Option<String> = None;

    for idx in 0..count {
        if pos + 1 >= data.len() {
            fatal = Some(format!("entry {} header truncated", idx));
            break;
        }
        let hdr_start = pos;
        let first = data[pos];
        let type_byte = (first >> 4) & 0b0111;
        let declared = match Declared::from_pack_byte(type_byte) {
            Some(d) => d,
            None => {
                fatal = Some(format!("entry {} unknown type byte {}", idx, type_byte));
                break;
            }
        };
        let mut size = (first & 0x7f) as u64;
        let mut shift = 7u32;
        pos += 1;
        while pos < data.len() && (data[pos - 1] & 0x80) != 0 {
            size |= ((data[pos] & 0x7f) as u64) << shift;
            shift += 7;
            pos += 1;
            if shift > 63 {
                fatal = Some(format!("entry {} size encoding too long", idx));
                break;
            }
        }
        if fatal.is_some() {
            break;
        }
        let mut base_ofs: Option<i64> = None;
        let mut base_oid: Option<String> = None;
        if declared == Declared::OfsDelta {
            let mut opos = pos;
            match read_ofs_distance(data, &mut opos) {
                Ok(distance) => {
                    let target = pos as i64 - distance as i64;
                    base_ofs = Some(target);
                    pos = opos;
                }
                Err(e) => {
                    fatal = Some(format!("entry {} ofs distance: {}", idx, e));
                    break;
                }
            }
        } else if declared == Declared::RefDelta {
            if pos + 20 > data.len() {
                fatal = Some(format!("entry {} ref oid truncated", idx));
                break;
            }
            let mut hex = String::with_capacity(40);
            for b in &data[pos..pos + 20] {
                hex.push_str(&format!("{:02x}", b));
            }
            base_oid = Some(hex);
            pos += 20;
        }
        let hdr_end = pos;
        let zdata_start = pos;
        let inflate = inflate_at(data, pos, Some(size), HARD_LIMIT);
        match inflate {
            Ok(res) => {
                let zdata_end = pos + res.consumed;
                pos = zdata_end;
                entries.push(RawEntry {
                    hdr_start,
                    hdr_end,
                    zdata_start,
                    zdata_end,
                    declared,
                    declared_size: size,
                    base_ofs,
                    base_oid,
                    payload: res.data,
                    status: "ok".into(),
                    error: None,
                });
            }
            Err(InflateError::DeclaredTooSmall { declared, actual, result })
            | Err(InflateError::DeclaredTooLarge { declared, actual, result }) => {
                let zdata_end = pos + result.consumed;
                pos = zdata_end;
                entries.push(RawEntry {
                    hdr_start,
                    hdr_end,
                    zdata_start,
                    zdata_end,
                    declared,
                    declared_size: size,
                    base_ofs,
                    base_oid,
                    payload: result.data,
                    status: "size_spoof".into(),
                    error: Some(format!(
                        "declared {} but inflated {} (hdr size field {})",
                        declared, actual, size
                    )),
                });
            }
            Err(other) => {
                fatal = Some(format!("entry {} fatal zlib: {}", idx, other.message()));
                break;
            }
        }
    }

    // Build candidates even though trailer may be unverifiable yet.
    let mut offsets: Vec<(i64, i64)> = Vec::new(); // (offset, cid)
    let db = store.conn.lock().unwrap();
    db.execute(
        "UPDATE sources SET kind='pack', version=?1, obj_count=?2 WHERE id=?3",
        params![version as i64, count as i64, source_id],
    )
    .map_err(|e| ("db".to_string(), e.to_string()))?;

    for ent in &entries {
        let mut status = ent.status.clone();
        let mut err = ent.error.clone();
        if let Some(bofs) = ent.base_ofs {
            if bofs < 12 || bofs >= ent.hdr_start as i64 {
                status = "bad_ofs".into();
                err = Some(format!(
                    "ofs-delta distance out of bounds: target offset {}",
                    bofs
                ));
            }
        }
        let oid = if ent.declared.is_delta() || status != "ok" {
            match ent.declared.full_type() {
                Some(t) if status == "ok" => Some(git_oid(t.name(), &ent.payload)),
                Some(t) => Some(git_oid(t.name(), &ent.payload)),
                None => None,
            }
        } else {
            ent.declared.full_type().map(|t| git_oid(t.name(), &ent.payload))
        };
        db.execute(
            "INSERT INTO candidates
             (source_id, origin, pack_offset, declared_type, declared_size, inflated_size,
              hdr_start, hdr_end, zdata_start, zdata_end, base_ofs, base_oid,
              oid, parse_status, parse_error, evidence)
             VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                source_id,
                ent.hdr_start as i64,
                ent.declared.name(),
                ent.declared_size as i64,
                ent.payload.len() as i64,
                ent.hdr_start as i64,
                ent.hdr_end as i64,
                ent.zdata_start as i64,
                ent.zdata_end as i64,
                ent.base_ofs,
                ent.base_oid,
                oid,
                status,
                err,
                format!(
                    "header[{},{}), zlib[{},{}), consumed {}",
                    ent.hdr_start,
                    ent.hdr_end,
                    ent.zdata_start,
                    ent.zdata_end,
                    ent.zdata_end - ent.zdata_start
                )
            ],
        )
        .map_err(|e| ("db".to_string(), e.to_string()))?;
        let cid = db.last_insert_rowid();
        offsets.push((ent.hdr_start as i64, cid));
    }
    drop(db);

    for (i, ent) in entries.iter().enumerate() {
        let cid = offsets[i].1;
        store.write_payload(cid, &ent.payload).ok();
    }

    // ofs edges + range validation
    let db = store.conn.lock().unwrap();
    for (i, ent) in entries.iter().enumerate() {
        let cid = offsets[i].1;
        if let Some(bofs) = ent.base_ofs {
            let target = offsets
                .iter()
                .find(|(off, _)| *off == bofs)
                .map(|(_, id)| *id);
            db.execute(
                "INSERT INTO edges(from_cid, to_cid, to_oid, kind) VALUES(?1,?2,NULL,'ofs')",
                params![cid, target],
            )
            .map_err(|e| ("db".to_string(), e.to_string()))?;
        }
        if let Some(oid) = &ent.base_oid {
            db.execute(
                "INSERT INTO edges(from_cid, to_cid, to_oid, kind) VALUES(?1,NULL,?2,'ref')",
                params![cid, oid],
            )
            .map_err(|e| ("db".to_string(), e.to_string()))?;
        }
    }

    // trailer verification
    let trailer_pos = pos;
    let mut trailer_ok = false;
    let mut checksum: Option<String> = None;
    if let Some(fatal_msg) = &fatal {
        db.execute(
            "UPDATE sources SET parse_status='truncated', parse_error=?1 WHERE id=?2",
            params![fatal_msg, source_id],
        )
        .ok();
        report.warnings.push(format!("truncated: {}", fatal_msg));
    } else if trailer_pos + 20 == data.len() {
        let calc = sha1_hex(&data[..trailer_pos]);
        let stored: String = data[trailer_pos..trailer_pos + 20]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        checksum = Some(stored.clone());
        trailer_ok = calc == stored;
        let pstatus = if trailer_ok { "ok" } else { "checksum_bad" };
        let perr = if trailer_ok {
            None
        } else {
            Some(format!("pack trailer checksum mismatch: stored {}, calc {}", stored, calc))
        };
        db.execute(
            "UPDATE sources SET pack_checksum=?1, trailer_ok=?2, parse_status=?3, parse_error=?4 WHERE id=?5",
            params![stored, trailer_ok as i64, pstatus, perr, source_id],
        )
        .ok();
        if !trailer_ok {
            report.warnings.push("pack checksum mismatch".into());
        }
    } else if trailer_pos + 20 < data.len() {
        let calc = sha1_hex(&data[..trailer_pos]);
        let stored: String = data[trailer_pos..trailer_pos + 20]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        trailer_ok = calc == stored;
        checksum = Some(stored);
        db.execute(
            "UPDATE sources SET pack_checksum=?1, trailer_ok=?2, note=?3 WHERE id=?4",
            params![
                stored,
                trailer_ok as i64,
                format!("{} trailing bytes after 20-byte trailer", data.len() - trailer_pos - 20),
                source_id
            ],
        )
        .ok();
    } else {
        db.execute(
            "UPDATE sources SET parse_status='truncated', parse_error='trailer missing' WHERE id=?1",
            params![source_id],
        )
        .ok();
        report.warnings.push("trailer missing".into());
    }
    let _ = checksum;
    Ok(())
}

fn parse_idx(
    store: &Store,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> Result<(), (String, String)> {
    if data.len() < 8 {
        return Err(("corrupt".into(), "idx shorter than magic".into()));
    }
    if &data[0..4] != &[0xff, 0x74, 0x4f, 0x63] {
        return Err(("unsupported".into(), "only idx v2 supported".into()));
    }
    if &data[4..8] != &[0, 0, 0, 2] {
        return Err(("unsupported".into(), "idx version != 2".into()));
    }
    let mut fanout = Vec::with_capacity(256);
    let mut last = 0u32;
    for i in 0..256 {
        let pos = 8 + i * 4;
        let v = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if v < last {
            return Err((
                "corrupt".into(),
                format!("fanout bucket {} decreases", i),
            ));
        }
        last = v;
        fanout.push(v);
    }
    let n = fanout[255] as usize;
    let names_start = 8 + 256 * 4;
    let crc_start = names_start + n * 20;
    let off_start = crc_start + n * 4;
    let big_start = off_start + n * 4;
    let need = big_start.max(off_start) + 40;
    if data.len() < need {
        return Err(("corrupt".into(), "idx table truncated".into()));
    }
    let pack_checksum: String = data[big_start..big_start + 20]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let idx_checksum: String = data[big_start + 20..big_start + 40]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let calc_idx = sha1_hex(&data[..big_start + 20]);
    if calc_idx != idx_checksum {
        return Err((
            "checksum_bad".into(),
            format!("idx self checksum mismatch: stored {}, calc {}", idx_checksum, calc_idx),
        ));
    }

    struct IdxRow {
        oid: String,
        crc: u32,
        offset: u64,
    }
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let npos = names_start + i * 20;
        let oid: String = data[npos..npos + 20]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let cpos = crc_start + i * 4;
        let crc = u32::from_be_bytes([data[cpos], data[cpos + 1], data[cpos + 2], data[cpos + 3]]);
        let opos = off_start + i * 4;
        let raw = u32::from_be_bytes([data[opos], data[opos + 1], data[opos + 2], data[opos + 3]]);
        let offset = if raw & 0x8000_0000 != 0 {
            let table_idx = (raw & 0x7fff_ffff) as usize;
            let bpos = big_start + table_idx * 8;
            if bpos + 8 > data.len() - 40 {
                return Err(("corrupt".into(), "64-bit offset table truncated".into()));
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[bpos..bpos + 8]);
            u64::from_be_bytes(bytes)
        } else {
            raw as u64
        };
        rows.push(IdxRow { oid, crc, offset });
    }

    let db = store.conn.lock().unwrap();
    db.execute(
        "UPDATE sources SET kind='idx', obj_count=?1, pack_checksum=?2, version=2 WHERE id=?3",
        params![n as i64, pack_checksum, source_id],
    )
    .map_err(|e| ("db".to_string(), e.to_string()))?;
    db.execute("DELETE FROM idx_entries WHERE source_id=?1", params![source_id])
        .ok();
    db.execute("DELETE FROM idx_fanout WHERE source_id=?1", params![source_id])
        .ok();
    {
        let mut stmt = db
            .prepare("INSERT INTO idx_fanout(source_id,bucket,value) VALUES(?1,?2,?3)")
            .map_err(|e| ("db".to_string(), e.to_string()))?;
        for (i, v) in fanout.iter().enumerate() {
            stmt.execute(params![source_id, i as i64, *v as i64])
                .map_err(|e| ("db".to_string(), e.to_string()))?;
        }
    }
    {
        let mut stmt = db
            .prepare("INSERT INTO idx_entries(source_id,oid,crc,pack_offset) VALUES(?1,?2,?3,?4)")
            .map_err(|e| ("db".to_string(), e.to_string()))?;
        for r in &rows {
            stmt.execute(params![source_id, r.oid, r.crc as i64, r.offset as i64])
                .map_err(|e| ("db".to_string(), e.to_string()))?;
        }
    }
    drop(db);
    let _ = report;
    Ok(())
}

/// Pair every idx with its pack by pack checksum, then annotate candidates with
/// idx oid + CRC verification. Returns human-readable mismatch warnings.
pub fn pair_packs(store: &Store) -> Vec<String> {
    let mut warnings = Vec::new();
    let db = store.conn.lock().unwrap();
    let packs: Vec<(i64, String, i64)> = db
        .prepare(
            "SELECT id, COALESCE(pack_checksum,''), COALESCE(obj_count,-1)
             FROM sources WHERE kind='pack'",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let idxs: Vec<(i64, String, i64)> = db
        .prepare(
            "SELECT id, COALESCE(pack_checksum,''), COALESCE(obj_count,-1)
             FROM sources WHERE kind='idx'",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    for (pid, pchecksum, pcount) in &packs {
        let matched: Vec<_> = idxs.iter().filter(|(_, cs, _)| cs == pchecksum).collect();
        let source_data = std::fs::read(store.source_path(*pid)).unwrap_or_default();
        if matched.is_empty() {
            warnings.push(format!("pack {} has no matching index", pid));
            continue;
        }
        for (iid, _, icount) in matched {
            if icount != pcount {
                warnings.push(format!(
                    "index {} object count {} differs from pack {} count {}",
                    iid, icount, pid, pcount
                ));
            }
            let rows: Vec<(String, u32, i64)> = db
                .prepare("SELECT oid, crc, pack_offset FROM idx_entries WHERE source_id=?1")
                .unwrap()
                .query_map(params![iid], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32, r.get::<_, i64>(2)?))
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            for (oid, idx_crc, offset) in rows {
                let cid: Option<i64> = db
                    .query_row(
                        "SELECT id FROM candidates WHERE source_id=?1 AND pack_offset=?2",
                        params![pid, offset],
                        |r| r.get(0),
                    )
                    .optional()
                    .ok()
                    .flatten();
                let Some(cid) = cid else {
                    warnings.push(format!(
                        "index {} references offset {} absent in pack {}",
                        iid, offset, pid
                    ));
                    continue;
                };
                let (z_start, z_end, hdr_start): (i64, i64, i64) = db
                    .query_row(
                        "SELECT zdata_start, zdata_end, hdr_start FROM candidates WHERE id=?1",
                        params![cid],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .unwrap();
                let start = hdr_start as usize;
                let end = z_end as usize;
                let calc = if end <= source_data.len() {
                    crc32(&source_data[start..end]) as i64
                } else {
                    -1
                };
                let crc_ok = calc == idx_crc as i64;
                if !crc_ok {
                    warnings.push(format!(
                        "candidate {} CRC mismatch: idx 0x{:08x}, calc 0x{:08x}",
                        cid, idx_crc, calc as u32
                    ));
                }
                db.execute(
                    "UPDATE candidates SET idx_oid=?1, idx_crc=?2, crc_ok=?3 WHERE id=?4",
                    params![oid, idx_crc as i64, crc_ok, cid],
                )
                .ok();
            }
        }
    }
    for (iid, cs, _) in &idxs {
        if !packs.iter().any(|(_, pcs, _)| pcs == cs) {
            warnings.push(format!("index {} has no matching pack", iid));
        }
    }
    warnings
}

/// Resolve ref-delta edges to concrete base candidates via their final oid.
/// Import-order independent: chooses deterministically among duplicates.
pub fn link_ref_edges(store: &Store) {
    let db = store.conn.lock().unwrap();
    let dangling: Vec<(i64, String)> = db
        .prepare("SELECT from_cid, to_oid FROM edges WHERE kind='ref' AND to_cid IS NULL")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    for (from, oid) in dangling {
        let base: Option<i64> = db
            .query_row(
                "SELECT id FROM candidates
                 WHERE oid=?1 AND parse_status='ok'
                 ORDER BY (declared_type IN ('ofs_delta','ref_delta')) ASC, id ASC
                 LIMIT 1",
                params![oid],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
            .or_else(|| {
                db.query_row(
                    "SELECT id FROM candidates WHERE idx_oid=?1 ORDER BY id ASC LIMIT 1",
                    params![oid],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten()
            });
        db.execute(
            "UPDATE edges SET to_cid=?1 WHERE from_cid=?2 AND kind='ref' AND to_oid=?3",
            params![base, from, oid],
        )
        .ok();
    }
}

use rusqlite::OptionalExtension;
