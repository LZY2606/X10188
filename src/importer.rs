//! Import files into the project data directory and register their parsed
//! contents as candidates.  Packs and indexes are auto-paired by their pack
//! checksum so CRC values and fanout can be cross-checked.

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::gitid::to_hex;
use crate::idx::parse_idx;
use crate::loose::parse_loose;
use crate::pack::{parse_pack, PackEntry};
use crate::store::Store;
use crate::types::{GitType, SourceKind};

/// Cap on inflating a single entry during import (size-spoof guard).
pub const IMPORT_INFLATE_CAP: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: SourceKind,
    pub filename: String,
    pub checksum_hex: Option<String>,
    pub candidates_added: usize,
    pub notes: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    to_hex(&h.finalize())
}

pub fn detect_kind(filename: &str, data: &[u8]) -> Option<SourceKind> {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") || &data[..4] == b"PACK" {
        return Some(SourceKind::Pack);
    }
    if lower.ends_with(".idx") || data.len() >= 4 && data[..4] == crate::idx::IDX_V2_MAGIC {
        return Some(SourceKind::Idx);
    }
    if lower.contains('/') || lower.starts_with("0") || looks_like_loose(data) {
        return Some(SourceKind::Loose);
    }
    None
}

fn looks_like_loose(data: &[u8]) -> bool {
    // zlib stream beginning with a textual type name is a strong heuristic.
    use flate2::Decompress;
    if data.is_empty() {
        return false;
    }
    let mut d = Decompress::new(true);
    let mut out = [0u8; 32];
    let mut pos = 0usize;
    loop {
        let in_before = d.total_in() as usize;
        let res = d.decompress(
            &data[pos..],
            &mut out[d.total_out() as usize..],
            flate2::FlushDecompress::None,
        );
        pos += d.total_in() as usize - in_before;
        match res {
            Ok(flate2::Status::Ok) if d.total_out() < 8 => continue,
            _ => break,
        }
    }
    let n = d.total_out() as usize;
    let head = &out[..n];
    head.starts_with(b"commit ") || head.starts_with(b"tree ")
        || head.starts_with(b"blob ") || head.starts_with(b"tag ")
}

/// Copy bytes into the data dir, register the source, parse and index it.
pub fn import_file(
    store: &Store,
    data_dir: &Path,
    filename: &str,
    data: &[u8],
    now: i64,
) -> rusqlite::Result<ImportReport> {
    let kind = detect_kind(filename, data)
        .ok_or_else(|| rusqlite::Error::ToSqlConversionFailure(
            format!("cannot recognise file type of {filename}").into()))?;
    fs::create_dir_all(data_dir).map_err(io_err)?;

    // Keep the original bytes on disk under the data directory.
    let safe = filename
        .replace('/', "_")
        .replace('\\', "_")
        .replace("..", "_");
    let on_disk = data_dir.join(format!("{now}-{safe}"));
    fs::write(&on_disk, data).map_err(io_err)?;

    let sha = sha256_hex(data);
    let mut report = ImportReport {
        source_id: 0,
        kind,
        filename: filename.to_string(),
        checksum_hex: None,
        candidates_added: 0,
        notes: Vec::new(),
    };

    let mut conn = store.conn.lock().unwrap();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO sources(filename, kind, path, sha256, size, imported_at, checksum_hex)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![filename, kind.label(), on_disk.to_string_lossy(), sha, data.len() as i64, now],
    )?;
    let source_id = tx.last_insert_rowid();
    report.source_id = source_id;

    match kind {
        SourceKind::Pack => import_pack(&tx, source_id, data, &mut report)?,
        SourceKind::Idx => import_idx(&tx, source_id, data, &mut report)?,
        SourceKind::Loose => import_loose(&tx, source_id, filename, data, &mut report)?,
    }

    // Pair up sources: attach CRCs/oids between packs and matching idx.
    pair_packs_and_idx(&tx, &mut report)?;

    tx.commit()?;
    Ok(report)
}

fn io_err(e: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

fn insert_candidate(
    tx: &Connection,
    source_id: i64,
    kind: GitType,
    oid_hex: Option<&str>,
    e: &PackEntry,
) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT INTO candidates(
            source_id, kind, oid_hex, offset, declared_size, actual_size,
            crc_idx, crc_actual, parse_error, base_ref_hex, base_offset,
            data_offset, compressed_len)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            source_id,
            kind.label(),
            oid_hex,
            e.offset as i64,
            e.declared_size as i64,
            e.actual_size as i64,
            e.crc_from_idx.map(|c| c as i64),
            e.crc_actual as i64,
            e.error,
            e.base_oid.map(|o| to_hex(&o)),
            e.ofs_distance.map(|d| (e.offset as i64) - d as i64),
            e.data_offset as i64,
            e.compressed_len as i64,
        ],
    )?;
    let cid = tx.last_insert_rowid();
    if let Some(payload) = &e.payload {
        let role = if kind.is_base() { "raw" } else { "raw" };
        tx.execute(
            "INSERT INTO blobs(candidate_id, role, content, len) VALUES (?1, ?2, ?3, ?4)",
            params![cid, role, payload, payload.len() as i64],
        )?;
    }
    Ok(cid)
}

fn import_pack(
    tx: &Connection,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    let parsed = parse_pack(data, IMPORT_INFLATE_CAP);
    let checksum = if let Some(h) = &parsed.header {
        let hex = to_hex(&h.trailer_stored);
        report.checksum_hex = Some(hex.clone());
        Some(hex)
    } else {
        None
    };
    tx.execute(
        "UPDATE sources SET checksum_hex = ?1 WHERE id = ?2",
        params![checksum, source_id],
    )?;

    if let Some(h) = &parsed.header {
        if !h.trailer_ok {
            add_finding(
                tx,
                source_id,
                None,
                "error",
                "pack_checksum_mismatch",
                &format!(
                    "pack trailer sha1 {} != computed {}",
                    to_hex(&h.trailer_stored),
                    to_hex(&h.trailer_computed)
                ),
            )?;
        }
        if h.num_objects_declared as usize != parsed.entries.len() {
            add_finding(
                tx,
                source_id,
                None,
                "error",
                "pack_count_mismatch",
                &format!(
                    "pack declares {} objects, {} entries readable",
                    h.num_objects_declared,
                    parsed.entries.len()
                ),
            )?;
        }
    }
    for err in &parsed.errors {
        add_finding(
            tx,
            source_id,
            None,
            "error",
            "pack_parse_error",
            &format!("@{}: {}", err.offset, err.message),
        )?;
    }

    for e in &parsed.entries {
        let kind = e.kind.unwrap_or(GitType::Blob);
        let cid = insert_candidate(tx, source_id, kind, None, e)?;
        if e.error.is_some() {
            tx.execute(
                "UPDATE candidates SET resolve_status='error', error_summary=?1 WHERE id=?2",
                params![e.error, cid],
            )?;
        }
        if let Some(msg) = &e.error {
            add_finding(tx, source_id, Some(cid), "error", "entry_error", msg)?;
        }
        report.candidates_added += 1;
    }
    Ok(())
}

fn import_loose(
    tx: &Connection,
    source_id: i64,
    filename: &str,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    // Expect a path-like name: ab/cdef....
    let compact: String = filename.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let declared_oid = if compact.len() >= 40 {
        Some(compact[..40].to_string())
    } else {
        None
    };

    match parse_loose(data, IMPORT_INFLATE_CAP) {
        Ok(obj) => {
            let computed = to_hex(&crate::gitid::git_object_id(obj.kind, &obj.content));
            let oid = declared_oid.clone().unwrap_or_else(|| computed.clone());
            tx.execute(
                "INSERT INTO candidates(source_id, kind, oid_hex, declared_size, actual_size,
                    compressed_len, resolve_status, needs_recompute)
                 VALUES (?1,?2,?3,?4,?5,?6,'ready',1)",
                params![source_id, obj.kind.label(), oid, obj.declared_size as i64,
                    obj.content.len() as i64, obj.compressed_len as i64],
            )?;
            let cid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO blobs(candidate_id, role, content, len) VALUES (?1,'raw',?2,?3)",
                params![cid, obj.content, obj.content.len() as i64],
            )?;
            report.candidates_added += 1;
            report.checksum_hex = Some(computed.clone());
            if declared_oid.as_deref() != Some(computed.as_str()) {
                add_finding(
                    tx,
                    source_id,
                    Some(cid),
                    "error",
                    "loose_oid_mismatch",
                    &format!(
                        "loose path names {} but content hashes to {}",
                        declared_oid.unwrap_or_else(|| "<none>".into()),
                        computed
                    ),
                )?;
                tx.execute(
                    "UPDATE candidates SET parse_error=?1, resolve_status='error' WHERE id=?2",
                    params![
                        format!("content hash {} disagrees with path oid", computed),
                        cid
                    ],
                )?;
            }
        }
        Err(err) => {
            let msg = err.to_string();
            tx.execute(
                "INSERT INTO candidates(source_id, kind, oid_hex, declared_size, actual_size,
                    resolve_status, error_summary, needs_recompute)
                 VALUES (?1,'blob',?2,0,0,'error',?3,0)",
                params![source_id, declared_oid, msg],
            )?;
            let cid = tx.last_insert_rowid();
            add_finding(tx, source_id, Some(cid), "error", "loose_error", &msg)?;
            report.candidates_added += 1;
        }
    }
    Ok(())
}

fn add_finding(
    tx: &Connection,
    source_id: i64,
    candidate_id: Option<i64>,
    severity: &str,
    code: &str,
    message: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO findings(source_id, candidate_id, severity, code, message)
         VALUES (?1,?2,?3,?4,?5)",
        params![source_id, candidate_id, severity, code, message],
    )?;
    Ok(())
}

fn import_idx(
    tx: &Connection,
    source_id: i64,
    data: &[u8],
    report: &mut ImportReport,
) -> rusqlite::Result<()> {
    let parsed = parse_idx(data);
    let pack_hex = to_hex(&parsed.pack_checksum);
    report.checksum_hex = Some(pack_hex.clone());
    tx.execute(
        "UPDATE sources SET checksum_hex = ?1 WHERE id = ?2",
        params![pack_hex, source_id],
    )?;

    let mut error_text: Option<String> = None;
    if !parsed.idx_checksum_ok {
        let msg = format!(
            "idx checksum mismatch: stored {} != computed {}",
            to_hex(&parsed.idx_checksum_stored),
            to_hex(&parsed.idx_checksum_computed)
        );
        error_text = Some(msg.clone());
        add_finding(tx, source_id, None, "error", "idx_checksum_mismatch", &msg)?;
    }
    for e in &parsed.errors {
        add_finding(tx, source_id, None, "error", "idx_structure", e)?;
        error_text = Some(e.clone());
    }

    tx.execute(
        "INSERT INTO idx_meta(source_id, pack_checksum_hex, idx_checksum_ok, num_objects, error)
         VALUES (?1,?2,?3,?4,?5)",
        params![source_id, pack_hex, parsed.idx_checksum_ok as i64,
            parsed.num_objects as i64, error_text],
    )?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO idx_fanout(source_id, bucket, cumulative) VALUES (?1,?2,?3)")?;
        for (bucket, cumulative) in parsed.fanout.iter().enumerate() {
            stmt.execute(params![source_id, bucket as i64, *cumulative as i64])?;
        }
    }
    Ok(())
}

/// After any import, reconcile every idx with the pack sharing its checksum.
fn pair_packs_and_idx(
    tx: &Connection,
    _report: &mut ImportReport,
) -> rusqlite::Result<()> {
    // idx sources with their named pack checksum
    let mut idx_rows = tx.prepare(
        "SELECT s.id, s.checksum_hex FROM sources s WHERE s.kind='idx'")?;
    let idxs: Vec<(i64, Option<String>)> = idx_rows
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    drop(idx_rows);

    for (idx_id, pack_hex) in idxs {
        let Some(pack_hex) = pack_hex else { continue };
        let pack_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM sources WHERE kind='pack' AND checksum_hex=?1
                 ORDER BY id LIMIT 1",
                params![pack_hex],
                |r| r.get(0),
            )
            .optional()?;
        let Some(pack_id) = pack_id else {
            add_finding(
                tx,
                idx_id,
                None,
                "warn",
                "idx_without_pack",
                "no imported pack matches this index checksum",
            )?;
            continue;
        };

        // idx rows: oid, offset, crc
        let fan = read_idx_entries(tx, idx_id)?;
        let count_declared = fan.len();
        let pack_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM candidates WHERE source_id=?1",
            params![pack_id],
            |r| r.get(0),
        )?;
        if count_declared as i64 != pack_count {
            add_finding(
                tx,
                idx_id,
                None,
                "error",
                "idx_pack_count_mismatch",
                &format!("idx lists {count_declared} objects, pack parsed {pack_count}"),
            )?;
        }

        for (oid_hex, offset, crc) in fan {
            let cid: Option<i64> = tx
                .query_row(
                    "SELECT id FROM candidates WHERE source_id=?1 AND offset=?2",
                    params![pack_id, offset as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(cid) = cid else {
                add_finding(
                    tx,
                    idx_id,
                    None,
                    "error",
                    "idx_offset_orphan",
                    &format!("idx oid {oid_hex} points at pack offset {offset} with no entry"),
                )?;
                continue;
            };
            tx.execute(
                "UPDATE candidates SET oid_hex=?1, crc_idx=?2 WHERE id=?3",
                params![oid_hex, crc as i64, cid],
            )?;
            // CRC cross-check (actual is over the exact on-disk entry bytes).
            let actual: Option<i64> = tx.query_row(
                "SELECT crc_actual FROM candidates WHERE id=?1",
                params![cid],
                |r| r.get(0),
            )?;
            if let Some(actual) = actual
                && actual as u32 != crc
            {
                add_finding(
                    tx,
                    idx_id,
                    Some(cid),
                    "error",
                    "crc_mismatch",
                    &format!(
                        "oid {oid_hex} @{offset}: idx crc {:08x} != computed {:08x}",
                        crc, actual as u32
                    ),
                )?;
                tx.execute(
                    "UPDATE candidates SET parse_error=COALESCE(parse_error, ?1) WHERE id=?2",
                    params![format!("CRC mismatch: idx {crc:08x} actual {actual:08x}"), cid],
                )?;
            }
        }

        // Reverse: pack entries with no idx row.
        let idx_offsets: std::collections::HashSet<i64> =
            read_idx_entries(tx, idx_id)?.into_iter().map(|(_, o, _)| o as i64).collect();
        let mut stmt = tx
            .prepare("SELECT id, offset FROM candidates WHERE source_id=?1")?;
        let rows: Vec<(i64, i64)> = stmt
            .query_map(params![pack_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);
        for (cid, off) in rows {
            if !idx_offsets.contains(&off) {
                add_finding(
                    tx,
                    idx_id,
                    Some(cid),
                    "warn",
                    "pack_entry_without_idx",
                    &format!("pack entry @{off} has no matching idx row"),
                )?;
            }
        }
    }
    Ok(())
}

fn read_idx_entries(
    tx: &Connection,
    idx_id: i64,
) -> rusqlite::Result<Vec<(String, u64, u32)>> {
    // Re-read from disk: the oid/offset/crc tables live in the imported file.
    let path: String = tx.query_row(
        "SELECT path FROM sources WHERE id=?1",
        params![idx_id],
        |r| r.get(0),
    )?;
    let data = fs::read(&path).map_err(io_err)?;
    let parsed = parse_idx(&data);
    Ok(parsed
        .entries
        .iter()
        .map(|e| (to_hex(&e.oid), e.offset, e.crc32))
        .collect())
}
