//! File import: bytes are preserved verbatim under the data directory, type is
//! detected from content (never the filename extension), and parse artefacts
//! are persisted. A broken file is isolated; importing it never blocks analysis
//! of the other files.

use crate::db::State;
use crate::git::{split_delta_payload, GitType};
use crate::idx::parse_idx;
use crate::loose::parse_loose;
use crate::pack::{parse_pack, PackEntry};
use rusqlite::{params, Transaction};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub detail: String,
}

fn ioerr(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

fn detect_kind(raw: &[u8]) -> &'static str {
    if raw.len() >= 8 && &raw[0..4] == b"PACK" {
        return "pack";
    }
    if raw.len() >= 8 && &raw[0..4] == b"\xfftOc" {
        return "idx";
    }
    if let Ok(inf) = crate::zlib_util::inflate_one(raw, 4096) {
        if let Some(nul) = inf.data.iter().position(|b| *b == 0) {
            if let Ok(head) = std::str::from_utf8(&inf.data[..nul]) {
                if let Some((ty, size)) = head.split_once(' ') {
                    if GitType::from_loose_name(ty).is_some()
                        && size.bytes().all(|b| b.is_ascii_digit())
                    {
                        return "loose";
                    }
                }
            }
        }
    }
    "unknown"
}

pub fn import_bytes(state: &State, filename: &str, raw: &[u8]) -> std::io::Result<ImportReport> {
    let mut hasher = Sha256::new();
    hasher.update(raw);
    let content_sha256 = hex::encode(hasher.finalize());

    let kind = detect_kind(raw);
    let safe_name = Path::new(filename)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".into());
    let stored_name = format!("{content_sha256}__{safe_name}");
    let storage_rel = format!("sources/{stored_name}");
    let storage_abs = state.sources_dir.join(&stored_name);
    if !storage_abs.exists() {
        std::fs::write(&storage_abs, raw)?;
    }

    let mut conn = state.db.lock().unwrap();
    let tx = conn.transaction().map_err(ioerr)?;

    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM source WHERE content_sha256 = ?1 AND filename = ?2",
            params![content_sha256, filename],
            |row| row.get(0),
        )
        .ok();

    let (source_id, reused) = if let Some(id) = existing {
        (id, true)
    } else {
        let seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(imported_seq),0)+1 FROM source",
                [],
                |r| r.get(0),
            )
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO source(filename,kind,size_bytes,content_sha256,imported_seq,storage_path)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![filename, kind, raw.len() as i64, content_sha256, seq, storage_rel],
        )
        .map_err(ioerr)?;
        (tx.last_insert_rowid(), false)
    };

    // Re-deriving parse rows keeps re-import idempotent.
    let detail = if reused {
        "identical file already imported; refreshed derived data".to_string()
    } else {
        match kind {
            "pack" => import_pack(&tx, state, source_id, raw)?,
            "idx" => import_idx(&tx, source_id, raw),
            "loose" => import_loose(&tx, state, source_id, raw),
            _ => "stored as unknown (not a pack/idx/loose object)".to_string(),
        }
    };
    if reused {
        match kind {
            "pack" => {
                import_pack(&tx, state, source_id, raw)?;
            }
            "idx" => {
                import_idx(&tx, source_id, raw);
            }
            "loose" => {
                import_loose(&tx, state, source_id, raw);
            }
            _ => {}
        }
    }

    tx.commit().map_err(ioerr)?;
    drop(conn);
    crate::candidates::rebuild_candidates(state);
    Ok(ImportReport {
        source_id,
        kind: kind.to_string(),
        detail,
    })
}

fn save_object_copy(state: &State, name: &str, data: &[u8]) -> std::io::Result<String> {
    let rel = format!("objects/{name}");
    let abs = state.data_dir.join(&rel);
    std::fs::write(abs, data)?;
    Ok(rel)
}

fn delta_fields(e: &PackEntry) -> (Option<i64>, Option<i64>, Option<i64>, Option<String>) {
    if !matches!(e.type_name.as_str(), "ofs-delta" | "ref-delta") {
        return (None, None, None, None);
    }
    let ty = GitType::from_pack_code(e.type_code).unwrap();
    if let Some((base_size, result_size, _header_bytes, instr_start, ref_oid)) =
        split_delta_payload(&e.inflated, ty)
    {
        (
            Some(base_size as i64),
            Some(result_size as i64),
            Some(instr_start as i64),
            ref_oid.map(hex::encode),
        )
    } else {
        (None, None, None, None)
    }
}

fn import_pack(
    tx: &Transaction,
    state: &State,
    source_id: i64,
    raw: &[u8],
) -> std::io::Result<String> {
    let parsed = match parse_pack(raw) {
        Ok(p) => p,
        Err(e) => return Ok(format!("pack parse failed: {e}")),
    };
    tx.execute(
        "INSERT INTO pack_info(source_id,version,num_objects,trailer_expected,trailer_actual,
             trailer_ok,scan_completed) VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(source_id) DO UPDATE SET
           version=excluded.version,num_objects=excluded.num_objects,
           trailer_expected=excluded.trailer_expected,trailer_actual=excluded.trailer_actual,
           trailer_ok=excluded.trailer_ok,scan_completed=excluded.scan_completed",
        params![
            source_id,
            parsed.version,
            parsed.num_objects,
            hex::encode(parsed.trailer_expected),
            hex::encode(parsed.trailer_actual),
            parsed.trailer_ok as i64,
            parsed.scan_completed as i64,
        ],
    )
    .map_err(ioerr)?;

    tx.execute(
        "DELETE FROM pack_entry WHERE pack_source_id = ?1",
        params![source_id],
    )
    .map_err(ioerr)?;

    let mut n_saved = 0usize;
    for e in &parsed.entries {
        let inflated_path = if e.inflated.is_empty() {
            None
        } else {
            Some(save_object_copy(
                state,
                &format!("inflate_{}.bin", e.content_sha256),
                &e.inflated,
            )?)
        };
        let (delta_base_size, delta_result_size, delta_instr_start, delta_ref) = delta_fields(e);
        tx.execute(
            "INSERT INTO pack_entry(pack_source_id,ordinal,offset,header_len,type_code,type_name,
                 declared_size,ofs_distance,base_offset,base_oid,zlib_offset,compressed_len,
                 inflated_len,adler_ok,crc32,content_sha256,size_matches_header,inflated_path,
                 parse_error,delta_base_size,delta_result_size,delta_instr_start,delta_ref_oid)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            params![
                source_id,
                e.ordinal as i64,
                e.offset as i64,
                e.header_len as i64,
                e.type_code as i64,
                e.type_name,
                e.declared_size as i64,
                e.ofs_distance.map(|v| v as i64),
                e.base_offset,
                e.base_oid.map(hex::encode),
                e.zlib_offset as i64,
                e.compressed_len as i64,
                e.inflated_len as i64,
                e.adler_ok as i64,
                e.crc32 as i64,
                e.content_sha256,
                e.size_matches_header as i64,
                inflated_path,
                e.parse_error,
                delta_base_size,
                delta_result_size,
                delta_instr_start,
                delta_ref,
            ],
        )
        .map_err(ioerr)?;
        n_saved += 1;
    }
    Ok(format!(
        "pack v{}: {}/{} objects, trailer {}, scan {}, {} issue(s)",
        parsed.version,
        n_saved,
        parsed.num_objects,
        if parsed.trailer_ok { "ok" } else { "BAD" },
        if parsed.scan_completed { "complete" } else { "halted" },
        parsed.issues.len()
    ))
}

fn import_idx(tx: &Transaction, source_id: i64, raw: &[u8]) -> String {
    let parsed = match parse_idx(raw) {
        Ok(p) => p,
        Err(e) => return format!("idx parse failed: {e}"),
    };
    if tx
        .execute(
            "INSERT INTO idx_info(source_id,num_objects,pack_checksum,idx_checksum_ok)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(source_id) DO UPDATE SET num_objects=excluded.num_objects,
               pack_checksum=excluded.pack_checksum,idx_checksum_ok=excluded.idx_checksum_ok",
            params![
                source_id,
                parsed.num_objects,
                hex::encode(parsed.pack_checksum_expected),
                parsed.idx_checksum_ok as i64,
            ],
        )
        .is_err()
    {
        return "idx metadata insert failed".into();
    }
    tx.execute(
        "DELETE FROM idx_entry WHERE idx_source_id = ?1",
        params![source_id],
    )
    .ok();
    for ent in &parsed.entries {
        tx.execute(
            "INSERT INTO idx_entry(idx_source_id,ordinal,oid,crc32,offset,large_offset)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                source_id,
                ent.ordinal as i64,
                hex::encode(ent.oid),
                ent.crc32 as i64,
                ent.offset as i64,
                ent.large_offset as i64
            ],
        )
        .ok();
    }
    format!(
        "idx v2: {} entries, fanout_tip {}, checksum {}, {} issue(s)",
        parsed.num_objects,
        parsed.fanout[255],
        if parsed.idx_checksum_ok { "ok" } else { "BAD" },
        parsed.issues.len()
    )
}

fn import_loose(tx: &Transaction, state: &State, source_id: i64, raw: &[u8]) -> String {
    let parsed = match parse_loose(raw) {
        Ok(p) => p,
        Err(e) => return format!("loose parse failed: {e}"),
    };
    let oid_hex = hex::encode(parsed.computed_oid);
    let rel = format!("objects/loose_{oid_hex}.bin");
    let abs = state.data_dir.join(&rel);
    std::fs::write(abs, &parsed.body).ok();
    let ok = tx
        .execute(
            "INSERT INTO loose_info(source_id,declared_type,declared_size,computed_oid,header_ok,
                 adler_ok,content_sha256,body_path,issue)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(source_id) DO UPDATE SET declared_type=excluded.declared_type,
               declared_size=excluded.declared_size,computed_oid=excluded.computed_oid,
               header_ok=excluded.header_ok,adler_ok=excluded.adler_ok,
               content_sha256=excluded.content_sha256,body_path=excluded.body_path,issue=excluded.issue",
            params![
                source_id,
                parsed.declared_type,
                parsed.declared_size as i64,
                oid_hex,
                parsed.header_ok as i64,
                parsed.adler_ok as i64,
                parsed.content_sha256,
                rel,
                parsed.issue,
            ],
        )
        .is_ok();
    if !ok {
        return "loose metadata insert failed".into();
    }
    format!(
        "loose {oid_hex} ({} bytes, header {}, adler {})",
        parsed.body.len(),
        if parsed.header_ok { "ok" } else { "SIZE MISMATCH" },
        if parsed.adler_ok { "ok" } else { "BAD" },
    )
}
