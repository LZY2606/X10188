//! File import: store bytes, parse pack/idx/loose, register candidates.

use crate::error::AppResult;
use crate::idx::{parse_idx, RawIdx};
use crate::pack::{parse_pack, ParseLimits, RawPack};
use crate::store::{next_seq, Store};
use rusqlite::{params, Connection};
use std::fs;

#[derive(Debug)]
pub struct ImportedFile {
    pub source_id: i64,
    pub kind: String,
    pub file_name: String,
}

pub fn detect_kind(file_name: &str, data: &[u8]) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".pack") || (data.len() >= 4 && &data[0..4] == b"PACK") {
        return Some("pack");
    }
    if lower.ends_with(".idx")
        || (data.len() >= 8 && &data[0..4] == b"\xfftOc")
        || looks_like_v1_idx(data)
    {
        return Some("idx");
    }
    if matches!(data.first(), Some(0x78)) {
        return Some("loose");
    }
    None
}

fn looks_like_v1_idx(data: &[u8]) -> bool {
    if data.len() < 1024 {
        return false;
    }
    let last = u32::from_be_bytes(data[1020..1024].try_into().unwrap());
    (1..=10_000_000).contains(&last)
}

pub fn import_file(
    conn: &mut Connection,
    store: &Store,
    file_name: &str,
    data: Vec<u8>,
) -> AppResult<ImportedFile> {
    let kind = detect_kind(file_name, &data)
        .ok_or_else(|| crate::error::AppError::Conflict("unrecognized file type".into()))?
        .to_string();
    let hash = Store::sha256(&data);
    if let Ok((sid, k)) = conn.query_row(
        "SELECT id, kind FROM sources WHERE content_sha256=?1",
        params![hash],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    ) {
        return Ok(ImportedFile {
            source_id: sid,
            kind: k,
            file_name: file_name.to_string(),
        });
    }

    let seq = next_seq(conn, "import_seq")?;
    let ext = match kind.as_str() {
        "pack" => "pack",
        "idx" => "idx",
        _ => "loose",
    };
    let stored_rel = format!("sources/{seq:06}.{ext}");
    let stored_full = store.data_dir.join(&stored_rel);
    fs::create_dir_all(stored_full.parent().unwrap())?;
    fs::write(&stored_full, &data)?;

    conn.execute(
        "INSERT INTO sources(kind, file_name, content_sha256, size, stored_path, import_seq)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![kind, file_name, hash, data.len() as i64, stored_rel, seq],
    )?;
    let sid = conn.last_insert_rowid();

    let mut fatal: Option<String> = None;
    match kind.as_str() {
        "pack" => fatal = import_pack(conn, store, sid, &data)?,
        "idx" => import_idx(conn, store, sid, &data)?,
        _ => import_loose(conn, store, sid, file_name, &data)?,
    }
    if let Some(msg) = fatal {
        conn.execute(
            "UPDATE sources SET parse_fatal=?1 WHERE id=?2",
            params![msg, sid],
        )?;
    }
    reconcile_pairs(conn, store)?;
    Ok(ImportedFile {
        source_id: sid,
        kind,
        file_name: file_name.to_string(),
    })
}

fn evidence(
    conn: &Connection,
    sid: i64,
    level: &str,
    code: &str,
    msg: &str,
    detail: Option<&str>,
) {
    conn.execute(
        "INSERT INTO source_evidence(source_id, level, code, message, detail)
         VALUES(?1,?2,?3,?4,?5)",
        params![sid, level, code, msg, detail],
    )
    .ok();
}

fn read_source_bytes(store: &Store, stored_path: &str) -> AppResult<Vec<u8>> {
    Ok(fs::read(store.data_dir.join(stored_path))?)
}

#[derive(Default)]
struct CandidateInsert {
    claimed_oid: Option<String>,
    oid: Option<String>,
    ordinal: i64,
    header_offset: i64,
    data_offset: i64,
    end_offset: i64,
    declared_size: i64,
    inflated_size: i64,
    obj_type: String,
    crc32: i64,
    ref_base: Option<String>,
    ofs_distance: Option<i64>,
    base_header_offset: Option<i64>,
    content_sha256: Option<String>,
    content_path: Option<String>,
    bad: i64,
    bad_reason: Option<String>,
}

fn insert_pack_candidate(conn: &Connection, sid: i64, c: &CandidateInsert) -> AppResult<i64> {
    conn.execute(
        "INSERT INTO candidates
         (claimed_oid, oid, source_id, origin, ordinal, header_offset, data_offset, end_offset,
          declared_size, inflated_size, obj_type, crc32, ref_base, ofs_distance,
          base_header_offset, content_sha256, content_path, bad, bad_reason)
         VALUES(?1,?2,?3,'pack',?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        params![
            c.claimed_oid,
            c.oid,
            sid,
            c.ordinal,
            c.header_offset,
            c.data_offset,
            c.end_offset,
            c.declared_size,
            c.inflated_size,
            c.obj_type,
            c.crc32,
            c.ref_base,
            c.ofs_distance,
            c.base_header_offset,
            c.content_sha256,
            c.content_path,
            c.bad,
            c.bad_reason
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn import_pack(
    conn: &mut Connection,
    store: &Store,
    sid: i64,
    data: &[u8],
) -> AppResult<Option<String>> {
    let limits = ParseLimits::default();
    let parsed: RawPack = match parse_pack(data, &limits) {
        Ok(p) => p,
        Err(e) => {
            evidence(conn, sid, "error", "pack_parse", &e, None);
            return Ok(Some(e));
        }
    };

    if parsed.trailer_checksum != parsed.computed_checksum {
        evidence(
            conn,
            sid,
            "error",
            "pack_checksum",
            "pack trailer sha1 mismatch",
            Some(&format!(
                "trailer={} computed={}",
                parsed.trailer_checksum, parsed.computed_checksum
            )),
        );
    }
    evidence(
        conn,
        sid,
        "info",
        "packsum",
        "pack sha1 checksum",
        Some(&parsed.computed_checksum),
    );

    for e in &parsed.entries {
        let mut ci = CandidateInsert {
            ordinal: e.index as i64,
            header_offset: e.header_offset as i64,
            data_offset: e.data_offset as i64,
            end_offset: e.end_offset as i64,
            declared_size: e.declared_size as i64,
            inflated_size: e.inflated_len as i64,
            obj_type: e.obj_type.name().to_string(),
            crc32: e.crc32 as i64,
            ref_base: e.ref_base.clone(),
            ofs_distance: e.negative_offset,
            bad: e.inflate_error.is_some() as i64,
            bad_reason: e.inflate_error.clone(),
            ..Default::default()
        };
        if let Some(dist) = e.negative_offset {
            ci.base_header_offset = Some(e.header_offset as i64 - dist);
        }
        if e.obj_type.is_content() && e.inflate_error.is_none() {
            if let Ok(z) = crate::zlibm::inflate_member(data, e.data_offset, limits.inflate_limit)
                .map(|z| z.data)
            {
                if z.len() == e.inflated_len {
                    let (h, rel) = store.write_content(&z)?;
                    ci.content_sha256 = Some(h);
                    ci.content_path = Some(rel);
                    if z.len() as u64 == e.declared_size {
                        ci.oid = Some(crate::git::git_object_id(e.obj_type, &z));
                    }
                }
            }
        }
        let cid = insert_pack_candidate(conn, sid, &ci)?;
        if e.obj_type.is_delta() {
            conn.execute(
                "INSERT INTO graph_edges(candidate_id, base_oid, base_header_offset, kind)
                 VALUES(?1,?2,?3,?4)",
                params![cid, e.ref_base, ci.base_header_offset, e.obj_type.name()],
            )?;
        }
    }

    if let Some(msg) = &parsed.fatal {
        evidence(conn, sid, "error", "pack_fatal", msg, None);
    }
    Ok(parsed.fatal)
}

fn import_idx(conn: &mut Connection, store: &Store, sid: i64, data: &[u8]) -> AppResult<()> {
    let _ = store;
    let raw: RawIdx = match parse_idx(data) {
        Ok(r) => r,
        Err(e) => {
            evidence(conn, sid, "error", "idx_parse", &e, None);
            conn.execute("UPDATE sources SET parse_fatal=?1 WHERE id=?2", params![e, sid])?;
            return Ok(());
        }
    };
    if let Some(msg) = &raw.fatal {
        evidence(conn, sid, "error", "idx_fatal", msg, None);
    }
    if raw.pack_checksum != raw.computed_pack_checksum {
        evidence(
            conn,
            sid,
            "error",
            "idx_pack_checksum",
            "idx embedded pack sha1 field invalid",
            Some(&format!(
                "field={} computed={}",
                raw.pack_checksum, raw.computed_pack_checksum
            )),
        );
    }
    if raw.index_checksum != raw.computed_index_checksum {
        evidence(
            conn,
            sid,
            "error",
            "idx_self_checksum",
            "idx trailer sha1 mismatch",
            Some(&format!(
                "trailer={} computed={}",
                raw.index_checksum, raw.computed_index_checksum
            )),
        );
    }
    evidence(
        conn,
        sid,
        "info",
        "idx_packsum",
        "pack sha1 claimed by index",
        Some(&raw.pack_checksum),
    );
    let fanout = serde_json::to_string(&raw.fanout).unwrap_or_default();
    evidence(conn, sid, "info", "idx_fanout", "fanout table", Some(&fanout));
    Ok(())
}

fn import_loose(
    conn: &mut Connection,
    store: &Store,
    sid: i64,
    file_name: &str,
    data: &[u8],
) -> AppResult<()> {
    let parsed = match crate::loose::parse_loose(data, ParseLimits::default().inflate_limit) {
        Ok(p) => p,
        Err(e) => {
            evidence(conn, sid, "error", "loose_parse", &e, None);
            conn.execute("UPDATE sources SET parse_fatal=?1 WHERE id=?2", params![e, sid])?;
            return Ok(());
        }
    };
    let (h, rel) = store.write_content(&parsed.payload)?;
    let claimed = extract_oid_from_loose_path(file_name);
    let check_ok = claimed.as_deref() == Some(parsed.computed_oid.as_str());
    if let Some(want) = &claimed {
        if !check_ok {
            evidence(
                conn,
                sid,
                "error",
                "loose_oid_mismatch",
                &format!(
                    "loose path implies {want} but content hashes to {}",
                    parsed.computed_oid
                ),
                None,
            );
        }
    }
    if parsed.size_spoof {
        evidence(
            conn,
            sid,
            "error",
            "loose_size_spoof",
            &format!(
                "loose header declares {} bytes but payload is {}",
                parsed.declared_size,
                parsed.payload.len()
            ),
            None,
        );
    }
    conn.execute(
        "INSERT INTO candidates
         (claimed_oid, oid, source_id, origin, obj_type, declared_size, inflated_size,
          content_sha256, content_path, bad, bad_reason)
         VALUES(?1,?2,?3,'loose',?4,?5,?6,?7,?8,?9,?10)",
        params![
            claimed,
            parsed.computed_oid,
            sid,
            parsed.obj_type.name(),
            parsed.declared_size as i64,
            parsed.payload.len() as i64,
            h,
            rel,
            (!check_ok || parsed.size_spoof) as i64,
            if parsed.size_spoof {
                Some("declared size does not match payload".to_string())
            } else if !check_ok {
                Some("oid implied by path does not match content".to_string())
            } else {
                None
            }
        ],
    )?;
    Ok(())
}

fn extract_oid_from_loose_path(file_name: &str) -> Option<String> {
    let name = file_name.rsplit('/').next().unwrap_or(file_name);
    let parent = file_name.rsplit('/').nth(1).unwrap_or("");
    if parent.len() == 2
        && name.len() == 38
        && parent.chars().all(|c| c.is_ascii_hexdigit())
        && name.chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(format!("{parent}{name}"))
    } else if name.len() == 40 && name.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Match imported idx files to imported packs by pack sha1, then attach
/// claims (oid, idx crc32) to pack candidates. Idempotent.
fn reconcile_pairs(conn: &mut Connection, store: &Store) -> AppResult<()> {
    let packs: Vec<(i64, String)> = {
        let mut stmt = conn.prepare(
            "SELECT s.id, e.detail FROM sources s
             JOIN source_evidence e ON e.source_id=s.id AND e.code='packsum'
             WHERE s.kind='pack'",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    for (pack_sid, pack_sum) in &packs {
        let idx_sid: Option<i64> = conn
            .query_row(
                "SELECT e.source_id FROM source_evidence e
                 JOIN sources s ON s.id=e.source_id
                 WHERE e.code='idx_packsum' AND e.detail=?1 AND s.kind='idx'
                 ORDER BY s.import_seq LIMIT 1",
                params![pack_sum],
                |r| r.get(0),
            )
            .ok();
        let Some(idx_sid) = idx_sid else { continue };
        apply_idx_to_pack(conn, store, idx_sid, *pack_sid)?;
    }
    // Warn about orphan indexes.
    let orphan_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sources s WHERE s.kind='idx'
         AND NOT EXISTS (
           SELECT 1 FROM source_evidence e WHERE e.source_id=s.id AND e.code='idx_attached'
         )
         AND NOT EXISTS (
           SELECT 1 FROM source_evidence e2
           WHERE e2.source_id=s.id AND e2.code='idx_packsum'
             AND e2.detail IN (SELECT detail FROM source_evidence WHERE code='packsum')
         )",
        [],
        |r| r.get(0),
    )?;
    if orphan_count > 0 {
        let mut stmt = conn.prepare(
            "SELECT id FROM sources s WHERE s.kind='idx'
             AND NOT EXISTS (
               SELECT 1 FROM source_evidence e2
               WHERE e2.source_id=s.id AND e2.code='idx_packsum'
                 AND e2.detail IN (SELECT detail FROM source_evidence WHERE code='packsum')
             )",
        )?;
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for id in ids {
            let already: i64 = conn.query_row(
                "SELECT COUNT(*) FROM source_evidence WHERE source_id=?1 AND code='idx_orphan'",
                params![id],
                |r| r.get(0),
            )?;
            if already == 0 {
                evidence(
                    conn,
                    id,
                    "warning",
                    "idx_orphan",
                    "no imported pack matches this index; claims recorded but untrusted",
                    None,
                );
            }
        }
    }
    Ok(())
}

fn apply_idx_to_pack(
    conn: &mut Connection,
    store: &Store,
    idx_sid: i64,
    pack_sid: i64,
) -> AppResult<()> {
    let already: i64 = conn.query_row(
        "SELECT COUNT(*) FROM source_evidence WHERE source_id=?1 AND code='idx_attached'",
        params![idx_sid],
        |r| r.get(0),
    )?;
    if already > 0 {
        return Ok(());
    }
    let stored: String = conn.query_row(
        "SELECT stored_path FROM sources WHERE id=?1",
        params![idx_sid],
        |r| r.get(0),
    )?;
    let bytes = read_source_bytes(store, &stored)?;
    let raw = parse_idx(&bytes).map_err(|e| crate::error::AppError::Db(e))?;

    let mut by_offset: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    {
        let mut stmt =
            conn.prepare("SELECT id, header_offset FROM candidates WHERE source_id=?1")?;
        let rows = stmt.query_map(params![pack_sid], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in rows.flatten() {
            by_offset.insert(r.1, r.0);
        }
    }

    for ie in &raw.entries {
        let off = ie.offset as i64;
        let Some(&cid) = by_offset.get(&off) else {
            evidence(
                conn,
                idx_sid,
                "error",
                "idx_offset_missing",
                &format!(
                    "idx claims {} at offset {off} but pack has no entry there",
                    ie.oid
                ),
                None,
            );
            continue;
        };
        let (stored_oid, stored_crc): (Option<String>, Option<i64>) = conn.query_row(
            "SELECT oid, crc32 FROM candidates WHERE id=?1",
            params![cid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        conn.execute(
            "UPDATE candidates SET claimed_oid=?1, idx_crc32=?2 WHERE id=?3",
            params![ie.oid, ie.crc32.map(|c| c as i64), cid],
        )?;
        if let Some(idx_crc) = ie.crc32 {
            if let Some(pack_crc) = stored_crc {
                if pack_crc as u32 != idx_crc {
                    evidence(
                        conn,
                        pack_sid,
                        "error",
                        "crc_mismatch",
                        &format!(
                            "offset {off}: idx crc {:08x} != computed pack crc {:08x}",
                            idx_crc, pack_crc as u32
                        ),
                        Some(&ie.oid),
                    );
                    conn.execute(
                        "UPDATE candidates SET bad=1,
                         bad_reason=COALESCE(bad_reason,'crc32 mismatch with index')
                         WHERE id=?1",
                        params![cid],
                    )?;
                }
            }
        }
        if let Some(computed) = stored_oid {
            if computed != ie.oid {
                evidence(
                    conn,
                    pack_sid,
                    "error",
                    "oid_mismatch",
                    &format!(
                        "offset {off}: idx claims {} but recomputed oid is {computed}",
                        ie.oid
                    ),
                    None,
                );
                conn.execute(
                    "UPDATE candidates SET bad=1,
                     bad_reason='recomputed oid disagrees with index' WHERE id=?1",
                    params![cid],
                )?;
            }
        } else {
            // Delta entries obtain their oid trustingly from the index;
            // reconstruction still verifies the object id afterwards.
            conn.execute(
                "UPDATE candidates SET oid=?1 WHERE id=?2",
                params![ie.oid, cid],
            )?;
        }
    }

    let mut stmt = conn.prepare(
        "SELECT header_offset FROM candidates WHERE source_id=?1 AND claimed_oid IS NULL",
    )?;
    let missing: Vec<i64> = stmt
        .query_map(params![pack_sid], |r| r.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();
    for off in missing {
        evidence(
            conn,
            idx_sid,
            "warning",
            "idx_missing_entry",
            &format!("pack entry at offset {off} absent from index"),
            None,
        );
    }

    evidence(
        conn,
        idx_sid,
        "info",
        "idx_attached",
        &format!("index attached to pack {pack_sid}"),
        None,
    );
    Ok(())
}
