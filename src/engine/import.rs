//! Import path: sniff file kind, persist bytes under the data directory,
//! parse and build candidates/evidence, then reconcile indexes with packs.

use super::Engine;
use crate::gitio::{hex_oid, parse_hex_oid, sha1_bytes, ObjType};
use crate::idx;
use crate::loose;
use crate::pack;
use rusqlite::params;
use std::path::Path;

pub struct ImportResult {
    pub source_id: i64,
    pub affected: i64,
}

pub fn sniff_and_store(
    engine: &mut Engine,
    filename: &str,
    bytes: &[u8],
    digest: &str,
) -> rusqlite::Result<(String, ImportResult)> {
    let name = filename.to_ascii_lowercase();
    let kind = if bytes.len() >= 4 && &bytes[..4] == b"PACK" {
        "pack"
    } else if bytes.len() >= 8 && &bytes[..4] == b"\xfftOc" {
        "idx"
    } else if looks_like_loose_path(&name) {
        "loose"
    } else {
        // Try to inflate a loose object as a last resort.
        match loose::parse_loose(bytes) {
            Ok(_) => "loose",
            Err(_) => "unknown",
        }
    };
    let kind = kind.to_string();

    let rel = format!("sources/{digest}");
    let stored = engine.data_dir.join(&rel);
    std::fs::write(&stored, bytes).map_err(rusqlite::Error::from)?;

    engine.store.conn.execute(
        "INSERT INTO sources(filename, kind, sha256, byte_len, stored_path)
         VALUES(?1,?2,?3,?4,?5)",
        params![filename, kind, digest, bytes.len() as i64, rel],
    )?;
    let source_id = engine.store.conn.last_insert_rowid();

    let mut affected = 0i64;
    match kind.as_str() {
        "pack" => affected = import_pack(engine, source_id, bytes)?,
        "idx" => affected = import_idx(engine, source_id, bytes)?,
        "loose" => affected = import_loose(engine, source_id, filename, bytes)?,
        _ => evidence(
            engine,
            "error",
            "UnrecognizedInput",
            &format!("could not identify {filename} as pack, idx or loose object"),
            Some(source_id),
            None,
            None,
        )?,
    }
    Ok((kind, ImportResult { source_id, affected }))
}

fn looks_like_loose_path(name: &str) -> bool {
    // Git loose layout: <2 hex chars>/<38 hex chars>.
    let flat: String = name.split('/').collect();
    let flat = flat.trim_end_matches(".gitobject");
    if flat.len() != 40 {
        return false;
    }
    parse_hex_oid(flat).is_some()
}

pub(crate) fn evidence(
    engine: &mut Engine,
    severity: &str,
    code: &str,
    message: &str,
    source_id: Option<i64>,
    candidate_id: Option<i64>,
    offset: Option<i64>,
) -> rusqlite::Result<()> {
    engine.store.conn.execute(
        "INSERT INTO evidence(severity, code, message, source_id, candidate_id, \"offset\")
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![severity, code, message, source_id, candidate_id, offset],
    )?;
    Ok(())
}

fn idx_offsets_for_pack(engine: &Engine, pack_checksum: &str) -> Vec<u64> {
    let mut stmt = engine
        .store
        .conn
        .prepare(
            "SELECT i.id FROM sources i
             WHERE i.kind='idx' AND i.linked_pack_sha = ?1",
        )
        .unwrap();
    let ids: Vec<i64> = stmt
        .query_map(params![pack_checksum], |r| r.get::<_, i64>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    let mut offsets = Vec::new();
    for id in ids {
        let mut s2 = engine
            .store
            .conn
            .prepare("SELECT \"offset\" FROM idx_anchors WHERE idx_source_id=?1")
            .unwrap();
        let rows = s2
            .query_map(params![id], |r| r.get::<_, i64>(0))
            .unwrap();
        for r in rows.flatten() {
            offsets.push(r as u64);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn insert_pack_candidate(
    engine: &mut Engine,
    source_id: i64,
    e: &pack::PackEntry,
    known_oid: Option<[u8; 20]>,
    crc_ok: Option<bool>,
) -> rusqlite::Result<i64> {
    let oid_s = known_oid.map(|o| hex_oid(&o));
    let ref_base = e.ref_base.map(|o| hex_oid(&o));
    let sort_key = format!(
        "{:02}:{}:{:016x}",
        oid_s.as_deref().unwrap_or("~~~~~~~~~~~~~~~~~~~~"),
        source_id,
        e.offset
    );
    engine.store.conn.execute(
        "INSERT OR IGNORE INTO candidates(
            source_id, kind, \"offset\", oid, obj_type, declared_size, actual_size,
            zlib_ok, size_ok, crc_ok, base_offset, ofs_distance, ref_base, inflated, sort_key)
         VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            source_id,
            e.offset as i64,
            oid_s,
            e.obj_type.name(),
            e.declared_size as i64,
            e.inflated_len as i64,
            e.zlib_ok,
            e.declared_size as i64 == e.inflated_len as i64,
            crc_ok,
            e.base_offset.map(|v| v as i64),
            e.ofs_distance.map(|v| v as i64),
            ref_base,
            e.inflated,
            sort_key
        ],
    )?;
    engine.store.conn.query_row(
        "SELECT id FROM candidates WHERE source_id=?1 AND \"offset\"=?2 AND kind='pack'",
        params![source_id, e.offset as i64],
        |r| r.get::<_, i64>(0),
    )
}

fn import_pack(engine: &mut Engine, source_id: i64, bytes: &[u8]) -> rusqlite::Result<i64> {
    let hints = pack_hint_offsets(engine, bytes);
    let info = match pack::parse_pack(bytes, &hints) {
        Ok(info) => info,
        Err(err) => {
            evidence(engine, "error", "PackParse", &err, Some(source_id), None, None)?;
            engine
                .store
                .conn
                .execute("UPDATE sources SET trailer_ok=0 WHERE id=?1", params![source_id])?;
            return Ok(0);
        }
    };
    engine.store.conn.execute(
        "UPDATE sources SET pack_version=?2, pack_object_count=?3, trailer_ok=?4, pack_checksum=?5 WHERE id=?1",
        params![
            source_id,
            info.version as i64,
            info.count as i64,
            info.trailer_ok,
            hex_oid(&info.checksum)
        ],
    )?;
    if let Some(err) = &info.trailer_error {
        evidence(engine, "warning", "PackChecksum", err, Some(source_id), None, None)?;
    }
    for (off, err) in &info.parse_failures {
        evidence(
            engine,
            "error",
            "EntryIsolated",
            &format!("object at offset {off} isolated: {err}"),
            Some(source_id),
            None,
            Some(*off as i64),
        )?;
    }
    let checksum_hex = hex_oid(&info.checksum);

    // CRC values advertised by any matching indexes.
    let crc_map = crc_map_for_pack(engine, &checksum_hex);

    for e in &info.entries {
        let known = idx_oid_for_offset(engine, &checksum_hex, e.offset);
        let crc_ok = crc_map.get(&e.offset).map(|good| *good);
        let cid = insert_pack_candidate(engine, source_id, e, known, crc_ok)?;
        if !e.zlib_ok {
            if let Some(msg) = &e.inflate_error {
                evidence(
                    engine,
                    "error",
                    "ZlibBoundary",
                    &format!("offset {}: {msg}", e.offset),
                    Some(source_id),
                    Some(cid),
                    Some(e.offset as i64),
                )?;
            }
        }
        if e.declared_size as u64 != e.inflated_len {
            evidence(
                engine,
                "error",
                "SpoofedSize",
                &format!(
                    "offset {} declares size {} but inflates to {} bytes",
                    e.offset, e.declared_size, e.inflated_len
                ),
                Some(source_id),
                Some(cid),
                Some(e.offset as i64),
            )?;
        }
        if let Some(false) = crc_ok {
            evidence(
                engine,
                "error",
                "BadCrc",
                &format!("idx CRC32 does not match raw entry at offset {}", e.offset),
                Some(source_id),
                Some(cid),
                Some(e.offset as i64),
            )?;
        }
        if let Some(expected) = known {
            assign_known_oid_evidence(engine, cid, expected, source_id, e.offset)?;
        }
    }
    Ok(info.entries.len() as i64)
}

fn pack_hint_offsets(engine: &Engine, bytes: &[u8]) -> Vec<u64> {
    if bytes.len() < 20 {
        return Vec::new();
    }
    let stored = &bytes[bytes.len() - 20..];
    idx_offsets_for_pack(engine, &hex_oid(stored))
}

fn idx_oid_for_offset(
    engine: &Engine,
    pack_checksum: &str,
    offset: u64,
) -> Option<[u8; 20]> {
    let mut stmt = engine
        .store
        .conn
        .prepare(
            "SELECT a.oid FROM idx_anchors a JOIN sources s ON s.id = a.idx_source_id
             WHERE s.linked_pack_sha = ?1 AND a.\"offset\" = ?2 LIMIT 1",
        )
        .unwrap();
    let s = stmt
        .query_row(
            params![pack_checksum, offset as i64],
            |r| r.get::<_, String>(0),
        )
        .ok()?;
    parse_hex_oid(&s)
}

fn crc_map_for_pack(engine: &Engine, pack_checksum: &str) -> std::collections::HashMap<u64, bool> {
    let mut out = std::collections::HashMap::new();
    let advertised: Vec<(u64, u32)> = {
        let mut stmt = engine
            .store
            .conn
            .prepare(
                "SELECT a.\"offset\", a.crc32 FROM idx_anchors a
                 JOIN sources i ON i.id = a.idx_source_id
                 WHERE i.linked_pack_sha = ?1",
            )
            .unwrap();
        stmt.query_map(params![pack_checksum], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .map(|(o, c)| (o as u64, c))
        .collect()
    };
    if advertised.is_empty() {
        return out;
    }
    let rel: Option<String> = engine
        .store
        .conn
        .query_row(
            "SELECT stored_path FROM sources WHERE kind='pack' AND pack_checksum=?1",
            params![pack_checksum],
            |r| r.get(0),
        )
        .ok();
    let rel = match rel {
        Some(r) => r,
        None => return out,
    };
    let bytes = match std::fs::read(engine.data_dir.join(&rel)) {
        Ok(b) => b,
        Err(_) => return out,
    };
    for (off, expected) in advertised {
        if let Some(entry) = crate::pack::parse_pack(&bytes, &[off])
            .ok()
            .and_then(|mut i| i.entries.drain(..).find(|e| e.offset == off))
        {
            let actual = crc32fast::hash(&entry.raw_entry);
            out.insert(off, actual == expected);
        }
    }
    out
}

fn assign_known_oid_evidence(
    engine: &mut Engine,
    cid: i64,
    expected: [u8; 20],
    source_id: i64,
    offset: u64,
) -> rusqlite::Result<()> {
    // For non-deltas we can verify immediately; deltas are verified after
    // resolution and only get their advertised oid recorded here.
    let (otype, inflated, zlib_ok, size_ok): (
        String,
        Vec<u8>,
        bool,
        bool,
    ) = engine.store.conn.query_row(
        "SELECT obj_type, inflated, zlib_ok, size_ok FROM candidates WHERE id=?1",
        params![cid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if otype.ends_with("-delta") {
        engine.store.conn.execute(
            "UPDATE candidates SET oid=?2 WHERE id=?1 AND oid IS NULL",
            params![cid, hex_oid(&expected)],
        )?;
        return Ok(());
    }
    engine
        .store
        .conn
        .execute("UPDATE candidates SET oid=?2 WHERE id=?1", params![cid, hex_oid(&expected)])?;
    if !zlib_ok || !size_ok {
        return Ok(());
    }
    let concrete = match otype.as_str() {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        _ => return Ok(()),
    };
    let actual = crate::gitio::hash_object(concrete, &inflated);
    let ok = actual == expected;
    engine
        .store
        .conn
        .execute("UPDATE candidates SET hash_ok=?2 WHERE id=?1", params![cid, ok])?;
    if !ok {
        evidence(
            engine,
            "error",
            "ObjectIdMismatch",
            &format!(
                "offset {}: idx advertises {} but recomputed object id is {}",
                offset,
                hex_oid(&expected),
                hex_oid(&actual)
            ),
            Some(source_id),
            Some(cid),
            Some(offset as i64),
        )?;
    }
}

fn import_idx(engine: &mut Engine, source_id: i64, bytes: &[u8]) -> rusqlite::Result<i64> {
    let info = match idx::parse_idx(bytes) {
        Ok(i) => i,
        Err(err) => {
            evidence(engine, "error", "IdxParse", &err, Some(source_id), None, None)?;
            return Ok(0);
        }
    };
    let fanout_json = serde_json::to_string(
        &info.fanout.iter().map(|v| *v as i64).collect::<Vec<_>>(),
    )
    .unwrap();
    engine.store.conn.execute(
        "UPDATE sources SET fanout=?2, pack_object_count=?3, trailer_ok=?4, linked_pack_sha=?5 WHERE id=?1",
        params![
            source_id,
            fanout_json,
            info.entries.len() as i64,
            info.pack_trailer_ok && info.idx_trailer_ok,
            hex_oid(&info.pack_checksum)
        ],
    )?;
    if let Some(err) = &info.fanout_error {
        evidence(engine, "error", "Fanout", err, Some(source_id), None, None)?;
    }
    if let Some(err) = &info.trailer_error {
        evidence(engine, "warning", "IdxChecksum", err, Some(source_id), None, None)?;
    }
    for entry in &info.entries {
        engine.store.conn.execute(
            "INSERT OR IGNORE INTO idx_anchors(idx_source_id, oid, \"offset\", crc32)
             VALUES(?1,?2,?3,?4)",
            params![source_id, hex_oid(&entry.oid), entry.offset as i64, entry.crc32],
        )?;
    }
    Ok(info.entries.len() as i64)
}

fn import_loose(
    engine: &mut Engine,
    source_id: i64,
    filename: &str,
    bytes: &[u8],
) -> rusqlite::Result<i64> {
    let advertised = filename
        .split('/')
        .collect::<String>()
        .trim_end_matches(".gitobject")
        .to_string();
    let advertised_oid = parse_hex_oid(&advertised);
    let info = match loose::parse_loose(bytes) {
        Ok(i) => i,
        Err(err) => {
            evidence(engine, "error", "LooseParse", &err, Some(source_id), None, None)?;
            return Ok(0);
        }
    };
    let computed = crate::gitio::hash_object(info.obj_type, &info.content);
    let oid = advertised_oid.unwrap_or(computed);
    let oid_hex = hex_oid(&oid);
    let zlib_ok = info.zlib_ok;
    let size_ok = info.size_ok;
    let sort_key = format!("{oid_hex}:{source_id}:-1");
    engine.store.conn.execute(
        "INSERT INTO candidates(source_id, kind, \"offset\", oid, obj_type, declared_size,
            actual_size, zlib_ok, size_ok, inflated, sort_key)
         VALUES(?1,'loose',-1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            source_id,
            oid_hex,
            info.obj_type.name(),
            info.declared_size as i64,
            info.content.len() as i64,
            zlib_ok,
            size_ok,
            info.content,
            sort_key
        ],
    )?;
    let cid = engine.store.conn.last_insert_rowid();
    if let Some(err) = &info.inflate_error {
        evidence(engine, "error", "ZlibBoundary", err, Some(source_id), Some(cid), None)?;
    }
    if !size_ok {
        evidence(
            engine,
            "error",
            "SpoofedSize",
            &format!(
                "loose object header declares {} bytes but content is {} bytes",
                info.declared_size,
                info.content.len()
            ),
            Some(source_id),
            Some(cid),
            None,
        )?;
    }
    let hash_ok = computed == oid;
    engine
        .store
        .conn
        .execute("UPDATE candidates SET hash_ok=?2 WHERE id=?1", params![cid, hash_ok])?;
    if !hash_ok {
        evidence(
            engine,
            "error",
            "ObjectIdMismatch",
            &format!(
                "loose filename advertises {} but recomputed object id is {}",
                oid_hex,
                hex_oid(&computed)
            ),
            Some(source_id),
            Some(cid),
            None,
        )?;
    }
    Ok(1)
}
