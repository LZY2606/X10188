use crate::git::{
    self, crc32, git_object_id, inflate_zlib, oid_hex, parse_index, parse_loose, split_loose_object,
    GitError, ObjectType, HARD_EXPAND_LIMIT,
};
use crate::store::AppState;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone)]
struct EntryRecord {
    offset: usize,
    header_len: i64,
    object_type: ObjectType,
    declared_size: usize,
    payload_offset: usize,
    payload_end: usize,
    data: Vec<u8>,
    payload_crc32: u32,
    negative_distance: Option<i64>,
    base_offset: Option<i64>,
    base_ref_oid: Option<[u8; 20]>,
}

#[derive(Debug, Clone)]
struct HeaderScan {
    version: u32,
    declared_count: usize,
    entries: Vec<Result<EntryRecord, (usize, GitError)>>,
    trailer_offset: usize,
    checksum_ok: bool,
}

#[derive(Debug, Clone)]
pub struct ImportSummary {
    pub source_id: i64,
    pub kind: String,
    pub objects: usize,
    pub evidence: usize,
}

pub fn import_bytes(state: &AppState, filename: &str, data: &[u8]) -> rusqlite::Result<ImportSummary> {
    let sha256 = hex::encode(Sha256::digest(data));
    let kind = detect_kind(filename, data);
    let safe = format!("{}-{}", sha256, sanitize_filename(filename));
    let stored_rel = Path::new("files").join(safe);
    let stored_abs = state.data_dir.join(&stored_rel);
    if !stored_abs.exists() {
        std::fs::write(&stored_abs, data)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    }

    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT OR IGNORE INTO sources(kind, original_name, stored_path, sha256, byte_size)
         VALUES(?1,?2,?3,?4,?5)",
        params![kind, filename, stored_rel.to_string_lossy(), sha256, data.len() as i64],
    )?;
    let source_id = db.query_row(
        "SELECT id FROM sources WHERE sha256=?1",
        params![sha256],
        |row| row.get::<_, i64>(0),
    )?;

    let existing_kind: String = db.query_row(
        "SELECT kind FROM sources WHERE id=?1",
        params![source_id],
        |row| row.get(0),
    )?;
    if existing_kind != "unknown" && existing_kind != kind {
        return Ok(ImportSummary { source_id, kind: existing_kind, objects: 0, evidence: 0 });
    }
    db.execute(
        "UPDATE sources SET kind=?1, parse_status='pending', parse_error=NULL WHERE id=?2",
        params![kind, source_id],
    )?;

    let tx = db.unchecked_transaction()?;
    let mut summary = ImportSummary { source_id, kind: kind.to_string(), objects: 0, evidence: 0 };
    let parse_result = match kind {
        "pack" => import_pack(&tx, state, source_id, data),
        "index" => import_index(&tx, source_id, data),
        "loose" => import_loose(&tx, state, source_id, data),
        _ => Ok(0usize),
    };
    match parse_result {
        Ok(objects) => {
            summary.objects = objects;
            tx.execute(
                "UPDATE sources SET parse_status='parsed', parse_error=NULL WHERE id=?1",
                params![source_id],
            )?;
        }
        Err(err) => {
            let message = err.to_string();
            tx.execute(
                "UPDATE sources SET parse_status='bad', parse_error=?1 WHERE id=?2",
                params![message, source_id],
            )?;
            tx.execute(
                "INSERT INTO evidence(source_id, severity, kind, message, detail_json)
                 VALUES(?1,'error','parse-failure',?2,'{}')",
                params![source_id, message],
            )?;
            summary.evidence = 1;
        }
    }
    link_packs_and_indexes(&tx)?;
    rebuild_candidate_pins_none(&tx)?;
    tx.commit()?;
    Ok(summary)
}

fn detect_kind(filename: &str, data: &[u8]) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if data.starts_with(b"PACK") {
        return "pack";
    }
    if data.len() >= 8 && &data[..4] == b"\xfftOc" {
        return "index";
    }
    if lower.ends_with(".idx") {
        return "index";
    }
    if lower.ends_with(".pack") {
        return "pack";
    }
    "loose"
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn u32_be(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

fn save_payload(state: &AppState, sha256: &str, data: &[u8]) -> std::io::Result<String> {
    let rel = format!("blobs/{}.bin", sha256);
    let path = state.data_dir.join(&rel);
    if !path.exists() {
        std::fs::write(path, data)?;
    }
    Ok(rel)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn read_entry_header(data: &[u8], mut offset: usize) -> Result<(ObjectType, usize, usize, usize, Option<usize>, Option<[u8; 20]>), GitError> {
    let first = *data.get(offset).ok_or(GitError::TooShort("pack entry"))?;
    let object_type = ObjectType::from_pack((first >> 4) & 7)?;
    let mut size = usize::from(first & 0x0f);
    let mut shift = 4;
    let start = offset;
    offset += 1;
    let mut more = first & 0x80 != 0;
    while more {
        let byte = *data.get(offset).ok_or(GitError::TooShort("pack size"))?;
        size |= usize::from(byte & 0x7f) << shift;
        shift += 7;
        more = byte & 0x80 != 0;
        offset += 1;
    }
    let mut negative = None;
    let mut base_oid = None;
    if object_type == ObjectType::OfsDelta {
        let first = *data.get(offset).ok_or(GitError::TooShort("ofs-delta"))?;
        let mut current = first;
        let mut distance = usize::from(first & 0x7f);
        offset += 1;
        while current & 0x80 != 0 {
            let next = *data.get(offset).ok_or(GitError::TooShort("ofs-delta"))?;
            distance = distance
                .checked_add(1)
                .and_then(|value| value.checked_shl(7))
                .ok_or(GitError::InvalidOffset)?
                | usize::from(next & 0x7f);
            current = next;
            offset += 1;
        }
        negative = Some(distance);
    }
    if object_type == ObjectType::RefDelta {
        let bytes = data
            .get(offset..offset + 20)
            .ok_or(GitError::TooShort("ref-delta base OID"))?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(bytes);
        base_oid = Some(oid);
        offset += 20;
    }
    Ok((object_type, start, size, offset, negative, base_oid))
}

fn scan_pack(data: &[u8]) -> Result<HeaderScan, GitError> {
    if data.len() < 32 {
        return Err(GitError::TooShort("pack"));
    }
    if &data[..4] != b"PACK" {
        return Err(GitError::BadSignature);
    }
    let version = u32_be(data, 4);
    if version != 2 {
        return Err(GitError::UnsupportedVersion(version));
    }
    let declared_count = u32_be(data, 8) as usize;
    let trailer_offset = data.len() - 20;
    let mut entries = Vec::new();
    let mut offset = 12;
    while offset < trailer_offset {
        if entries.len() >= declared_count {
            entries.push(Err((offset, GitError::BadObject("more entries than declared"))));
            break;
        }
        let scan = read_entry_header(data, offset);
        let record = match scan {
            Ok((object_type, entry_offset, declared_size, payload_offset, negative, base_oid)) => {
                if object_type == ObjectType::OfsDelta {
                    let distance = negative.unwrap();
                    if distance == 0 || distance > entry_offset || entry_offset - distance < 12 {
                        Err((entry_offset, GitError::InvalidOffset))
                    } else {
                        inflate_entry(
                            data,
                            entry_offset,
                            payload_offset - entry_offset,
                            object_type,
                            declared_size,
                            payload_offset,
                            trailer_offset,
                            Some(distance),
                            None,
                        )
                    }
                } else {
                    inflate_entry(
                        data,
                        entry_offset,
                        payload_offset - entry_offset,
                        object_type,
                        declared_size,
                        payload_offset,
                        trailer_offset,
                        None,
                        base_oid,
                    )
                }
            }
            Err(err) => Err((offset, err)),
        };
        match record {
            Ok(entry) => {
                offset = entry.payload_end;
                entries.push(Ok(entry));
            }
            Err((bad_offset, err)) => {
                entries.push(Err((bad_offset, err)));
                break;
            }
        }
    }
    let checksum_ok = if entries.len() == declared_count
        && matches!(entries.last(), Some(Ok(last)) if last.payload_end == trailer_offset)
    {
        let mut hasher = sha1::Sha1::new();
        hasher.update(&data[..trailer_offset]);
        let actual: [u8; 20] = hasher.finalize().into();
        actual == data[trailer_offset..]
    } else {
        false
    };
    Ok(HeaderScan { version, declared_count, entries, trailer_offset, checksum_ok })
}

#[allow(clippy::too_many_arguments)]
fn inflate_entry(
    data: &[u8],
    offset: usize,
    header_len: usize,
    object_type: ObjectType,
    declared_size: usize,
    payload_offset: usize,
    trailer_offset: usize,
    negative_distance: Option<usize>,
    base_oid: Option<[u8; 20]>,
) -> Result<EntryRecord, (usize, GitError)> {
    if declared_size > HARD_EXPAND_LIMIT {
        return Err((offset, GitError::BadObject("declared size exceeds hard limit")));
    }
    let inflated = inflate_zlib(data, payload_offset, declared_size, Some(declared_size))
        .map_err(|err| (offset, err))?;
    let payload_end = payload_offset + inflated.consumed;
    if payload_end > trailer_offset {
        return Err((offset, GitError::TooShort("pack entry payload")));
    }
    Ok(EntryRecord {
        offset,
        header_len: header_len as i64,
        object_type,
        declared_size,
        payload_offset,
        payload_end,
        data: inflated.data,
        payload_crc32: crc32(&data[offset..payload_end]),
        negative_distance: negative_distance.map(|value| value as i64),
        base_offset: negative_distance.map(|distance| (offset - distance) as i64),
        base_ref_oid: base_oid,
    })
}

fn import_pack(
    tx: &rusqlite::Transaction<'_>,
    state: &AppState,
    source_id: i64,
    data: &[u8],
) -> Result<usize, GitError> {
    let scan = scan_pack(data)?;
    let pack_sha: String = {
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(&data[..scan.trailer_offset]);
        hex::encode(hasher.finalize())
    };
    tx.execute(
        "INSERT INTO packs(source_id, version, entry_count, checksum)
         VALUES(?1,?2,?3,?4)",
        params![source_id, scan.version, scan.declared_count as i64, pack_sha],
    )
    .ok();
    let pack_id = tx.query_row(
        "SELECT id FROM packs WHERE source_id=?1",
        params![source_id],
        |row| row.get::<_, i64>(0),
    )
    .map_err(|_| GitError::BadObject("database error"))?;
    if !scan.checksum_ok {
        add_evidence_sql(
            tx,
            source_id,
            None,
            "error",
            "pack-checksum",
            "pack SHA-1 trailer mismatch",
        );
    }
    let mut count = 0usize;
    for item in &scan.entries {
        let entry = match item {
            Ok(entry) => entry,
            Err((offset, err)) => {
                add_evidence_sql(
                    tx,
                    source_id,
                    None,
                    "error",
                    "bad-entry",
                    &format!("entry at offset {offset}: {err}"),
                );
                continue;
            }
        };
        let payload_hash = sha256_hex(&entry.data);
        let payload_path = save_payload(state, &payload_hash, &entry.data)
            .map_err(|_| GitError::BadObject("cannot store payload"))?;
        tx.execute(
            "INSERT INTO objects(source_id,pack_id,pack_offset,object_type,declared_size,expanded_size,payload_offset,payload_end,payload_crc32,negative_distance,base_offset,base_ref_oid,parse_status,payload_sha256,stored_payload_path)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'parsed',?13,?14)",
            params![
                source_id,
                pack_id,
                entry.offset as i64,
                entry.object_type.name(),
                entry.declared_size as i64,
                entry.data.len() as i64,
                entry.payload_offset as i64,
                entry.payload_end as i64,
                entry.payload_crc32 as i64,
                entry.negative_distance,
                entry.base_offset,
                entry.base_ref_oid.map(|oid| oid_hex(&oid)),
                payload_hash,
                payload_path
            ],
        )
        .ok();
        let object_id = tx
            .query_row(
                "SELECT id FROM objects WHERE source_id=?1 AND pack_offset=?2",
                params![source_id, entry.offset as i64],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        if entry.object_type.is_base() {
            if let Ok((kind, content)) = split_loose_object(&entry.data) {
                let actual = git_object_id(kind.name(), &content);
                insert_candidate(
                    tx,
                    &actual,
                    object_id,
                    "pack",
                    scan.checksum_ok,
                    if scan.checksum_ok { None } else { Some("pack checksum mismatch") },
                );
            }
        }
        count += 1;
    }
    Ok(count)
}

fn import_index(
    tx: &rusqlite::Transaction<'_>,
    source_id: i64,
    data: &[u8],
) -> Result<usize, GitError> {
    let index = parse_index(data)?;
    tx.execute(
        "INSERT INTO indexes(source_id,entry_count,pack_checksum,checksum_ok)
         VALUES(?1,?2,?3,1)",
        params![source_id, index.entries.len() as i64, oid_hex(&index.pack_checksum)],
    )
    .ok();
    let index_id = tx
        .query_row(
            "SELECT id FROM indexes WHERE source_id=?1",
            params![source_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| GitError::BadObject("database error"))?;
    for (bucket, value) in index.fanout.iter().enumerate() {
        tx.execute(
            "INSERT OR REPLACE INTO fanout(index_id,bucket,cumulative) VALUES(?1,?2,?3)",
            params![index_id, bucket as i64, *value as i64],
        )
        .ok();
    }
    for entry in &index.entries {
        tx.execute(
            "INSERT INTO index_entries(index_id,oid,pack_offset,crc32) VALUES(?1,?2,?3,?4)",
            params![
                index_id,
                oid_hex(&entry.oid),
                entry.offset as i64,
                entry.crc32 as i64
            ],
        )
        .ok();
    }
    Ok(index.entries.len())
}

fn import_loose(
    tx: &rusqlite::Transaction<'_>,
    state: &AppState,
    source_id: i64,
    data: &[u8],
) -> Result<usize, GitError> {
    let (kind, content, consumed) = parse_loose(data)?;
    let actual = git_object_id(kind.name(), &content);
    let payload_hash = sha256_hex(&content);
    let payload_path = save_payload(state, &payload_hash, &content)
        .map_err(|_| GitError::BadObject("cannot store payload"))?;
    tx.execute(
        "INSERT INTO objects(source_id,loose_path,object_type,declared_size,expanded_size,payload_end,payload_sha256,stored_payload_path,parse_status)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'parsed')",
        params![
            source_id,
            format!("loose/{}", oid_hex(&actual)),
            kind.name(),
            content.len() as i64,
            content.len() as i64,
            consumed as i64,
            payload_hash,
            payload_path
        ],
    )
    .ok();
    let object_id = tx
        .query_row(
            "SELECT id FROM objects WHERE source_id=?1",
            params![source_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| GitError::BadObject("database error"))?;
    insert_candidate(tx, &actual, object_id, "loose", true, None);
    Ok(1)
}

fn add_evidence_sql(
    tx: &rusqlite::Transaction<'_>,
    source_id: i64,
    object_id: Option<i64>,
    severity: &str,
    kind: &str,
    message: &str,
) {
    tx.execute(
        "INSERT INTO evidence(source_id,object_id,severity,kind,message)
         VALUES(?1,?2,?3,?4,?5)",
        params![source_id, object_id, severity, kind, message],
    )
    .ok();
}

fn insert_candidate(
    tx: &rusqlite::Transaction<'_>,
    oid: &[u8; 20],
    object_id: i64,
    source_kind: &str,
    valid: bool,
    invalid_reason: Option<&str>,
) {
    let sort_key = tx
        .query_row(
            "SELECT COALESCE(MIN(pack_offset),0), COALESCE(byte_size,0), MIN(id)
             FROM objects JOIN sources ON sources.id=objects.source_id WHERE objects.id=?1",
            params![object_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )
        .unwrap_or((0, 0, object_id));
    let key = sort_key.0.wrapping_add(sort_key.1.wrapping_mul(1000003)).wrapping_add(sort_key.2);
    tx.execute(
        "INSERT INTO candidates(oid,object_id,source_kind,valid,invalid_reason,sort_key)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            oid_hex(oid),
            object_id,
            source_kind,
            valid as i64,
            invalid_reason,
            key
        ],
    )
    .ok();
}

fn link_packs_and_indexes(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE indexes
         SET matched_pack_id=(
           SELECT packs.id FROM packs
           JOIN sources ON sources.id=packs.source_id
           WHERE packs.checksum=indexes.pack_checksum
           ORDER BY sources.sha256 LIMIT 1
         )",
        [],
    )?;
    tx.execute(
        "UPDATE packs
         SET expected_index_source_id=(
           SELECT indexes.source_id FROM indexes
           WHERE indexes.pack_checksum=packs.checksum
           ORDER BY indexes.pack_checksum, indexes.source_id LIMIT 1
         )",
        [],
    )?;

    let mismatches = tx
        .prepare(
            "SELECT index_entries.id, indexes.source_id, index_entries.pack_offset,
                    index_entries.crc32, objects.payload_crc32, objects.id
             FROM index_entries
             JOIN indexes ON indexes.id=index_entries.index_id
             JOIN packs ON packs.id=indexes.matched_pack_id
             LEFT JOIN objects ON objects.pack_id=packs.id
                AND objects.pack_offset=index_entries.pack_offset",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    for (_, source_id, offset, idx_crc, pack_crc, object_id) in mismatches {
        if let Some(pack_crc) = pack_crc {
            tx.execute(
                "UPDATE objects SET index_crc32=?1 WHERE id=?2",
                params![idx_crc, object_id],
            )?;
            if idx_crc != pack_crc {
                tx.execute(
                    "INSERT INTO evidence(source_id,object_id,severity,kind,message,detail_json)
                     VALUES(?1,?2,'error','crc-mismatch',
                       'index CRC32 does not match recomputed entry CRC32',
                       json_object('packOffset',?3,'indexCrc32',?4,'packCrc32',?5))",
                    params![source_id, object_id, offset, idx_crc, pack_crc],
                )?;
            }
        }
    }

    let indexed = tx
        .prepare(
            "SELECT objects.id, index_entries.oid
             FROM objects
             JOIN packs ON packs.id=objects.pack_id
             JOIN indexes ON indexes.matched_pack_id=packs.id
             JOIN index_entries ON index_entries.index_id=indexes.id
                AND index_entries.pack_offset=objects.pack_offset
             WHERE objects.object_type NOT IN ('ofs-delta','ref-delta')",
        )?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    for (object_id, oid_text) in indexed {
        if let Some(oid) = git::parse_oid(&oid_text) {
            insert_index_candidate(tx, &oid, object_id);
        }
    }
    Ok(())
}

fn insert_index_candidate(tx: &rusqlite::Transaction<'_>, oid: &[u8; 20], object_id: i64) {
    tx.execute(
        "DELETE FROM candidates WHERE object_id=?1 AND source_kind='index'",
        params![object_id],
    )
    .ok();
    let reason: Option<String> = tx
        .query_row(
            "SELECT CASE WHEN evidence.id IS NULL THEN NULL ELSE 'index or CRC evidence mismatch' END
             FROM objects LEFT JOIN evidence ON evidence.object_id=objects.id
                AND evidence.severity='error'
             WHERE objects.id=?1 LIMIT 1",
            params![object_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    insert_candidate(tx, oid, object_id, "index", reason.is_none(), reason.as_deref());
}

fn rebuild_candidate_pins_none(_tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    Ok(())
}
