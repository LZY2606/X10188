use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

use crate::crc::crc32;
use crate::delta::{read_size_encoding, ObjectType};
use crate::error::{Error, Result};
use crate::hash::sha256_hex;
use crate::idx::parse_index;
use crate::loose::parse_loose;
use crate::pack::parse_pack;
use crate::store::{next_import_seq, Store};

fn infer_kind(filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") || lower.ends_with(".packx") {
        "pack"
    } else if lower.ends_with(".idx") || lower.ends_with(".idxx") {
        "index"
    } else {
        "loose"
    }
}

fn safe_filename(filename: &str) -> String {
    filename
        .replace(['/', '\\'], "_")
        .replace("..", "_")
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

pub fn import_bytes(store: &Store, original_name: &str, data: Vec<u8>) -> Result<String> {
    let mut conn = store.conn.lock().expect("database lock");
    let tx = conn.transaction()?;
    let source_id = import_transaction(&tx, store, original_name, data)?;
    tx.commit()?;
    Ok(source_id)
}

fn import_transaction(
    conn: &Connection,
    store: &Store,
    original_name: &str,
    data: Vec<u8>,
) -> Result<String> {
    let filename = safe_filename(original_name);
    let digest = sha256_hex(&data);
    let size = data.len() as i64;
    let kind = infer_kind(&filename);
    let source_id = format!("{digest}:{filename}");
    if let Ok(existing) = conn.query_row(
        "SELECT id FROM sources WHERE id = ?1",
        params![source_id],
        |r| r.get::<_, String>(0),
    ) {
        mark_all_from_pack_or_index_dirty(conn, store, &existing)?;
        return Ok(existing);
    }
    let disk_name = format!("{digest}-{filename}");
    let disk_path = store.config.files_dir.join(disk_name);
    fs::write(&disk_path, &data)?;
    let relative = format!("files/{disk_name}");
    let seq = next_import_seq(conn)?;
    conn.execute(
        "INSERT INTO sources (id, filename, kind, size, content_sha256, disk_path, import_seq, status, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'imported', NULL)",
        params![source_id, filename, kind, size, digest, relative, seq],
    )?;
    match kind {
        "pack" => import_pack(conn, store, &source_id, &data)?,
        "index" => import_index(conn, store, &source_id, &data)?,
        _ => import_loose(conn, &source_id, &filename, &data)?,
    }
    relink_indexes(conn, store)?;
    mark_new_dependency_closure(conn)?;
    Ok(source_id)
}

fn import_pack(conn: &Connection, _store: &Store, source_id: &str, data: &[u8]) -> Result<()> {
    let parsed = match parse_pack(data, Some(256 * 1024 * 1024)) {
        Ok(p) => p,
        Err(error) => {
            conn.execute(
                "UPDATE sources SET status='parse_error', error=?2 WHERE id=?1",
                params![source_id, error.to_string()],
            )?;
            return Ok(());
        }
    };
    let pack_status = if parsed.checksum_ok && parsed.fatal_error.is_none() {
        "ok"
    } else {
        "invalid"
    };
    let pack_error = parsed
        .fatal_error
        .clone()
        .or_else(|| (!parsed.checksum_ok).then(|| "pack checksum mismatch".to_string()));
    conn.execute(
        "UPDATE sources SET status=?2, error=?3 WHERE id=?1",
        params![source_id, pack_status, pack_error],
    )?;
    conn.execute(
        "INSERT INTO packs (source_id, version, object_count, data_end, checksum, checksum_ok, fatal_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![source_id, parsed.version as i64, parsed.count as i64, parsed.data_end as i64,
                parsed.checksum_expected, parsed.checksum_ok as i64, parsed.fatal_error],
    )?;
    for object in &parsed.objects {
        let cid = format!("{source_id}:pack:{}", object.offset);
        conn.execute(
            "INSERT INTO candidates
             (id, source_id, kind, offset, header_end, data_end, compressed_len, object_type, type_code,
              declared_size, actual_size, expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty)
             VALUES (?1,?2,'pack',?3,?4,?5,?6,?7,?8,?9,?10,NULL,?11,?12,?13,?14,1)",
            params![
                cid, source_id, object.offset as i64, object.header_end as i64,
                object.data_end as i64, object.compressed_len as i64,
                object.object_type.git_name(), object.type_code as i64,
                object.declared_size as i64, object.actual_size.map(|v| v as i64),
                object.actual_oid, object.base_offset.map(|v| v as i64), object.base_oid, object.error
            ],
        )?;
        if let Some(base_offset) = object.base_offset {
            conn.execute(
                "INSERT OR IGNORE INTO candidate_edges (candidate_id, edge_kind, base_offset, base_oid)
                 VALUES (?1, 'ofs', ?2, NULL)",
                params![cid, base_offset as i64],
            )?;
        }
        if let Some(base_oid) = &object.base_oid {
            conn.execute(
                "INSERT OR IGNORE INTO candidate_edges (candidate_id, edge_kind, base_offset, base_oid)
                 VALUES (?1, 'ref', NULL, ?2)",
                params![cid, base_oid],
            )?;
        }
    }
    Ok(())
}

fn import_index(conn: &Connection, _store: &Store, source_id: &str, data: &[u8]) -> Result<()> {
    let parsed = match parse_index(data) {
        Ok(p) => p,
        Err(error) => {
            conn.execute(
                "UPDATE sources SET status='parse_error', error=?2 WHERE id=?1",
                params![source_id, error.to_string()],
            )?;
            return Ok(());
        }
    };
    let status = if parsed.errors.is_empty() { "ok" } else { "invalid" };
    conn.execute(
        "INSERT INTO parsed_indexes (source_id, pack_checksum, matched_pack_source, checksum_ok, errors)
         VALUES (?1, ?2, NULL, ?3, ?4)",
        params![source_id, parsed.pack_checksum, parsed.checksum_ok as i64, parsed.errors.join("\n")],
    )?;
    for entry in &parsed.entries {
        conn.execute(
            "INSERT INTO index_entries (index_source_id, oid, offset, expected_crc, crc_ok)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![source_id, entry.oid, entry.offset as i64, entry.expected_crc.map(|v| v as i64)],
        )?;
    }
    conn.execute("UPDATE sources SET status=?2 WHERE id=?1", params![source_id, status])?;
    Ok(())
}

fn import_loose(conn: &Connection, source_id: &str, filename: &str, data: &[u8]) -> Result<()> {
    let cid = format!("{source_id}:loose:0");
    let expected = expected_oid_from_filename(filename);
    match parse_loose(data) {
        Ok(parsed) => {
            let error = match &expected {
                Some(expected) if expected != &parsed.actual_oid => Some(format!(
                    "loose path expected {expected}, content hashes to {}",
                    parsed.actual_oid
                )),
                _ => None,
            };
            conn.execute(
                "INSERT INTO candidates
                 (id, source_id, kind, offset, header_end, data_end, compressed_len, object_type, type_code,
                  declared_size, actual_size, expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty)
                 VALUES (?1,?2,'loose',0,NULL,NULL,NULL,?3,NULL,?4,?4,?5,?6,NULL,NULL,?7,1)",
                params![cid, source_id, parsed.object_type.git_name(), parsed.actual_body_size as i64,
                        expected, parsed.actual_oid, error],
            )?;
            conn.execute("UPDATE sources SET status='ok', error=NULL WHERE id=?1", params![source_id])?;
        }
        Err(error) => {
            conn.execute(
                "INSERT INTO candidates
                 (id, source_id, kind, offset, header_end, data_end, compressed_len, object_type, type_code,
                  declared_size, actual_size, expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty)
                 VALUES (?1,?2,'loose',0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?3,NULL,NULL,NULL,?4,1)",
                params![cid, source_id, expected, error.to_string()],
            )?;
            conn.execute("UPDATE sources SET status='parse_error', error=?2 WHERE id=?1",
                         params![source_id, error.to_string()])?;
        }
    }
    Ok(())
}

fn expected_oid_from_filename(filename: &str) -> Option<String> {
    let path = Path::new(filename);
    let stem = path.file_stem()?.to_str()?;
    let parent = path.parent().and_then(|p| p.file_name()).and_then(|v| v.to_str());
    if let Some(prefix) = parent {
        let candidate = format!("{prefix}{stem}");
        if candidate.len() == 40 && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(candidate);
        }
    }
    if stem.len() == 40 && stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(stem.to_string())
    } else {
        None
    }
}

fn relink_indexes(conn: &Connection, store: &Store) -> Result<()> {
    let mut stmt = conn.prepare("SELECT source_id, pack_checksum FROM parsed_indexes")?;
    let indexes: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    drop(stmt);
    for (index_source, pack_checksum) in indexes {
        let matched: Option<String> = conn.query_row(
            "SELECT source_id FROM packs WHERE checksum=?1 ORDER BY source_id LIMIT 1",
            params![pack_checksum],
            |r| r.get(0),
        ).optional()?;
        conn.execute(
            "UPDATE parsed_indexes SET matched_pack_source=?2 WHERE source_id=?1",
            params![index_source, matched],
        )?;
        let mut entries = conn.prepare(
            "SELECT id, offset, expected_crc FROM index_entries WHERE index_source_id=?1",
        )?;
        let rows: Vec<(i64, i64, Option<i64>)> = entries.query_map(params![index_source], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?.collect::<std::result::Result<_, _>>()?;
        drop(entries);
        for (entry_id, offset, expected_crc) in rows {
            let crc_ok = match (matched.as_ref(), expected_crc) {
                (Some(pack_source), Some(expected)) => {
                    let path: String = conn.query_row(
                        "SELECT disk_path FROM sources WHERE id=?1",
                        params![pack_source],
                        |r| r.get(0),
                    )?;
                    let data = fs::read(store.config.data_dir.join(&path))
                        .map_err(|e| Error::Io(e.to_string()))?;
                    parse_pack(&data, Some(256 * 1024 * 1024))?.objects
                        .iter()
                        .find(|o| o.offset == offset as u64)
                        .map(|o| (crc32(&data[o.header_end as usize..o.data_end as usize]) as i64) == expected)
                }
                _ => None,
            };
            conn.execute("UPDATE index_entries SET crc_ok=?2 WHERE id=?1",
                         params![entry_id, crc_ok.map(|v| v as i64)])?;
        }
    }
    assign_expected_oids_from_indexes(conn)?;
    Ok(())
}

trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>>;
}
impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn assign_expected_oids_from_indexes(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE candidates
         SET expected_oid = (
           SELECT ie.oid FROM parsed_indexes pi
           JOIN index_entries ie ON ie.index_source_id = pi.source_id
           WHERE pi.matched_pack_source = candidates.source_id AND ie.offset = candidates.offset
           LIMIT 1
         )
         WHERE kind='pack' AND expected_oid IS NULL
           AND EXISTS (
           SELECT 1 FROM parsed_indexes pi JOIN index_entries ie ON ie.index_source_id = pi.source_id
           WHERE pi.matched_pack_source = candidates.source_id AND ie.offset = candidates.offset)",
        [],
    )?;
    Ok(())
}

fn mark_all_from_pack_or_index_dirty(conn: &Connection, _store: &Store, source_id: &str) -> Result<()> {
    conn.execute("UPDATE candidates SET dirty=1 WHERE source_id=?1", params![source_id])?;
    mark_new_dependency_closure(conn)?;
    Ok(())
}

fn mark_new_dependency_closure(conn: &Connection) -> Result<()> {
    loop {
        let changed = conn.execute(
            "UPDATE candidates SET dirty=1 WHERE dirty=0 AND (
               EXISTS (
                 SELECT 1 FROM candidate_edges e JOIN candidates base ON base.kind='loose'
                 WHERE e.candidate_id = candidates.id AND e.base_oid = base.actual_oid AND base.dirty=1
               )
               OR EXISTS (
                 SELECT 1 FROM candidate_edges e
                 JOIN candidates base ON base.kind='pack' AND base.source_id = candidates.source_id
                 WHERE e.candidate_id = candidates.id AND e.base_offset = base.offset AND base.dirty=1
               )
               OR EXISTS (
                 SELECT 1 FROM candidate_edges e JOIN candidates base ON base.kind='pack'
                 WHERE e.candidate_id = candidates.id AND e.base_oid IS NOT NULL
                   AND e.base_oid IN (base.expected_oid, base.actual_oid) AND base.dirty=1
               )
            )",
            [],
        )?;
        if changed == 0 {
            break;
        }
    }
    Ok(())
}
