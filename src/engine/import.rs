use crate::crc::crc32;
use crate::db::Db;
use crate::gitobj::{git_oid, parse_loose};
use crate::hexutil::to_hex;
use crate::idx::parse_idx;
use crate::pack::parse_pack;
use crate::types::{ErrCode, ObjStatus, ObjType};
use rusqlite::params;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::PathBuf;

#[derive(serde::Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub nodes_added: usize,
    pub message: String,
}

pub fn import_bytes(db: &Db, data_dir: &str, filename: &str, data: &[u8]) -> ImportReport {
    let kind = detect_kind(data);
    let mut conn = db.0.lock().unwrap();
    let tx = conn.transaction().unwrap();

    let digest = {
        let mut h = Sha1::new();
        h.update(data);
        to_hex(&h.finalize())
    };
    let ext = match kind {
        "pack" => "pack",
        "idx" => "idx",
        _ => "loose",
    };
    let stored_name = format!("{}.{}", &digest[..12], ext);
    let mut stored_path = PathBuf::from(data_dir);
    stored_path.push(&stored_name);
    fs::write(&stored_path, data).expect("write stored import");

    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM sources WHERE sha256=?1 AND filename=?2",
            params![digest, filename],
            |r| r.get(0),
        )
        .ok();
    let source_id = if let Some(id) = existing {
        id
    } else {
        tx.execute(
            "INSERT INTO sources(filename,kind,stored_path,sha256,size) VALUES(?1,?2,?3,?4,?5)",
            params![filename, kind, stored_path.to_string_lossy(), digest, data.len() as i64],
        )
        .unwrap();
        tx.last_insert_rowid()
    };

    let mut nodes_added = 0usize;
    let mut message = String::new();
    match kind {
        "pack" => {
            let r = import_pack(&tx, source_id, data);
            nodes_added = r.0;
            message = r.1;
        }
        "idx" => {
            let r = import_idx(&tx, source_id, data);
            message = r;
        }
        _ => {
            let r = import_loose(&tx, source_id, data);
            nodes_added = r.0;
            message = r.1;
        }
    }

    tx.commit().unwrap();
    drop(conn);

    if kind != "idx" {
        super::resolve::incremental(db);
    } else {
        super::resolve::incremental(db);
    }

    ImportReport {
        source_id,
        kind: kind.to_string(),
        filename: filename.to_string(),
        nodes_added,
        message,
    }
}

fn detect_kind(data: &[u8]) -> &'static str {
    if data.len() >= 8 && &data[0..4] == b"PACK" {
        return "pack";
    }
    if data.len() >= 8 && &data[0..4] == &[0xff, b't', b'O', b'c'] {
        return "idx";
    }
    "loose"
}

fn import_pack(
    tx: &rusqlite::Transaction,
    source_id: i64,
    data: &[u8],
) -> (usize, String) {
    let parsed = match parse_pack(data, 1u64 << 40) {
        Ok(p) => p,
        Err(e) => {
            tx.execute(
                "INSERT INTO evidence(pack_id,node_id,level,code,message)
                 VALUES(NULL,NULL,'error','bad_header',?1)",
                params![e],
            )
            .unwrap();
            return (0, format!("pack rejected: {}", e));
        }
    };

    tx.execute(
        "INSERT INTO packs(source_id,version,object_count,trailer_oid,computed_checksum)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            source_id,
            parsed.header.version,
            parsed.header.count,
            parsed.header.trailer_oid_hex,
            parsed.header.computed_checksum_hex
        ],
    )
    .unwrap();
    let pack_id = tx.last_insert_rowid();

    if parsed.header.trailer_oid_hex != parsed.header.computed_checksum_hex {
        tx.execute(
            "INSERT INTO evidence(pack_id,node_id,level,code,message,at_offset)
             VALUES(?1,NULL,'warning','oid_mismatch',
             'pack trailer checksum does not match sha1 of pack body',?2)",
            params![pack_id, data.len() as i64 - 20],
        )
        .unwrap();
    }

    for f in &parsed.failures {
        tx.execute(
            "INSERT INTO evidence(pack_id,node_id,level,code,message,at_offset)
             VALUES(?1,NULL,'error',?2,?3,?4)",
            params![pack_id, f.code.name(), f.note, f.offset as i64],
        )
        .unwrap();
    }

    let mut added = 0usize;
    for e in &parsed.entries {
        tx.execute(
            "INSERT INTO nodes(oid,kind,source_id,pack_id,pack_offset,zlib_start,entry_end,
             declared_size,base_offset,base_oid,status)
             VALUES('',?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending')",
            params![
                e.obj_type.name(),
                source_id,
                pack_id,
                e.offset as i64,
                e.zlib_start as i64,
                e.entry_end as i64,
                e.declared_size as i64,
                e.base_offset.map(|v| v as i64),
                e.base_oid,
            ],
        )
        .unwrap();
        let node_id = tx.last_insert_rowid();

        tx.execute(
            "INSERT INTO objects(oid,node_id,kind,data,stage) VALUES('',?1,?2,?3,'raw')",
            params![node_id, e.obj_type.name(), e.payload],
        )
        .unwrap();

        if let Some(code) = e.parse_error {
            tx.execute(
                "UPDATE nodes SET status='error',error_code=?1,error_note=?2 WHERE id=?3",
                params![code.name(), e.parse_note, node_id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO evidence(node_id,pack_id,level,code,message,at_offset)
                 VALUES(?1,?2,'error',?3,?4,?5)",
                params![
                    node_id,
                    pack_id,
                    code.name(),
                    e.parse_note.clone().unwrap_or_default(),
                    e.offset as i64
                ],
            )
            .unwrap();
        }
        added += 1;
    }

    pair_idxs(tx, pack_id, source_id, data, &parsed.entries);

    let mismatch: Option<(bool, String)> = tx
        .query_row(
            "SELECT matched, COALESCE(mismatch_note,'') FROM packs WHERE id=?1",
            params![pack_id],
            |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, String>(1)?)),
        )
        .ok();
    let msg = match mismatch {
        Some((true, _)) => format!("pack parsed: {} entries, idx paired", added),
        Some((false, note)) if !note.is_empty() => {
            format!("pack parsed: {} entries; {}", added, note)
        }
        _ => format!("pack parsed: {} entries, no matching idx", added),
    };
    (added, msg)
}

#[allow(clippy::too_many_arguments)]
fn pair_idxs(
    tx: &rusqlite::Transaction,
    pack_id: i64,
    pack_source_id: i64,
    pack_data: &[u8],
    entries: &[crate::types::ParsedEntry],
) {
    let mut stmt = tx
        .prepare("SELECT id, stored_path FROM sources WHERE kind='idx'")
        .unwrap();
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    drop(stmt);

    let pack_trailer = &pack_data[pack_data.len() - 20..];
    for (idx_source_id, path) in rows {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let idx = match parse_idx(&bytes) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if idx.pack_checksum_hex != to_hex(pack_trailer) {
            continue;
        }
        annotate_with_idx(tx, pack_id, idx_source_id, &idx, entries, pack_source_id);
        return;
    }
    tx.execute(
        "UPDATE packs SET matched=0,mismatch_note='no index matches pack checksum' WHERE id=?1",
        params![pack_id],
    )
    .unwrap();
}

fn annotate_with_idx(
    tx: &rusqlite::Transaction,
    pack_id: i64,
    idx_source_id: i64,
    idx: &crate::idx::IdxParse,
    entries: &[crate::types::ParsedEntry],
    _pack_source_id: i64,
) {
    let checksum_ok = idx.computed_idx_checksum_hex == idx.idx_checksum_hex;
    let mut matched_offsets = 0usize;
    let mut unmatched = Vec::new();

    for row in &idx.entries {
        let entry = entries.iter().find(|e| e.offset == row.offset);
        let node_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM nodes WHERE pack_id=?1 AND pack_offset=?2",
                params![pack_id, row.offset as i64],
                |r| r.get(0),
            )
            .ok();
        let Some(node_id) = node_id else {
            unmatched.push(row.oid_hex.clone());
            continue;
        };
        if entry.is_some() {
            matched_offsets += 1;
        }

        let computed = tx
            .query_row(
                "SELECT data FROM objects WHERE node_id=?1 AND stage='raw'",
                params![node_id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .ok();

        let mut crc_ok: Option<bool> = None;
        if let Some(_payload) = computed {
            let stored_path: String = tx
            .query_row(
                "SELECT s.stored_path FROM nodes n JOIN sources s ON s.id=n.source_id WHERE n.id=?1",
                params![node_id],
                |r| r.get(0),
            )
            .unwrap();
            let pack_bytes = fs::read(&stored_path).unwrap();
            let node = entry.unwrap();
            let region = &pack_bytes[node.offset as usize..node.entry_end];
            let actual = crc32(region);
            crc_ok = Some(actual == row.crc32);
            tx.execute(
                "UPDATE nodes SET idx_crc=?1,computed_crc=?2,crc_ok=?3 WHERE id=?4",
                params![
                    row.crc32 as i64,
                    actual as i64,
                    crc_ok.unwrap() as i64,
                    node_id
                ],
            )
            .unwrap();
            if !crc_ok.unwrap() {
                tx.execute(
                    "INSERT INTO evidence(node_id,pack_id,level,code,message,at_offset)
                     VALUES(?1,?2,'error','bad_crc',
                     'idx CRC32 does not match bytes between object header and zlib end',?3)",
                    params![node_id, pack_id, row.offset as i64],
                )
                .unwrap();
                tx.execute(
                    "UPDATE nodes SET status='error',error_code='bad_crc',
                     error_note='CRC32 mismatch against idx' WHERE id=?1 AND status!='error'",
                    params![node_id],
                )
                .unwrap();
            }
        }

        tx.execute(
            "UPDATE nodes SET oid=?1 WHERE id=?2 AND oid=''",
            params![row.oid_hex, node_id],
        )
        .unwrap();
    }

    for oid in &unmatched {
        tx.execute(
            "INSERT INTO evidence(pack_id,node_id,level,code,message)
             VALUES(?1,NULL,'warning','idx_mismatch',?2)",
            params![pack_id, format!("idx lists oid {} at offset not present in pack", oid)],
        )
        .unwrap();
    }

    let note = if matched_offsets == idx.entries.len() && checksum_ok {
        String::new()
    } else {
        format!(
            "idx matched {}/{} entries; idx checksum {}",
            matched_offsets,
            idx.entries.len(),
            if checksum_ok { "ok" } else { "BAD" }
        )
    };
    tx.execute(
        "UPDATE packs SET idx_source_id=?1,idx_pack_checksum=?2,idx_checksum_ok=?3,
         matched=?4,mismatch_note=?5 WHERE id=?6",
        params![
            idx_source_id,
            idx.pack_checksum_hex,
            checksum_ok as i64,
            (matched_offsets == idx.entries.len()) as i64,
            note,
            pack_id
        ],
    )
    .unwrap();
    tx.execute(
        "UPDATE sources SET pack_id=?1 WHERE id=?2",
        params![pack_id, idx_source_id],
    )
    .unwrap();
}

fn import_loose(
    tx: &rusqlite::Transaction,
    source_id: i64,
    data: &[u8],
) -> (usize, String) {
    match parse_loose(data) {
        Ok(obj) => {
            let oid = git_oid(obj.kind, &obj.data);
            tx.execute(
                "INSERT INTO nodes(oid,kind,final_kind,resolved_kind,source_id,loose_path,
                 declared_size,status,resolve_depth)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,'resolved',0)",
                params![
                    oid,
                    obj.kind.name(),
                    obj.kind.name(),
                    obj.kind.name(),
                    source_id,
                    "loose",
                    obj.data.len() as i64
                ],
            )
            .unwrap();
            let node_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO objects(oid,node_id,kind,data,stage) VALUES(?1,?2,?3,?4,'resolved')",
                params![oid, node_id, obj.kind.name(), obj.data],
            )
            .unwrap();
            tx.execute(
                "UPDATE sources SET linked_oid=?1 WHERE id=?2",
                params![oid, source_id],
            )
            .unwrap();
            (1, format!("loose object {} resolved", &oid[..12]))
        }
        Err(e) => {
            tx.execute(
                "INSERT INTO nodes(oid,kind,source_id,loose_path,status,error_code,error_note)
                 VALUES('','unknown',?1,'loose','error','corrupt_zlib',?2)",
                params![source_id, format!("{:?}", e)],
            )
            .unwrap();
            let node_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO evidence(node_id,level,code,message)
                 VALUES(?1,'error','corrupt_zlib',?2)",
                params![node_id, format!("{:?}", e)],
            )
            .unwrap();
            (0, "loose object rejected".into())
        }
    }
}

fn import_idx(
    tx: &rusqlite::Transaction,
    source_id: i64,
    data: &[u8],
) -> String {
    let idx = match parse_idx(data) {
        Ok(i) => i,
        Err(e) => {
            tx.execute(
                "INSERT INTO evidence(level,code,message) VALUES('error','bad_header',?1)",
                params![format!("idx rejected: {}", e)],
            )
            .unwrap();
            return format!("idx rejected: {}", e);
        }
    };
    if idx.computed_idx_checksum_hex != idx.idx_checksum_hex {
        tx.execute(
            "INSERT INTO evidence(level,code,message) VALUES('warning','idx_mismatch',
             'idx trailer sha1 does not match checksum of index body')",
            [],
        )
        .unwrap();
    }

    let pack_row: Option<(i64, i64, String)> = tx
        .query_row(
            "SELECT p.id,p.source_id,s.stored_path FROM packs p
             JOIN sources s ON s.id=p.source_id
             WHERE p.trailer_oid=?1",
            params![idx.pack_checksum_hex],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();

    let Some((pack_id, pack_source_id, pack_path)) = pack_row else {
        tx.execute(
            "INSERT INTO evidence(level,code,message) VALUES('info','idx_mismatch',
             'idx imported but no pack with matching checksum is present yet')",
            [],
        )
        .unwrap();
        return "idx stored; waiting for matching pack".into();
    };

    let pack_bytes = fs::read(&pack_path).unwrap();
    let parsed = parse_pack(&pack_bytes, 1u64 << 40).unwrap();
    annotate_with_idx(tx, pack_id, source_id, &idx, &parsed.entries, pack_source_id);
    format!("idx paired with pack {}", pack_id)
}
