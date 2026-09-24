//! File ingestion: pack / idx / loose, with pairing and CRC evidence.

use crate::gitobj::{hex, object_id, ptype};
use crate::idx::parse_idx;
use crate::loose::parse_loose;
use crate::pack::parse_pack;
use crate::store::Store;
use crc32fast::Hasher as CrcHasher;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

pub fn detect_kind(name: &str, data: &[u8]) -> FileKind {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pack") || data.starts_with(b"PACK") {
        FileKind::Pack
    } else if lower.ends_with(".idx") || (data.len() >= 8 && &data[..4] == &[0xff, 0x74, 0x4f, 0x63])
    {
        FileKind::Idx
    } else if data.len() >= 2 && (data[0] & 0x0f) == 0x08 {
        // zlib stream with deflate method byte
        FileKind::Loose
    } else {
        FileKind::Unknown
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn insert_source(
    store: &mut Store,
    kind: &str,
    name: &str,
    stored: &Path,
    data: &[u8],
    status: &str,
    err: Option<&str>,
) -> i64 {
    let digest = sha256_hex(data);
    store
        .conn
        .execute(
            "INSERT INTO sources(kind, original_name, stored_path, bytes, sha256, imported_at,
                                parse_status, parse_error)
             VALUES (?1,?2,?3,?4,?5,strftime('%s','now'),?6,?7)",
            params![
                kind,
                name,
                stored.to_string_lossy(),
                data.len() as i64,
                digest,
                status,
                err
            ],
        )
        .unwrap();
    store.conn.last_insert_rowid()
}

pub fn import_file(store: &mut Store, name: &str, data: &[u8]) -> Result<(FileKind, i64), String> {
    let kind = detect_kind(name, data);
    let ext = match kind {
        FileKind::Pack => "pack",
        FileKind::Idx => "idx",
        FileKind::Loose => "loose",
        FileKind::Unknown => return Err("unrecognized file format".into()),
    };
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let fname = format!("{:016}_{}", ts, safe);
    let stored = store.data_dir.join("uploads").join(fname);
    std::fs::write(&stored, data).map_err(|e| e.to_string())?;

    match kind {
        FileKind::Pack => {
            let sid = import_pack(store, name, &stored, data);
            Ok((kind, sid))
        }
        FileKind::Idx => {
            let sid = import_idx(store, name, &stored, data);
            Ok((kind, sid))
        }
        FileKind::Loose => {
            let sid = import_loose(store, name, &stored, data);
            Ok((kind, sid))
        }
        FileKind::Unknown => unreachable!(),
    }
}

fn import_pack(store: &mut Store, name: &str, stored: &Path, data: &[u8]) -> i64 {
    match parse_pack(data, MAX_OBJECT_BYTES) {
        Err(fatal) => {
            let sid = insert_source(
                store, "pack", name, stored, data, "fatal", Some(&fatal.0),
            );
            store.add_evidence(
                &format!("source:{}", sid),
                "pack_fatal", "error", &fatal.0, None,
            );
            sid
        }
        Ok(pack) => {
            let sid = insert_source(store, "pack", name, stored, data, "ok", None);
            store
                .conn
                .execute(
                    "INSERT INTO packs(source_id, version, num_objects, body_len,
                                      checksum_stored, checksum_computed, checksum_ok)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        sid,
                        pack.version,
                        pack.num_objects,
                        pack.file_len - 20,
                        hex(&pack.stored_checksum),
                        hex(&pack.computed_checksum),
                        pack.checksum_ok as i64,
                    ],
                )
                .unwrap();
            let pack_id = store.conn.last_insert_rowid();

            if !pack.checksum_ok {
                store.add_evidence(
                    &format!("pack:{}", pack_id),
                    "pack_checksum_mismatch",
                    "error",
                    "pack trailer SHA-1 does not match the body checksum",
                    Some(&format!(
                        "stored={} computed={}",
                        hex(&pack.stored_checksum),
                        hex(&pack.computed_checksum)
                    )),
                );
            }
            for w in &pack.warnings {
                let sev = if w.code == "ofs_out_of_bounds" { "error" } else { "warning" };
                store.add_evidence(
                    &format!("pack:{}", pack_id),
                    &w.code,
                    sev,
                    &w.message,
                    w.offset.map(|o| format!("offset={}", o)).as_deref(),
                );
            }

            for e in &pack.entries {
                let (payload_path, inflate_err) = match (&e.payload, &e.inflate_error) {
                    (Some(p), None) => {
                        let pn = format!("pack{}_off{}.zout", pack_id, e.offset);
                        store.write_payload(&pn, p).ok();
                        (Some(pn), None)
                    }
                    _ => (None, e.inflate_error.clone()),
                };
                store
                    .conn
                    .execute(
                        "INSERT INTO entries(pack_id, offset, obj_type, declared_size,
                                             base_offset, base_oid, z_start, z_consumed,
                                             payload_path, inflate_error)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                        params![
                            pack_id,
                            e.offset as i64,
                            e.obj_type,
                            e.declared_size as i64,
                            e.base_offset.map(|v| v as i64),
                            e.base_oid.map(|o| hex(&o[..])),
                            e.z_start as i64,
                            e.z_consumed.map(|v| v as i64),
                            payload_path,
                            inflate_err,
                        ],
                    )
                    .unwrap();
                let entry_id = store.conn.last_insert_rowid();
                if let Some(msg) = &e.inflate_error {
                    store.add_evidence(
                        &format!("entry:{}", entry_id),
                        "inflate_failed",
                        "error",
                        msg,
                        Some(&format!("pack={} offset={}", pack_id, e.offset)),
                    );
                }
                if e.base_offset.is_none()
                    && e.obj_type == ptype::OFS_DELTA
                    && e.inflate_error.is_none()
                {
                    store.add_evidence(
                        &format!("entry:{}", entry_id),
                        "ofs_out_of_bounds",
                        "error",
                        "ofs-delta distance points before start of pack",
                        Some(&format!("offset={}", e.offset)),
                    );
                }
            }
            pair_all_idx(store, pack_id, data);
            sid
        }
    }
}

fn import_idx(store: &mut Store, name: &str, stored: &Path, data: &[u8]) -> i64 {
    match parse_idx(data) {
        Err(fatal) => {
            let sid = insert_source(store, "idx", name, stored, data, "fatal", Some(&fatal.0));
            store.add_evidence(
                &format!("source:{}", sid),
                "idx_fatal", "error", &fatal.0, None,
            );
            sid
        }
        Ok(idx) => {
            let sid = insert_source(store, "idx", name, stored, data, "ok", None);
            store
                .conn
                .execute(
                    "INSERT INTO idx_files(source_id, version, n_entries, pack_checksum,
                                           idx_checksum_ok, paired_pack_id)
                     VALUES (?1,?2,?3,?4,?5,NULL)",
                    params![
                        sid,
                        idx.version,
                        idx.entries.len() as i64,
                        hex(&idx.pack_checksum),
                        idx.idx_checksum_ok as i64
                    ],
                )
                .unwrap();
            let idx_id = store.conn.last_insert_rowid();
            for w in &idx.warnings {
                store.add_evidence(
                    &format!("idx:{}", idx_id),
                    &w.code, "warning", &w.message, None,
                );
            }
            for ie in &idx.entries {
                store
                    .conn
                    .execute(
                        "INSERT INTO idx_entries(idx_id, oid, pack_offset, crc)
                         VALUES (?1,?2,?3,?4)",
                        params![
                            idx_id,
                            hex(&ie.oid),
                            ie.pack_offset as i64,
                            ie.crc.map(|v| v as i64)
                        ],
                    )
                    .unwrap();
            }
            let fanout_json = serde_json::to_string(&idx.fanout[..]).unwrap();
            store.add_evidence(
                &format!("idx:{}", idx_id),
                "fanout",
                "warning",
                &format!("parsed fanout table with {} objects", idx.entries.len()),
                Some(&fanout_json),
            );
            try_pair_idx(store, idx_id, &idx.pack_checksum);
            sid
        }
    }
}

fn try_pair_idx(store: &mut Store, idx_id: i64, pack_checksum: &[u8]) {
    let want = hex(pack_checksum);
    let found: Option<(i64, String)> = store
        .conn
        .prepare(
            "SELECT p.id, s.stored_path FROM packs p JOIN sources s ON s.id = p.source_id
             WHERE p.checksum_stored = ?1",
        )
        .unwrap()
        .query_row(params![want], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })
        .ok();
    if let Some((pack_id, path)) = found {
        pair_idx_with_pack(store, idx_id, pack_id, &path);
    } else {
        store.add_evidence(
            &format!("idx:{}", idx_id),
            "idx_unpaired",
            "warning",
            "no imported pack matches this index's pack checksum",
            Some(&format!("wanted pack checksum {}", want)),
        );
    }
}

fn pair_all_idx(store: &mut Store, pack_id: i64, pack_data: &[u8]) {
    let checksum: String = store
        .conn
        .query_row(
            "SELECT checksum_stored FROM packs WHERE id=?1",
            params![pack_id],
            |r| r.get(0),
        )
        .unwrap();
    let ids: Vec<i64> = {
        let mut stmt = store
            .conn
            .prepare("SELECT id FROM idx_files WHERE pack_checksum=?1")
            .unwrap();
        stmt.query_map(params![checksum], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };
    for idx_id in ids {
        let path: String = store
            .conn
            .query_row(
                "SELECT s.stored_path FROM idx_files i JOIN sources s ON s.id=i.source_id
                 WHERE i.id=?1",
                params![idx_id],
                |r| r.get(0),
            )
            .unwrap();
        pair_idx_with_pack(store, idx_id, pack_id, &path, );
    }
    let _ = pack_data;
}

fn pair_idx_with_pack(store: &mut Store, idx_id: i64, pack_id: i64, pack_path: &str) {
    let data = std::fs::read(pack_path).unwrap_or_default();
    store
        .conn
        .execute(
            "UPDATE idx_files SET paired_pack_id=?1 WHERE id=?2",
            params![pack_id, idx_id],
        )
        .unwrap();
    store.add_evidence(
        &format!("idx:{}", idx_id),
        "idx_paired",
        "warning",
        "index matched a pack by pack checksum",
        Some(&format!("idx={} pack={}", idx_id, pack_id)),
    );

    // Verify each object's CRC32 over its exact packed byte range.
    let rows: Vec<(i64, i64, Option<i64>)> = {
        let mut stmt = store
            .conn
            .prepare("SELECT id, pack_offset, crc FROM idx_entries WHERE idx_id=?1")
            .unwrap();
        stmt.query_map(params![idx_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };
    for (ie_id, offset, crc) in rows {
        // Determine byte range [offset, next entry offset) from entries table.
        let next_off: Option<i64> = store
            .conn
            .query_row(
                "SELECT MIN(offset) FROM entries WHERE pack_id=?1 AND offset > ?2",
                params![pack_id, offset],
                |r| r.get(0),
            )
            .unwrap_or(None);
        let end = match next_off {
            Some(n) => n as usize,
            None => data.len() - 20,
        };
        let off = offset as usize;
        let exists: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE pack_id=?1 AND offset=?2",
                params![pack_id, offset],
                |r| r.get(0),
            )
            .unwrap();
        if exists == 0 {
            store.add_evidence(
                &format!("idx:{}", idx_id),
                "idx_offset_unknown",
                "error",
                "index references an offset not present in the pack",
                Some(&format!("offset={}", off)),
            );
            continue;
        }
        if off >= end || end > data.len() {
            continue;
        }
        let mut hasher = CrcHasher::new();
        hasher.update(&data[off..end]);
        let got = hasher.finalize();
        if let Some(want) = crc {
            if got as i64 != want {
                store.add_evidence(
                    &format!("entry_at:{}:{}", pack_id, off),
                    "crc_mismatch",
                    "error",
                    "index CRC32 does not match packed byte range",
                    Some(&format!(
                        "offset={} expected={:08x} actual={:08x}",
                        off, want as u32, got
                    )),
                );
                store
                    .conn
                    .execute(
                        "UPDATE entries SET inflate_error = COALESCE(inflate_error, ?3)
                         WHERE pack_id=?1 AND offset=?2",
                        params![pack_id, offset, format!("crc mismatch: {:08x}!={:08x}", want as u32, got)],
                    )
                    .unwrap();
            }
        }
        let _ = ie_id;
    }
}

fn import_loose(store: &mut Store, name: &str, stored: &Path, data: &[u8]) -> i64 {
    // A loose import may name the file with an oid (basename).
    let stem = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let claimed = crate::gitobj::from_hex(&stem).filter(|v| v.len() == 20).map(|v| {
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        a
    });

    let parsed = parse_loose(data, claimed, MAX_OBJECT_BYTES);
    let status = if parsed.error.is_some() { "fatal" } else { "ok" };
    let sid = insert_source(
        store,
        "loose",
        name,
        stored,
        data,
        status,
        parsed.error.as_deref(),
    );
    let oid_hex = hex(&parsed.computed_oid);
    let content_name = format!("loose_{}.raw", oid_hex);
    store.write_payload(&content_name, &parsed.content).ok();
    store
        .conn
        .execute(
            "INSERT INTO loose_objects(source_id, claimed_oid, computed_oid, obj_type,
                                       size, content_path, oid_matches, parse_error)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                sid,
                claimed.map(|c| hex(&c)),
                oid_hex,
                parsed.obj_type,
                parsed.content.len() as i64,
                content_name,
                parsed.oid_matches as i64,
                parsed.error
            ],
        )
        .unwrap();
    let loose_id = store.conn.last_insert_rowid();
    if let Some(err) = &parsed.error {
        store.add_evidence(
            &format!("loose:{}", loose_id),
            "loose_corrupt", "error", err, None,
        );
    }
    if !parsed.oid_matches {
        store.add_evidence(
            &format!("loose:{}", loose_id),
            "oid_mismatch",
            "error",
            "file name oid does not match recomputed object id",
            Some(&format!(
                "claimed={} computed={}",
                claimed.map(|c| hex(&c)).unwrap_or_default(),
                oid_hex
            )),
        );
    }
    sid
}

#[allow(dead_code)]
fn oid_of(type_code: u8, content: &[u8]) -> String {
    hex(&object_id(type_code, content))
}
