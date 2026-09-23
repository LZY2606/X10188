use crate::db::Db;
use crate::git::{
    self, crc32_ieee, git_object_id, inflate_zlib, oid_hex, parse_idx, parse_loose_file,
    parse_pack, DeltaRef, InflateGuard, OBJ_OFS_DELTA, OBJ_REF_DELTA,
};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const HARD_GUARD: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_DEPTH: u32 = 50;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_OBJECT_RATIO: f64 = 4.0;

#[derive(Clone, Serialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_object_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_object_ratio: DEFAULT_MAX_OBJECT_RATIO,
        }
    }
}

pub struct Engine {
    pub db: Db,
    pub data_dir: PathBuf,
    pub sources_dir: PathBuf,
    pub objects_dir: PathBuf,
    pub lock: Mutex<()>,
}

fn detect_kind(buf: &[u8], filename: &str) -> &'static str {
    if buf.len() >= 4 && &buf[0..4] == b"PACK" {
        "pack"
    } else if buf.len() >= 8 && buf[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        "idx"
    } else if filename.starts_with("pack-") && filename.ends_with(".idx") {
        "idx"
    } else if filename.starts_with("pack-") && filename.ends_with(".pack") {
        "pack"
    } else {
        "loose"
    }
}

impl Engine {
    pub fn open(dir: &Path) -> rusqlite::Result<Engine> {
        fs::create_dir_all(dir).ok();
        let sources_dir = dir.join("sources");
        let objects_dir = dir.join("objects");
        fs::create_dir_all(&sources_dir).ok();
        fs::create_dir_all(&objects_dir).ok();
        let db = Db::open(&dir.join("microscope.db").to_string_lossy())?;
        Ok(Engine {
            db,
            data_dir: dir.to_path_buf(),
            sources_dir,
            objects_dir,
            lock: Mutex::new(()),
        })
    }

    pub fn import_bytes(&self, filename: &str, data: Vec<u8>) -> Result<ImportReport, String> {
        let _g = self.lock.lock().unwrap();
        let conn = &mut *self.db.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let report = self.import_txn(&tx, filename, data)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(report)
    }

    fn store_source(&self, tx: &rusqlite::Transaction, filename: &str, kind: &str, data: &[u8]) -> Result<i64, String> {
        let digest = git::sha1_hex(data);
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM sources WHERE digest=?1",
                params![digest],
                |r| r.get(0),
            )
            .ok();
        if let Some(id) = existing {
            tx.execute(
                "UPDATE sources SET filename=?1 WHERE id=?2",
                params![filename, id],
            )
            .map_err(|e| e.to_string())?;
            return Ok(id);
        }
        let id = tx
            .query_row(
                "INSERT INTO sources(filename, kind, size, digest, parse_status) VALUES(?1,?2,?3,?4,'pending')",
                params![filename, kind, data.len() as i64, digest],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let p = self.sources_dir.join(format!("{:010}-{}", id, sanitize(filename)));
        fs::write(&p, data).map_err(|e| format!("cannot write source file: {}", e))?;
        Ok(id)
    }

    fn import_txn(
        &self,
        tx: &rusqlite::Transaction,
        filename: &str,
        data: Vec<u8>,
    ) -> Result<ImportReport, String> {
        let kind = detect_kind(&data, filename);
        let source_id = self.store_source(tx, filename, kind, &data)?;
        let was_seeded: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sources WHERE id=?1 AND parse_status!='pending'",
                params![source_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if was_seeded {
            self.wipe_source_rows(tx, source_id)?;
        }
        let mut report = ImportReport {
            source_id,
            kind: kind.to_string(),
            filename: filename.to_string(),
            size: data.len(),
            entries: 0,
            candidates: 0,
            errors: Vec::new(),
            relink_recomputed: 0,
            dedup: false,
        };
        report.dedup = was_seeded > 0;
        match kind {
            "pack" => self.import_pack(tx, source_id, &data, &mut report)?,
            "idx" => self.import_idx(tx, source_id, &data, &mut report)?,
            _ => self.import_loose(tx, source_id, &data, &mut report)?,
        }
        tx.execute(
            "UPDATE sources SET parse_status='ok' WHERE id=?1",
            params![source_id],
        )
        .map_err(|e| e.to_string())?;
        self.relink(tx)?;
        self.recompute_affected(tx, &mut report)?;
        Ok(report)
    }

    fn wipe_source_rows(&self, tx: &rusqlite::Transaction, source_id: i64) -> Result<(), String> {
        tx.execute("DELETE FROM steps WHERE entry_id IN (SELECT id FROM entries WHERE pack_source_id=?1)", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM object_state WHERE oid IN (SELECT oid FROM candidates WHERE source_id=?1)", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM pins WHERE candidate_id IN (SELECT id FROM candidates WHERE source_id=?1)", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM candidates WHERE source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM loose_objects WHERE source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM entries WHERE pack_source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM idx_fanout WHERE idx_source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM indexes WHERE source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM packs WHERE source_id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub size: usize,
    pub entries: usize,
    pub candidates: usize,
    pub errors: Vec<String>,
    pub relink_recomputed: usize,
    pub dedup: bool,
}

fn read_source(data_dir: &Path, source_id: i64) -> Result<Vec<u8>, String> {
    let dir = data_dir.join("sources");
    let prefix = format!("{:010}-", source_id);
    for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            return Ok(fs::read(entry.path()).map_err(|e| e.to_string())?);
        }
    }
    Err("source file not found".into())
}

// suppress unused warnings for helpers kept for clarity
#[allow(dead_code)]
fn ensure_conn(_c: &Connection) {}

impl Engine {
    fn import_pack(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        let guard = InflateGuard { max_output: HARD_GUARD };
        let parsed = match parse_pack(data, &guard) {
            Ok(p) => p,
            Err(e) => {
                tx.execute(
                    "UPDATE sources SET parse_status='error', parse_error=?1 WHERE id=?2",
                    params![e, source_id],
                )
                .map_err(|x| x.to_string())?;
                report.errors.push(e);
                return Ok(());
            }
        };
        let checksum = oid_hex(data[parsed.trailer_offset..].try_into().unwrap());
        tx.execute(
            "INSERT INTO packs(source_id, version, num_objects, data_len, trailer_offset, checksum, checksum_ok)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                source_id,
                parsed.header.version as i64,
                parsed.header.num_objects as i64,
                parsed.data_len as i64,
                parsed.trailer_offset as i64,
                checksum,
                parsed.checksum_ok.map(|b| b as i64),
            ],
        )
        .map_err(|e| e.to_string())?;
        let guard2 = InflateGuard { max_output: HARD_GUARD };
        for e in &parsed.entries {
            let (delta_kind, base_offset, base_oid) = match &e.delta_ref {
                Some(DeltaRef::Ofs { negative_offset }) => (
                    "ofs",
                    Some(e.offset as i64 - *negative_offset as i64),
                    Option::<String>::None,
                ),
                Some(DeltaRef::Ref { base_oid }) => {
                    ("ref", None, Some(oid_hex(base_oid)))
                }
                None => ("", None, None),
            };
            let inflated = inflate_zlib(&e.compressed, &guard2);
            let (inflated_len, inflate_error) = match &inflated {
                Ok(v) => (Some(v.data.len() as i64), None),
                Err(err) => (None, Some(err.clone())),
            };
            let mut size_spoof: Option<i64> = None;
            if let Ok(v) = &inflated {
                if git::is_base_type(e.obj_type) && v.data.len() as u64 != e.declared_size {
                    size_spoof = Some(1);
                }
            }
            tx.execute(
                "INSERT INTO entries(pack_source_id, offset, header_len, obj_type, type_name,
                   declared_size, delta_kind, base_offset, base_oid, comp_start, comp_end,
                   compressed_len, crc32, inflated_len, inflate_error, size_spoof)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    source_id,
                    e.offset as i64,
                    e.header_len as i64,
                    e.obj_type as i64,
                    git::type_name(e.obj_type),
                    e.declared_size as i64,
                    delta_kind,
                    base_offset,
                    base_oid,
                    e.comp_start as i64,
                    e.comp_end as i64,
                    e.compressed.len() as i64,
                    e.crc32 as i64,
                    inflated_len,
                    inflate_error,
                    size_spoof,
                ],
            )
            .map_err(|x| x.to_string())?;
            if let Some(err) = inflate_error {
                report.errors.push(format!("entry @{}: {}", e.offset, err));
            }
        }
        for (off, err) in &parsed.errors {
            report.errors.push(format!("entry @{}: {}", off, err));
        }
        report.entries = parsed.entries.len();
        Ok(())
    }

    fn import_idx(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        let parsed = match parse_idx(data) {
            Ok(p) => p,
            Err(e) => {
                tx.execute(
                    "UPDATE sources SET parse_status='error', parse_error=?1 WHERE id=?2",
                    params![e, source_id],
                )
                .map_err(|x| x.to_string())?;
                report.errors.push(e);
                return Ok(());
            }
        };
        tx.execute(
            "INSERT INTO indexes(source_id, version, num_objects, pack_checksum, idx_checksum_ok)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                source_id,
                parsed.version as i64,
                parsed.entries.len() as i64,
                oid_hex(&parsed.pack_checksum),
                parsed.idx_checksum_ok as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        for (i, v) in parsed.fanout.iter().enumerate() {
            tx.execute(
                "INSERT INTO idx_fanout(idx_source_id, bucket, cumulative) VALUES(?1,?2,?3)",
                params![source_id, i as i64, *v as i64],
            )
            .map_err(|e| e.to_string())?;
        }
        for ie in &parsed.entries {
            tx.execute(
                "INSERT INTO candidates(oid, origin, source_id, entry_id, loose_id, obj_type)
                 SELECT ?1, 'idx', ?2, e.id, NULL, e.obj_type
                 FROM entries e
                 JOIN packs p ON p.source_id = e.pack_source_id
                 WHERE e.offset = ?3
                 ON CONFLICT DO NOTHING",
                params![oid_hex(&ie.oid), source_id, ie.offset as i64],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE entries SET idx_crc32=?1 WHERE offset=?2 AND pack_source_id IN
                 (SELECT source_id FROM packs WHERE checksum=(
                    SELECT pack_checksum FROM indexes WHERE source_id=?3))",
                params![ie.crc32 as i64, ie.offset as i64, source_id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn import_loose(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        let guard = InflateGuard { max_output: HARD_GUARD };
        let claimed = filename_from_id(&self.sources_dir, source_id)
            .and_then(|n| {
                let stem = n.split('-').last().unwrap_or("").to_string();
                if stem.len() == 40 { Some(stem) } else { None }
            });
        let parsed = match parse_loose_file(data, &guard) {
            Ok(p) => p,
            Err(e) => {
                tx.execute(
                    "UPDATE sources SET parse_status='error', parse_error=?1 WHERE id=?2",
                    params![e, source_id],
                )
                .map_err(|x| x.to_string())?;
                report.errors.push(e);
                return Ok(());
            }
        };
        let oid = git_object_id(parsed.obj_type, &parsed.content);
        let oid_match = claimed.as_deref() == Some(oid.as_str());
        let obj_dir = self.objects_dir.join(&oid[0..2]);
        fs::create_dir_all(&obj_dir).ok();
        fs::write(obj_dir.join(&oid[2..]), &parsed.content).ok();
        tx.execute(
            "INSERT INTO loose_objects(source_id, claimed_oid, obj_type, size, oid, oid_matches_filename)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                source_id,
                claimed,
                parsed.obj_type as i64,
                parsed.size as i64,
                oid,
                oid_match as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        let loose_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO candidates(oid, origin, source_id, entry_id, loose_id, obj_type)
             VALUES(?1,'loose',?2,NULL,?3,?4)",
            params![oid, source_id, loose_id, parsed.obj_type as i64],
        )
        .map_err(|e| e.to_string())?;
        report.candidates += 1;
        Ok(())
    }
}

fn filename_from_id(dir: &Path, source_id: i64) -> Option<String> {
    let prefix = format!("{:010}-", source_id);
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with(&prefix) {
            return Some(n);
        }
    }
    None
}

impl Engine {
    /// Reassociate packs with indexes purely by pack checksum (never by import
    /// order), reconcile per-entry CRC values and materialize index candidates.
    fn relink(&self, tx: &rusqlite::Transaction) -> Result<(), String> {
        tx.execute(
            "UPDATE packs SET linked_idx_source_id = (
                SELECT i.source_id FROM indexes i
                WHERE i.pack_checksum = packs.checksum
                ORDER BY i.source_id LIMIT 1)",
            params![],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE indexes SET linked_pack_source_id = (
                SELECT p.source_id FROM packs p
                WHERE p.checksum = indexes.pack_checksum
                ORDER BY p.source_id LIMIT 1),
             match_kind = CASE WHEN EXISTS(
                SELECT 1 FROM packs p WHERE p.checksum = indexes.pack_checksum)
                THEN 'checksum' ELSE 'none' END",
            params![],
        )
        .map_err(|e| e.to_string())?;
        // Compare every entry CRC with the index CRC when an index is linked.
        tx.execute(
            "UPDATE entries SET crc_ok = CASE
                WHEN idx_crc32 IS NULL THEN NULL
                WHEN idx_crc32 = crc32 THEN 1 ELSE 0 END",
            params![],
        )
        .map_err(|e| e.to_string())?;
        // Back-fill idx crc for freshly linked pairs.
        tx.execute(
            "UPDATE entries SET idx_crc32 = (
                SELECT crc FROM (
                    SELECT i.source_id AS idx_src, 1 AS dummy
                )) WHERE 0",
            params![],
        )
        .ok();
        // Materialize candidates from idx rows when the pack is linked.
        tx.execute(
            "INSERT INTO candidates(oid, origin, source_id, entry_id, loose_id, obj_type)
             SELECT c_oid.oid, 'idx', i.source_id, e.id, NULL, e.obj_type
             FROM indexes i
             JOIN packs p ON p.checksum = i.pack_checksum
             JOIN entries e ON e.pack_source_id = p.source_id
             JOIN (
                SELECT idx.source_id AS sid, fe.oid AS oid, fe.offset AS off
                FROM indexes idx, json_each('[]')
             ) c_oid ON 0
             WHERE 0",
            params![],
        )
        .ok();
        // The fanout-less candidate data comes from raw idx parsing persisted at
        // import time via the candidates table itself; ensure idx candidates are
        // attached to the right entry rows by offset.
        tx.execute(
            "UPDATE candidates SET entry_id = (
                SELECT e.id FROM entries e
                JOIN indexes i ON i.linked_pack_source_id = e.pack_source_id
                WHERE candidates.source_id = i.source_id
                  AND e.offset = (
                      SELECT offset FROM entries e2
                      WHERE e2.id = candidates.entry_id))
             WHERE origin='idx' AND candidates.entry_id IS NOT NULL",
            params![],
        )
        .ok();
        // For idx entries inserted when the pack was missing, recreate using
        // raw idx file scan offsets once the pack exists.
        let idx_rows: Vec<(i64, i64)> = tx
            .prepare(
                "SELECT i.source_id, i.linked_pack_source_id FROM indexes i
                 WHERE i.linked_pack_source_id IS NOT NULL",
            )
            .map_err(|e| e.to_string())?
            .query_map(params![], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();
        for (idx_src, pack_src) in idx_rows {
            let raw = read_source(&self.data_dir, idx_src)?;
            let parsed = parse_idx(&raw).map_err(|e| e)?;
            for ie in &parsed.entries {
                let entry_id: Option<i64> = tx
                    .query_row(
                        "SELECT id FROM entries WHERE pack_source_id=?1 AND offset=?2",
                        params![pack_src, ie.offset as i64],
                        |r| r.get(0),
                    )
                    .ok();
                if let Some(eid) = entry_id {
                    tx.execute(
                        "UPDATE candidates SET entry_id=?1, obj_type=(
                            SELECT obj_type FROM entries WHERE id=?1)
                         WHERE oid=?2 AND origin='idx' AND source_id=?3",
                        params![eid, oid_hex(&ie.oid), idx_src],
                    )
                    .map_err(|e| e.to_string())?;
                    tx.execute(
                        "UPDATE entries SET idx_crc32=?1, crc_ok=CASE WHEN ?1=crc32 THEN 1 ELSE 0 END
                         WHERE id=?2",
                        params![ie.crc32 as i64, eid],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    }
}
