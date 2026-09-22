//! File ingestion: persist raw bytes under the data directory, parse pack /
//! idx / loose inputs, and populate nodes and OID candidates deterministically.

use crate::db::Db;
use crate::git::{crc32, git_object_id, to_hex};
use crate::index::parse_idx;
use crate::loose::parse_loose;
use crate::model::NodeKind;
use crate::pack::parse_pack;
use rusqlite::params;
use sha2::Digest as Sha2Digest;
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub nodes_added: usize,
    pub candidates_added: usize,
    pub errors: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    // dependency-free SHA-256
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

struct Sha256 {
    inner: sha2::Sha256,
}
impl Sha256 {
    fn new() -> Self {
        Sha256 {
            inner: sha2::Sha256::new(),
        }
    }
    fn update(&mut self, d: &[u8]) {
        Sha2Digest::update(&mut self.inner, d);
    }
    fn finalize(self) -> [u8; 32] {
        Sha2Digest::finalize(self.inner).into()
    }
}

pub fn detect_kind(filename: &str, data: &[u8]) -> String {
    let lower = filename.to_lowercase();
    if data.starts_with(b"PACK") {
        return "pack".into();
    }
    if data.starts_with(b"\xff\x74\x4f\x63") {
        return "idx".into();
    }
    if lower.ends_with(".idx") {
        return "idx".into();
    }
    if lower.ends_with(".pack") {
        return "pack".into();
    }
    // otherwise assume loose
    "loose".into()
}

impl Db {
    fn insert_source(
        &self,
        filename: &str,
        kind: &str,
        stored: &Path,
        size: i64,
        sha: &str,
    ) -> i64 {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT INTO sources(filename,kind,stored_path,size,sha256)
             VALUES(?1,?2,?3,?4,?5)",
            params![filename, kind, stored.to_str().unwrap(), size, sha],
        )
        .unwrap();
        c.last_insert_rowid()
    }
}

/// Import raw bytes of a single file. `data_dir/files` holds all inputs so
/// nothing ever leaves the project data directory.
pub fn import_bytes(db: &Db, data_dir: &Path, filename: &str, data: &[u8]) -> ImportReport {
    let kind = detect_kind(filename, data);
    let files_dir = data_dir.join("files");
    fs::create_dir_all(&files_dir).unwrap();
    let digest_hex = sha256_hex(data);
    let stored = files_dir.join(format!("{digest_hex}-{}", sanitize(filename)));
    if !stored.exists() {
        fs::write(&stored, data).unwrap();
    }
    let source_id = db.insert_source(filename, &kind, &stored, data.len() as i64, &digest_hex);
    let mut report = ImportReport {
        source_id,
        kind: kind.clone(),
        nodes_added: 0,
        candidates_added: 0,
        errors: Vec::new(),
    };
    match kind.as_str() {
        "pack" => import_pack(db, source_id, data, &mut report),
        "idx" => import_idx(db, source_id, filename, data, &mut report),
        _ => import_loose(db, source_id, filename, data, &mut report),
    }
    report
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

fn import_pack(db: &Db, source_id: i64, data: &[u8], report: &mut ImportReport) {
    let parsed = parse_pack(data);
    {
        let c = db.0.lock().unwrap();
        c.execute(
            "INSERT INTO pack_scan(source_id,version,object_count,raw_len,trailer_sha,trailer_ok,scan_errors)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                source_id,
                parsed.version,
                parsed.count,
                parsed.raw_len,
                to_hex(&parsed.trailer_sha),
                parsed.trailer_ok as i64,
                serde_json::to_string(&parsed.scan_errors).unwrap(),
            ],
        )
        .unwrap();
        let src_errors: Vec<String> = parsed
            .scan_errors
            .iter()
            .map(|(o, m)| format!("@{o}: {m}"))
            .collect();
        c.execute(
            "UPDATE sources SET parse_errors=?1 WHERE id=?2",
            params![serde_json::to_string(&src_errors).unwrap(), source_id],
        )
        .unwrap();
    }
    report.errors.extend(
        parsed
            .scan_errors
            .iter()
            .map(|(o, m)| format!("@{o}: {m}")),
    );

    // Offset lookup inside this pack, for CRC expected-value matching.
    for e in &parsed.entries {
        let kind = match e.kind {
            crate::git::OBJ_OFS_DELTA => NodeKind::OfsDelta,
            crate::git::OBJ_REF_DELTA => NodeKind::RefDelta,
            _ => NodeKind::Full,
        };
        let object_type = if (1..=4).contains(&e.kind) {
            Some(e.kind as i64)
        } else {
            None
        };
        let base_oid = e.base_ref.map(|b| to_hex(&b));
        let node_id = {
            let c = db.0.lock().unwrap();
            c.execute(
                "INSERT INTO nodes(source_id,pack_offset,kind,object_type,declared_size,inflated_size,
                     payload,header_len,compressed_len,record_crc,base_ofs,base_ref_oid,parse_errors)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    source_id,
                    e.offset as i64,
                    kind.as_str(),
                    object_type,
                    e.declared_size as i64,
                    e.inflated.len() as i64,
                    e.inflated,
                    e.header_len as i64,
                    e.compressed_len as i64,
                    e.record_crc as i64,
                    e.base_ofs.map(|v| v as i64),
                    base_oid,
                    serde_json::to_string(&e.errors).unwrap(),
                ],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        report.nodes_added += 1;

        // Size spoof is detected here from declared vs inflated length.
        let mut local_errors = e.errors.clone();
        if e.declared_size as usize != e.inflated.len() && e.compressed_len > 0 {
            local_errors.push(format!(
                "size spoof: header declares {} inflated bytes but zlib produced {}",
                e.declared_size,
                e.inflated.len()
            ));
            let c = db.0.lock().unwrap();
            c.execute(
                "UPDATE nodes SET parse_errors=?1 WHERE id=?2",
                params![serde_json::to_string(&local_errors).unwrap(), node_id],
            )
            .unwrap();
        }
    }
    // Hash every full object (and even deltas' inflated bytes are kept raw;
    // candidates for resolved deltas come from resolution). Loose not here.
    create_hash_candidates(db, source_id);
}

/// Compute the hash candidate for full nodes. Deltas never get a hash
/// candidate here; their OID is only known after materialization.
fn create_hash_candidates(db: &Db, source_id: i64) {
    let rows: Vec<(i64, i64, Option<i64>, Vec<u8>)> = {
        let c = db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT id,pack_offset,object_type,payload FROM nodes
                 WHERE source_id=?1 AND kind='full'",
            )
            .unwrap();
        s.query_map(params![source_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };
    let mut c = db.0.lock().unwrap();
    let tx = c.transaction().unwrap();
    let mut added = 0usize;
    for (node_id, offset, object_type, payload) in rows {
        let Some(ty) = object_type else { continue };
        let oid = git_object_id(ty as u8, &payload);
        let hex = to_hex(&oid);
        let exists: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE oid=?1 AND node_id=?2 AND origin='hash'",
                params![hex, node_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            tx.execute(
                "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
                 VALUES(?1,?2,?3,?4,'hash','content-hash',1,?5,?6)",
                params![hex, node_id, source_id, offset, 60, 60],
            )
            .unwrap();
            added += 1;
        }
    }
    tx.commit().unwrap();
    let _ = added;
}

fn import_loose(db: &Db, source_id: i64, filename: &str, data: &[u8], report: &mut ImportReport) {
    let parsed = parse_loose(data);
    let oid_hex = infer_oid_from_path(filename);
    {
        let c = db.0.lock().unwrap();
        c.execute(
            "INSERT INTO nodes(source_id,pack_offset,kind,object_type,declared_size,inflated_size,
                 payload,header_len,compressed_len,parse_errors)
             VALUES(?1,-1,'loose',?2,?3,?4,?5,0,?6,?7)",
            params![
                source_id,
                parsed.kind as i64,
                parsed.declared_size as i64,
                parsed.content.len() as i64,
                parsed.content,
                parsed.consumed as i64,
                serde_json::to_string(&parsed.errors).unwrap(),
            ],
        )
        .unwrap();
    }
    report.nodes_added = 1;
    report.errors.extend(parsed.errors);

    // Candidate from materialized hash; plus a path-derived candidate if the
    // file was laid out as `ab/cdef...`.
    let (node_id, content, kind) = {
        let c = db.0.lock().unwrap();
        c.query_row(
            "SELECT id,payload,object_type FROM nodes WHERE source_id=?1",
            params![source_id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap()
    };
    let hash_oid = git_object_id(kind as u8, &content);
    let hash_hex = to_hex(&hash_oid);
    let c = db.0.lock().unwrap();
    c.execute(
        "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
         VALUES(?1,?2,?3,-1,'hash','content-hash',1,60,60)",
        params![hash_hex, node_id, source_id],
    )
    .unwrap();
    report.candidates_added += 1;
    if let Some(path_hex) = oid_hex {
        let matches = path_hex == hash_hex;
        c.execute(
            "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
             VALUES(?1,?2,?3,-1,'loose-path',?4,?5,?6,?7)",
            params![
                path_hex,
                node_id,
                source_id,
                format!("path:{filename}"),
                matches as i64,
                if matches { 100 } else { 40 },
                if matches { 100 } else { 40 },
            ],
        )
        .unwrap();
        report.candidates_added += 1;
    }
}

fn infer_oid_from_path(filename: &str) -> Option<String> {
    let clean = filename.replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        let first = parts[parts.len() - 2];
        let rest = parts[parts.len() - 1];
        if first.len() == 2 && rest.len() == 38 {
            let candidate = format!("{first}{rest}");
            if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate);
            }
        }
    }
    // Also accept a plain 40-hex filename.
    let stem = parts.last().copied().unwrap_or("");
    if stem.len() == 40 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(stem.to_string());
    }
    None
}

fn import_idx(db: &Db, source_id: i64, filename: &str, data: &[u8], report: &mut ImportReport) {
    let parsed = parse_idx(data);
    report.errors.extend(parsed.errors.iter().cloned());

    // Find a pack whose stored trailer checksum equals the idx pack checksum.
    let want = to_hex(&parsed.pack_checksum);
    let pack_rows: Vec<(i64, String, i64)> = {
        let c = db.0.lock().unwrap();
        let mut stmt = c
            .prepare("SELECT source_id,trailer_sha,raw_len FROM pack_scan")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    let pack_match = pack_rows.into_iter().find(|(_, trailer, _)| trailer == &want);

    let mut linked: Option<i64> = None;
    let mut checksum_matches = false;
    if let Some((pack_source_id, _trailer, _len)) = pack_match {
        linked = Some(pack_source_id);
        checksum_matches = true;
        // Record idx-derived candidates and reconcile offsets / CRC.
        let mut c = db.0.lock().unwrap();
        let tx = c.transaction().unwrap();
        for ent in &parsed.entries {
            let hex = to_hex(&ent.oid);
            // Node must exist at that offset in that pack.
            let node: Option<(i64, i64, i64)> = tx
                .query_row(
                    "SELECT id,pack_offset,record_crc FROM nodes
                     WHERE source_id=?1 AND pack_offset=?2",
                    params![pack_source_id, ent.offset as i64],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .ok();
            let Some((node_id, node_offset, record_crc)) = node else {
                report.errors.push(format!(
                    "idx claims oid {hex} at offset {} but no pack entry exists there",
                    ent.offset
                ));
                continue;
            };
            let crc_ok = if parsed.version == 2 {
                let ok = (record_crc as u32) == ent.crc;
                if !ok {
                    report.errors.push(format!(
                        "CRC mismatch for {hex}: idx says {:#010x}, pack record is {record_crc:#010x}",
                        ent.crc
                    ));
                }
                ok
            } else {
                true
            };
            tx.execute(
                "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
                 VALUES(?1,?2,?3,?4,'idx',?5,?6,?7,?8)
                 ON CONFLICT(oid,node_id,origin,source_label) DO UPDATE SET
                   hash_match=excluded.hash_match, confidence=excluded.confidence, sort_key=excluded.sort_key",
                params![
                    hex,
                    node_id,
                    pack_source_id,
                    node_offset,
                    format!("idx-source#{source_id}"),
                    crc_ok as i64,
                    if crc_ok { 95 } else { 30 },
                    if crc_ok { 95 } else { 30 },
                ],
            )
            .unwrap();
            report.candidates_added += 1;
            if parsed.version == 2 {
                tx.execute(
                    "UPDATE nodes SET expected_crc=?1, crc_ok=?2 WHERE id=?3",
                    params![ent.crc as i64, crc_ok as i64, node_id],
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
    } else {
        report.errors.push(format!(
            "idx pack checksum {want} does not match any imported pack"
        ));
    }

    {
        let c = db.0.lock().unwrap();
        c.execute(
            "UPDATE sources SET linked_pack_source_id=?1, idx_checksum_ok=?2, pack_checksum_matches=?3,
                parse_errors=?4 WHERE id=?5",
            params![
                linked,
                parsed.idx_checksum_ok as i64,
                checksum_matches as i64,
                serde_json::to_string(&report.errors).unwrap(),
                source_id,
            ],
        )
        .unwrap();
    }
    let _ = filename;
    let _ = crc32;
}

/// Recursively import every file under a directory (loose object tree support).
pub fn import_path(db: &Db, data_dir: &Path, path: &Path) -> Vec<ImportReport> {
    let mut reports = Vec::new();
    if path.is_file() {
        let mut buf = Vec::new();
        let mut f = fs::File::open(path).unwrap();
        f.read_to_end(&mut buf).unwrap();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "object".into());
        reports.push(import_bytes(db, data_dir, &name, &buf));
    } else {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        // Deterministic traversal (final ordering must not depend on import
        // order anyway, but stable traversal helps reproducibility).
        entries.sort();
        for p in entries {
            if p.is_dir() {
                reports.extend(import_path(db, data_dir, &p));
            } else {
                reports.extend(import_path(db, data_dir, &p));
            }
        }
    }
    reports
}
