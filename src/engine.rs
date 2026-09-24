//! The pack-chain analysis engine.
//!
//! Responsibilities:
//! * ingest pack / idx / loose files into the project data directory,
//! * keep raw offsets, claimed oids, crc and zlib boundaries as candidates,
//! * resolve the base/descendant delta DAG per analysis branch,
//! * enforce depth / total-byte / single-object-ratio budgets,
//! * isolate bad objects and continue with the rest,
//! * recompute only the affected subgraph when bases or pins change.
//!
//! Candidate ordering is derived solely from content-derived sort keys, so
//! import order never changes the result.

use crate::binformat::{git_object_id, OBJ_OFS_DELTA, OBJ_REF_DELTA};
use crate::db;
use crate::delta::apply_delta;
use crate::idx::parse_idx;
use crate::loose::parse_loose;
use crate::models::Evidence;
use crate::pack::parse_pack;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 20,
            max_total_bytes: 64 * 1024 * 1024,
            max_ratio: 0.9,
        }
    }
}

pub const HARD_INFLATE_CAP: usize = 256 * 1024 * 1024;

pub struct Engine {
    conn: Mutex<Connection>,
    data_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct Candidate {
    id: i64,
    source_id: i64,
    kind: String,
    pack_offset: Option<i64>,
    sort_key: String,
    type_name: String,
    declared_size: i64,
    actual_size: i64,
    size_ok: bool,
    parse_error: Option<String>,
    delta_data: Vec<u8>,
    ofs_distance: Option<i64>,
    base_offset: Option<i64>,
    ref_base: Option<[u8; 20]>,
    ofs_in_bounds: bool,
    crc_ok: Option<bool>,
    claimed_oid: Option<[u8; 20]>,
    stored_evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub filename: String,
    pub kind: String,
    pub sha256: String,
    pub candidates: usize,
    pub deduped: bool,
    pub evidence: Vec<Evidence>,
}

fn hexx(b: &[u8]) -> String {
    hex::encode(b)
}

fn parse_oid(s: &str) -> Option<[u8; 20]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 20 {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&v);
    Some(o)
}

fn detect_kind(filename: &str, data: &[u8]) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if data.len() >= 4 && &data[0..4] == b"PACK" {
        "pack"
    } else if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        "idx"
    } else if lower.ends_with(".pack") {
        "pack"
    } else if lower.ends_with(".idx") {
        "idx"
    } else {
        "loose"
    }
}

fn loose_oid_from_path(filename: &str) -> Option<[u8; 20]> {
    let p = Path::new(filename);
    let name = p.file_name()?.to_string_lossy().to_string();
    let parent = p
        .parent()
        .and_then(|x| x.file_name())
        .map(|x| x.to_string_lossy().to_string());
    match parent {
        Some(two) if two.len() == 2 && two.chars().all(|c| c.is_ascii_hexdigit()) => {
            parse_oid(&format!("{}{}", two, name))
        }
        _ => parse_oid(&name),
    }
}

impl Engine {
    pub fn open(data_dir: &Path) -> rusqlite::Result<Engine> {
        std::fs::create_dir_all(data_dir.join("objects"))?;
        let conn = db::open(&data_dir.join("microscope.db"))?;
        let engine = Engine {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        };
        // Recompute default branch once so a fresh/imported db is consistent.
        engine.recompute(1)?;
        Ok(engine)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn get_budget(&self) -> Budget {
        let conn = self.conn.lock().unwrap();
        let mut budget = Budget::default();
        if let Ok(v) = conn.query_row("SELECT v FROM kv WHERE k='budget'", [], |r| r.get::<_, String>(0))
        {
            if let Ok(b) = serde_json::from_str::<Budget>(&v) {
                budget = b;
            }
        }
        budget
    }

    pub fn set_budget(&self, budget: Budget) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let v = serde_json::to_string(&budget).unwrap();
        conn.execute(
            "INSERT INTO kv(k,v) VALUES('budget', ?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [v],
        )?;
        Ok(())
    }

    // -- ingestion ----------------------------------------------------------

    pub fn import_bytes(&self, filename: &str, data: &[u8]) -> rusqlite::Result<ImportReport> {
        let mut conn = self.conn.lock().unwrap();
        import_bytes_locked(&mut conn, &self.data_dir, filename, data)?;
        relink_claims(&mut conn)?;
        recompute_locked(&mut conn)?;
        let sid: i64 = conn.query_row(
            "SELECT id FROM sources ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .unwrap_or(0);
        let (name, kind, sha, evidence_s, count): (String, String, String, String, i64) =
            conn.query_row(
                "SELECT s.filename, s.kind, s.sha256, s.evidence_json,
                        (SELECT COUNT(*) FROM candidates c WHERE c.source_id=s.id)
                 FROM sources s WHERE s.id=?1",
                [sid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        let evidence = serde_json::from_str(&evidence_s).unwrap_or_default();
        Ok(ImportReport {
            source_id: sid,
            filename: name,
            kind,
            sha256: sha,
            candidates: count as usize,
            deduped: false,
            evidence,
        })
    }
}

fn insert_source_row(
    conn: &mut Connection,
    filename: &str,
    kind: &str,
    sha: &str,
    size: i64,
    stored: &Path,
    pack_sha: Option<&str>,
    loose_oid: Option<&str>,
    evidence: &[Evidence],
) -> rusqlite::Result<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO sources(filename,kind,sha256,size,stored_path,pack_sha,loose_oid,imported_at,evidence_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            filename,
            kind,
            sha,
            size,
            stored.to_string_lossy(),
            pack_sha,
            loose_oid,
            now,
            serde_json::to_string(evidence).unwrap_or_else(|_| "[]".into())
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn import_bytes_locked(
    conn: &mut Connection,
    data_dir: &Path,
    filename: &str,
    data: &[u8],
) -> rusqlite::Result<ImportReport> {
    let hash = Sha256::digest(data);
    let sha = hexx(&hash);
    let kind = detect_kind(filename, data);

    if let Ok(sid) = conn.query_row(
        "SELECT id FROM sources WHERE sha256=?1",
        [&sha],
        |r| r.get::<_, i64>(0),
    ) {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM candidates WHERE source_id=?1",
            [sid],
            |r| r.get(0),
        )?;
        let (name, kind_owned): (String, String) =
            conn.query_row("SELECT filename, kind FROM sources WHERE id=?1", [sid], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        return Ok(ImportReport {
            source_id: sid,
            filename: name,
            kind: kind_owned,
            sha256: sha,
            candidates: count as usize,
            deduped: true,
            evidence: Vec::new(),
        });
    }

    let ext = match kind {
        "pack" => "pack",
        "idx" => "idx",
        _ => "loose",
    };
    let stored = data_dir.join("objects").join(format!("{}.{}", sha, ext));
    std::fs::write(&stored, data).map_err(rusqlite::Error::from)?;

    let mut evidence: Vec<Evidence> = Vec::new();
    let (mut pack_sha, mut loose_oid): (Option<String>, Option<String>) = (None, None);
    let mut n = 0usize;

    // Source row first so foreign keys (and later re-imports) are stable.
    let sid = insert_source_row(
        conn,
        filename,
        kind,
        &sha,
        data.len() as i64,
        &stored,
        None,
        None,
        &[],
    )?;

    match kind {
        "pack" => {
            let parsed = parse_pack(data, HARD_INFLATE_CAP);
            pack_sha = Some(hexx(&parsed.trailer_declared));
            evidence.extend(parsed.evidence.clone());
            n = insert_pack_candidates(conn, sid, &sha, &parsed)?;
        }
        "idx" => {
            let parsed = parse_idx(data);
            pack_sha = Some(hexx(&parsed.pack_checksum));
            evidence.extend(parsed.evidence.clone());
            insert_idx_entries(conn, sid, &parsed)?;
        }
        _ => {
            let expected = loose_oid_from_path(filename);
            let parsed = parse_loose(data, expected, HARD_INFLATE_CAP);
            if let Some(oid) = expected {
                loose_oid = Some(hexx(&oid));
            }
            evidence.extend(parsed.evidence.clone());
            insert_loose_candidate(conn, sid, &sha, filename, expected, &parsed)?;
            n = 1;
        }
    }

    conn.execute(
        "UPDATE sources SET pack_sha=?1, loose_oid=?2, evidence_json=?3 WHERE id=?4",
        rusqlite::params![
            pack_sha,
            loose_oid,
            serde_json::to_string(&evidence).unwrap_or_else(|_| "[]".into()),
            sid
        ],
    )?;
    relink_claims(conn)?;

    Ok(ImportReport {
        source_id: sid,
        filename: filename.to_string(),
        kind: kind.to_string(),
        sha256: sha,
        candidates: n,
        deduped: false,
        evidence,
    })
}

fn insert_pack_candidates(
    conn: &mut Connection,
    sid: i64,
    source_sha: &str,
    pack: &crate::pack::ParsedPack,
) -> rusqlite::Result<usize> {
    let mut n = 0;
    for obj in &pack.objects {
        let sort_key = format!("{}:{:016x}", source_sha, obj.offset);
        let (delta_data, ofs_distance, base_offset, ref_base): (
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ) = if obj.type_id == OBJ_OFS_DELTA || obj.type_id == OBJ_REF_DELTA {
            (
                Some(obj.inflated.clone()),
                obj.ofs_distance.map(|d| d as i64),
                obj.base_offset,
                obj.ref_base.map(|o| hexx(&o)),
            )
        } else {
            (None, None, None, None)
        };
        conn.execute(
            "INSERT INTO candidates(source_id,kind,pack_offset,path,sort_key,type_name,
                 declared_size,actual_size,size_ok,parse_error,delta_data,ofs_distance,
                 base_offset,ref_base,ofs_in_bounds,crc_actual,crc_idx,crc_ok,
                 claimed_oid,content,evidence_json)
             VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,NULL,NULL,
                 NULL,NULL,?16)",
            rusqlite::params![
                sid,
                obj.offset as i64,
                format!("pack offset {}", obj.offset),
                sort_key,
                obj.type_name,
                obj.declared_size as i64,
                obj.actual_size as i64,
                obj.size_ok as i64,
                obj.parse_error,
                delta_data,
                ofs_distance,
                base_offset,
                ref_base,
                obj.ofs_in_bounds as i64,
                obj.crc_actual as i64,
                serde_json::to_string(&obj.evidence).unwrap_or_else(|_| "[]".into())
            ],
        )?;
        n += 1;
    }
    Ok(n)
}

fn insert_idx_entries(
    conn: &mut Connection,
    sid: i64,
    idx: &crate::idx::ParsedIdx,
) -> rusqlite::Result<()> {
    for (i, e) in idx.entries.iter().enumerate() {
        conn.execute(
            "INSERT INTO idx_entries(source_id,ordinal,oid,offset,crc32)
             VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![
                sid,
                i as i64,
                hexx(&e.oid),
                e.offset as i64,
                e.crc32 as i64
            ],
        )?;
    }
    Ok(())
}

fn insert_loose_candidate(
    conn: &mut Connection,
    sid: i64,
    source_sha: &str,
    filename: &str,
    expected: Option<[u8; 20]>,
    loose: &crate::loose::ParsedLoose,
) -> rusqlite::Result<i64> {
    let sort_key = match expected {
        Some(o) => format!("loose:{}", hexx(&o)),
        None => format!("{}:loose", source_sha),
    };
    let evidence = serde_json::to_string(&loose.evidence).unwrap_or_else(|_| "[]".into());
    let claimed = expected.map(|o| hexx(&o));
    let computed = hexx(&loose.computed_oid);
    let size_ok = loose.size_ok && loose.parse_error.is_none();
    conn.execute(
        "INSERT INTO candidates(source_id,kind,pack_offset,path,sort_key,type_name,
             declared_size,actual_size,size_ok,parse_error,delta_data,ofs_distance,
             base_offset,ref_base,ofs_in_bounds,crc_actual,crc_idx,crc_ok,
             claimed_oid,computed_oid,content,evidence_json)
         VALUES(?1,'loose',NULL,?2,?3,?4,?5,?6,?7,?8,NULL,NULL,NULL,NULL,1,NULL,NULL,NULL,
             ?9,?10,?11,?12)",
        rusqlite::params![
            sid,
            filename,
            sort_key,
            loose.type_name,
            loose.declared_size as i64,
            loose.actual_size as i64,
            size_ok as i64,
            loose.parse_error,
            claimed,
            computed,
            loose.content,
            evidence
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Attach .idx claims (oid + per-object CRC) to pack candidates. Matching is
/// by (pack sha -> source.pack_sha, object offset). Purely content-derived,
/// hence independent of import order.
fn relink_claims(conn: &mut Connection) -> rusqlite::Result<()> {
    // Clear stale claims first so removing/re-importing an idx is reflected.
    conn.execute(
        "UPDATE candidates SET claimed_oid=NULL, crc_idx=NULL, crc_ok=NULL WHERE kind='pack'",
        [],
    )?;
    conn.execute(
        "UPDATE candidates AS c
         SET claimed_oid = (
                SELECT i.oid FROM idx_entries i
                JOIN sources si ON si.id = i.source_id
                JOIN sources sp ON sp.id = c.source_id
                WHERE si.pack_sha = sp.pack_sha AND i.offset = c.pack_offset
                ORDER BY i.source_id, i.ordinal LIMIT 1
             ),
             crc_idx = (
                SELECT i.crc32 FROM idx_entries i
                JOIN sources si ON si.id = i.source_id
                JOIN sources sp ON sp.id = c.source_id
                WHERE si.pack_sha = sp.pack_sha AND i.offset = c.pack_offset
                ORDER BY i.source_id, i.ordinal LIMIT 1
             )
         WHERE c.kind='pack'",
        [],
    )?;
    conn.execute(
        "UPDATE candidates
         SET crc_ok = CASE
             WHEN crc_idx IS NULL THEN NULL
             WHEN crc_idx = crc_actual THEN 1 ELSE 0 END
         WHERE kind='pack'",
        [],
    )?;
    Ok(())
}
