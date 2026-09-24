use crate::db::{now, Db};
use crate::delta::{parse_delta, DeltaReport};
use crate::formats::{
    crc32, git_hash, hex_to_oid, oid_hex, parse_object_header, parse_pack_header,
    preview_bytes, sha1_hex, zlib_deflate, zlib_inflate_from, OBJ_BLOB, OBJ_COMMIT, OBJ_OFS_DELTA,
    OBJ_REF_DELTA, OBJ_TAG, OBJ_TREE,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Budgets {
    pub max_depth: usize,
    pub total_bytes: u64,
    pub single_ratio: f64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_depth: 64,
            total_bytes: 64 * 1024 * 1024,
            single_ratio: 0.9,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntryRow {
    pub id: i64,
    pub source_id: i64,
    pub slot: Option<i64>,
    pub pack_offset: Option<i64>,
    pub header_end: Option<i64>,
    pub zlib_start: Option<i64>,
    pub zlib_end: Option<i64>,
    pub kind: Option<i64>,
    pub declared_size: Option<i64>,
    pub actual_len: Option<i64>,
    pub claimed_oid: Option<String>,
    pub ofs_distance: Option<i64>,
    pub ofs_base_offset: Option<i64>,
    pub ref_base_oid: Option<String>,
    pub parse_status: String,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
struct SourceRow {
    id: i64,
    path: String,
    kind: String,
    byte_size: i64,
}

#[derive(Debug, Clone)]
struct Mat {
    entry_id: i64,
    kind: Option<i64>,
    output_len: Option<i64>,
    output_oid: Option<String>,
    status: String,
    error_code: Option<String>,
    error: Option<String>,
    depth: Option<i64>,
    block_chain: String,
    budget_max_depth: i64,
    budget_total_bytes: i64,
    budget_single_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub source_id: i64,
    pub path: String,
    pub kind: String,
    pub imported: bool,
    pub entries: usize,
    pub materialized: usize,
    pub paused: usize,
    pub bad: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteInfo {
    pub dependent_objects: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub entry_id: i64,
    pub oid: String,
    pub kind: String,
    pub source: String,
    pub offset: Option<i64>,
    pub status: String,
    pub depth: i64,
    pub output_len: Option<i64>,
    pub preview: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub from_entry: i64,
    pub to_entry: Option<i64>,
    pub to_oid: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub source: String,
    pub offset: Option<i64>,
    pub header_end: Option<i64>,
    pub zlib_start: Option<i64>,
    pub zlib_end: Option<i64>,
    pub declared_size: Option<i64>,
    pub actual_len: Option<i64>,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViewModel {
    pub title: String,
    pub sources: Vec<serde_json::Value>,
    pub entries: Vec<serde_json::Value>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub evidence: Vec<Evidence>,
    pub fanout: Vec<serde_json::Value>,
    pub pack_layout: Vec<serde_json::Value>,
    pub branches: Vec<serde_json::Value>,
    pub branch_id: i64,
    pub budgets: serde_json::Value,
    pub blocked: Vec<serde_json::Value>,
}

pub struct Engine {
    pub db: Db,
    pub budgets: std::sync::Mutex<Budgets>,
}

impl Engine {
    pub fn open(root: &Path) -> Result<Self, String> {
        Ok(Self {
            db: Db::open(root)?,
            budgets: std::sync::Mutex::new(Budgets::default()),
        })
    }

    pub fn memory() -> Result<Self, String> {
        Ok(Self {
            db: Db::memory()?,
            budgets: std::sync::Mutex::new(Budgets::default()),
        })
    }

    pub fn set_budgets(&self, budgets: Budgets) {
        *self.budgets.lock().unwrap() = budgets;
    }

    pub fn import_bytes(&mut self, original_name: &str, bytes: &[u8]) -> Result<ImportResult, String> {
        let budget_snapshot = self.current_budgets();
        let lower = original_name.to_ascii_lowercase();
        let kind = if lower.ends_with(".pack") {
            "pack"
        } else if lower.ends_with(".idx") {
            "idx"
        } else if is_loose_oid_path(original_name) {
            "loose"
        } else {
            return Err("unsupported source: expected .pack, .idx, or objects/xx/<38 hex>".into());
        };
        if kind == "loose" {
            if zlib_inflate_from(bytes, 0).is_err() {
                return Err("loose object is not a valid zlib stream".into());
            }
        } else if kind == "pack" && bytes.len() >= 4 && &bytes[0..4] != b"PACK" {
            return Err("pack is missing PACK magic".into());
        } else if kind == "idx" && bytes.len() >= 8 && &bytes[4..8] != b"\xfftOc" {
            return Err("only pack index version 2 is supported".into());
        }
        let sha = hex::encode(Sha256::digest(bytes));
        let stored = self.db.data_dir.join("uploads").join(kind).join(&sha);
        if !stored.exists() {
            fs::create_dir_all(stored.parent().unwrap()).map_err(|e| e.to_string())?;
            fs::write(&stored, bytes).map_err(|e| e.to_string())?;
        }
        let path = format!("data/uploads/{kind}/{sha}");
        let tx = self.db.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
        let existing = tx
            .query_row("SELECT id FROM sources WHERE path=?1", params![path], |row| row.get::<_, i64>(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let source_id = if let Some(id) = existing {
            id
        } else {
            tx.execute(
                "INSERT INTO sources(path,kind,byte_size,sha256,imported_at) VALUES(?1,?2,?3,?4,?5)",
                params![path, kind, bytes.len() as i64, sha, now()],
            )
            .map_err(|e| e.to_string())?;
            let id = tx.last_insert_rowid();
            if kind == "pack" {
                parse_pack(&tx, id, Path::new(&path), bytes)?;
            } else if kind == "idx" {
                parse_idx(&tx, id, Path::new(&path), bytes)?;
            } else {
                parse_loose(&tx, id, original_name, bytes)?;
            }
            mark_new_entry_dirty(&tx, 1, id)?;
            id
        };
        let stats = materialize_branch(&tx, 1, budget_snapshot)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(ImportResult {
            source_id,
            path,
            kind: kind.into(),
            imported: existing.is_none(),
            entries: stats.entries,
            materialized: stats.materialized,
            paused: stats.paused,
            bad: stats.bad,
        })
    }

    fn current_budgets(&self) -> Budgets {
        self.budgets.lock().unwrap().clone()
    }

    pub fn retry(&mut self, branch_id: i64) -> Result<ReconStats, String> {
        let budget_snapshot = self.current_budgets();
        let tx = self.db.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM edge_dirty", []).ok();
        let stats = materialize_branch(&tx, branch_id, budget_snapshot)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(stats)
    }

    pub fn create_branch_with_pin(&mut self, name: &str, oid: &str, entry_id: i64) -> Result<(i64, ReconStats), String> {
        hex_to_oid(oid)?;
        let budget_snapshot = self.current_budgets();
        let tx = self.db.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM object_entries WHERE id=?1 AND claimed_oid=?2",
            params![entry_id, oid],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
        if exists == 0 {
            return Err("pin does not match an object candidate".into());
        }
        tx.execute(
            "INSERT INTO branches(name,created_at) VALUES(?1,?2)",
            params![name, now()],
        )
        .map_err(|e| e.to_string())?;
        let branch_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO pins(branch_id,oid,entry_id) VALUES(?1,?2,?3)",
            params![branch_id, oid, entry_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason)
             SELECT ?1,id,'new pinned branch' FROM object_entries",
            params![branch_id],
        )
        .map_err(|e| e.to_string())?;
        let stats = materialize_branch(&tx, branch_id, budget_snapshot)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok((branch_id, stats))
    }
}

fn note(conn: &rusqlite::Transaction, source_id: i64, severity: &str, code: &str, message: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO source_notes(source_id,severity,code,message) VALUES(?1,?2,?3,?4)",
        params![source_id, severity, code, message],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn matching_index(conn: &rusqlite::Transaction, pack_path: &str) -> Result<Option<(i64, PathBuf, Vec<u8>)>, String> {
    let checksum = conn
        .query_row(
            "SELECT checksum_sha FROM pack_summary WHERE source_id=(SELECT id FROM sources WHERE path=?1)",
            params![pack_path],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let checksum = match checksum {
        Some(value) => value,
        None => return Ok(None),
    };
    let row = conn
        .query_row(
            "SELECT s.id,s.path FROM sources s JOIN index_summary i ON s.id=i.source_id
             WHERE s.kind='idx' AND i.expected_pack_sha=?1",
            params![checksum],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    match row {
        Some((id, rel)) => {
            let full = PathBuf::from(&rel);
            let bytes = fs::read(&full).map_err(|e| e.to_string())?;
            Ok(Some((id, full, bytes)))
        }
        None => Ok(None),
    }
}

fn parse_idx_offsets(data: &[u8]) -> Result<(u32, Vec<(String, u64, u32)>, Vec<(usize, i64)>), String> {
    if data.len() < 8 || &data[0..4] != b"\xfftOc" {
        return Err("missing index v2 magic".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported index version {version}"));
    }
    let fanout_base = 8;
    let total = u32::from_be_bytes(data[fanout_base + 255 * 4..fanout_base + 259 * 4].try_into().unwrap());
    let fanout = (0..256)
        .map(|bucket| {
            let start = fanout_base + bucket * 4;
            (bucket, i64::from(u32::from_be_bytes(data[start..start + 4].try_into().unwrap())))
        })
        .collect::<Vec<_>>();
    let n = total as usize;
    let oid_base = fanout_base + 256 * 4;
    let crc_base = oid_base + n * 20;
    let offset_base = crc_base + n * 4;
    let large_base = offset_base + n * 4;
    if large_base > data.len().saturating_sub(40) {
        return Err("index object tables are truncated".into());
    }
    let mut values = Vec::with_capacity(n);
    for slot in 0..n {
        let oid = oid_hex(data[oid_base + slot * 20..oid_base + (slot + 1) * 20].try_into().unwrap());
        let crc = u32::from_be_bytes(data[crc_base + slot * 4..crc_base + (slot + 1) * 4].try_into().unwrap());
        let raw = u32::from_be_bytes(data[offset_base + slot * 4..offset_base + (slot + 1) * 4].try_into().unwrap());
        let offset = if raw & 0x8000_0000 != 0 {
            let table_index = (raw & 0x7fff_ffff) as usize;
            let pos = large_base + table_index * 8;
            if pos + 8 > data.len() - 40 {
                return Err("large offset table is out of bounds".into());
            }
            u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap())
        } else {
            u64::from(raw)
        };
        values.push((oid, offset, crc));
    }
    Ok((total, values, fanout))
}

fn parse_pack(
    conn: &rusqlite::Transaction,
    source_id: i64,
    stored: &Path,
    data: &[u8],
) -> Result<(), String> {
    let header = parse_pack_header(data)?;
    let observed = sha1_hex(&data[..data.len() - 20]);
    let checksum = sha1_hex(&data[data.len() - 20..]);
    let checksum_ok = observed == checksum;
    conn.execute(
        "INSERT INTO pack_summary(source_id,version,object_count,header_end,checksum_sha,observed_checksum_sha,checksum_ok)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            source_id,
            header.version,
            header.object_count,
            12,
            checksum,
            observed,
            checksum_ok
        ],
    )
    .map_err(|e| e.to_string())?;
    if !checksum_ok {
        note(conn, source_id, "error", "pack_checksum", "pack trailing SHA-1 does not match contents")?;
    }
    let indexed = matching_index(conn, &format!("{}", stored.display()))?;
    let entries = if let Some((idx_source, _, idx_bytes)) = &indexed {
        let (_, values, fanout) = parse_idx_offsets(idx_bytes)?;
        save_idx_summary(conn, *idx_source, idx_bytes, data, observed.clone())?;
        for (bucket, cumulative) in fanout {
            conn.execute(
                "INSERT OR REPLACE INTO index_fanout(source_id,bucket,cumulative) VALUES(?1,?2,?3)",
                params![idx_source, bucket as i64, cumulative],
            )
            .map_err(|e| e.to_string())?;
        }
        values
            .into_iter()
            .enumerate()
            .map(|(slot, (oid, offset, crc))| Some((slot as i64, oid, offset, Some(crc))))
            .collect::<Vec<_>>()
    } else {
        (0..header.object_count as usize)
            .map(|slot| Some((slot as i64, String::new(), 0, None)))
            .collect()
    };
    let mut offset = 12usize;
    for item in entries.iter().cloned() {
        let (slot, mut claimed_oid, indexed_offset, indexed_crc) = item.unwrap();
        if indexed_crc.is_some() {
            offset = indexed_offset as usize;
        }
        if offset >= data.len() - 20 {
            insert_entry_error(conn, source_id, Some(slot), Some(offset as i64), "offset_out_of_bounds", "object offset crosses pack trailer")?;
            continue;
        }
        let object_start = offset;
        let header_parsed = parse_object_header(data, offset);
        let object_header = match header_parsed {
            Ok(value) => value,
            Err(message) => {
                insert_entry_error(conn, source_id, Some(slot), Some(object_start as i64), "object_header", &message)?;
                if indexed_crc.is_none() {
                    break;
                }
                continue;
            }
        };
        let zlib_start = object_header.header_end;
        let inflated = zlib_inflate_from(data, zlib_start);
        let (payload, zlib_end, inflate_warning) = match inflated {
            Ok(value) => value,
            Err(message) => {
                insert_entry_error_with_header(conn, source_id, Some(slot), object_start, zlib_start, &object_header, claimed_oid.clone(), indexed_crc, "zlib", &message)?;
                if indexed_crc.is_none() {
                    break;
                }
                offset = next_indexed_offset(&entries, slot).unwrap_or(data.len() - 20);
                continue;
            }
        };
        if payload.len() as u64 != object_header.declared_size {
            let message = format!(
                "declared object/delta size {} but inflated length {}",
                object_header.declared_size,
                payload.len()
            );
            insert_entry_error_with_header(conn, source_id, Some(slot), object_start, zlib_start, &object_header, claimed_oid.clone(), indexed_crc, "size_spoof", &message)?;
            if indexed_crc.is_none() {
                break;
            }
            offset = next_indexed_offset(&entries, slot).unwrap_or(data.len() - 20);
            continue;
        }
        let observed_crc = crc32(&data[object_start..zlib_end]);
        let crc_ok = indexed_crc.map_or(true, |expected| expected == observed_crc);
        if !crc_ok {
            note(conn, source_id, "error", "object_crc", &format!("object at {object_start} has mismatched index CRC"))?;
        }
        let mut ofs_base_offset = None;
        if object_header.kind == OBJ_OFS_DELTA {
            let distance = object_header.ofs_distance.unwrap_or(0);
            if distance as usize > object_start {
                let message = format!("ofs-delta distance {distance} precedes pack offset {object_start}");
                insert_entry_error_with_header(conn, source_id, Some(slot), object_start, zlib_start, &object_header, claimed_oid.clone(), indexed_crc, "ofs_out_of_bounds", &message)?;
                if indexed_crc.is_none() {
                    break;
                }
                offset = next_indexed_offset(&entries, slot).unwrap_or(data.len() - 20);
                continue;
            }
            ofs_base_offset = Some((object_start - distance as usize) as i64);
        }
        let ref_base_oid = object_header.ref_base.map(|oid| oid_hex(&oid));
        let parse_status = if crc_ok { "ok" } else { "crc_error" };
        let parse_error = if crc_ok { inflate_warning } else { Some("index CRC does not match object bytes".into()) };
        if indexed_crc.is_none() && object_header.kind <= OBJ_BLOB {
            let computed = git_hash(crate::formats::type_name(object_header.kind), &payload);
            claimed_oid = oid_hex(&computed);
        }
        conn.execute(
            "INSERT OR REPLACE INTO object_entries(source_id,slot,pack_offset,header_end,zlib_start,zlib_end,kind,declared_size,compressed_len,actual_len,claimed_oid,ofs_distance,ofs_base_offset,ref_base_oid,index_crc,observed_crc,parse_status,parse_error)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                source_id,
                slot,
                object_start as i64,
                zlib_start as i64,
                zlib_start as i64,
                zlib_end as i64,
                object_header.kind,
                object_header.declared_size as i64,
                (zlib_end - zlib_start) as i64,
                payload.len() as i64,
                claimed_oid,
                object_header.ofs_distance.map(|v| v as i64),
                ofs_base_offset,
                ref_base_oid,
                indexed_crc.map(|v| v as i64),
                observed_crc as i64,
                parse_status,
                parse_error
            ],
        )
        .map_err(|e| e.to_string())?;
        offset = zlib_end;
    }
    if offset != data.len() - 20 && indexed.is_none() {
        note(conn, source_id, "warning", "layout", "sequential scan stopped before reaching checksum trailer")?;
    }
    Ok(())
}

fn insert_entry_error(
    conn: &rusqlite::Transaction,
    source_id: i64,
    slot: Option<i64>,
    offset: Option<i64>,
    code: &str,
    message: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO object_entries(source_id,slot,pack_offset,parse_status,parse_error)
         VALUES(?1,?2,?3,?4,?5)",
        params![source_id, slot, offset, code, message],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn insert_entry_error_with_header(
    conn: &rusqlite::Transaction,
    source_id: i64,
    slot: Option<i64>,
    pack_offset: usize,
    zlib_start: usize,
    header: &crate::formats::PackObjectHeader,
    claimed_oid: String,
    index_crc: Option<u32>,
    code: &str,
    message: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO object_entries(source_id,slot,pack_offset,header_end,zlib_start,kind,declared_size,claimed_oid,index_crc,parse_status,parse_error)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            source_id,
            slot,
            pack_offset as i64,
            zlib_start as i64,
            zlib_start as i64,
            header.kind,
            header.declared_size as i64,
            claimed_oid,
            index_crc.map(|v| v as i64),
            code,
            message
        ],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn next_indexed_offset(entries: &[Option<(i64, String, u64, Option<u32>)>], slot: i64) -> Option<usize> {
    entries
        .get(slot as usize + 1)
        .and_then(|item| item.as_ref())
        .map(|(_, _, offset, _)| *offset as usize)
}

fn save_idx_summary(
    conn: &rusqlite::Transaction,
    source_id: i64,
    idx: &[u8],
    pack: &[u8],
    observed_pack_sha: String,
) -> Result<(), String> {
    let count = u32::from_be_bytes(idx[8 + 255 * 4..8 + 259 * 4].try_into().unwrap());
    let expected_pack = hex::encode(&idx[idx.len() - 40..idx.len() - 20]);
    let expected_index = hex::encode(&idx[idx.len() - 20..]);
    let observed_index = sha1_hex(&idx[..idx.len() - 20]);
    let index_ok = observed_index == expected_index;
    let pack_ok = expected_pack == observed_pack_sha;
    conn.execute(
        "INSERT OR REPLACE INTO index_summary(source_id,version,object_count,expected_pack_sha,index_sha,observed_pack_sha,observed_index_sha,pack_sha_ok,index_sha_ok)
         VALUES(?1,2,?2,?3,?4,?5,?6,?7,?8)",
        params![source_id, count, expected_pack, expected_index, observed_pack_sha, observed_index, pack_ok, index_ok],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())?;
    if !index_ok {
        note(conn, source_id, "error", "index_checksum", "index trailing SHA-1 does not match contents")?;
    }
    if !pack_ok {
        note(conn, source_id, "error", "pack_index_mismatch", "index does not describe this pack checksum")?;
    }
    let _ = pack;
    Ok(())
}

fn parse_idx(
    conn: &rusqlite::Transaction,
    source_id: i64,
    _stored: &Path,
    data: &[u8],
) -> Result<(), String> {
    let (count, values, fanout) = parse_idx_offsets(data)?;
    let expected_pack = hex::encode(&data[data.len() - 40..data.len() - 20]);
    let expected_index = hex::encode(&data[data.len() - 20..]);
    let observed_index = sha1_hex(&data[..data.len() - 20]);
    let (pack_source, observed_pack) = conn
        .query_row(
            "SELECT source_id, observed_checksum_sha FROM pack_summary WHERE checksum_sha=?1",
            params![expected_pack],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map_or((None, expected_pack.clone()), |(id, sha)| (Some(id), sha));
    let pack_ok = observed_pack == expected_pack;
    let index_ok = observed_index == expected_index;
    conn.execute(
        "INSERT OR REPLACE INTO index_summary(source_id,version,object_count,expected_pack_sha,index_sha,observed_pack_sha,observed_index_sha,pack_sha_ok,index_sha_ok)
         VALUES(?1,2,?2,?3,?4,?5,?6,?7,?8)",
        params![source_id, count, expected_pack, expected_index, observed_pack, observed_index, pack_ok, index_ok],
    )
    .map_err(|e| e.to_string())?;
    for (bucket, cumulative) in fanout {
        conn.execute(
            "INSERT OR REPLACE INTO index_fanout(source_id,bucket,cumulative) VALUES(?1,?2,?3)",
            params![source_id, bucket as i64, cumulative],
        )
        .map_err(|e| e.to_string())?;
    }
    if !index_ok {
        note(conn, source_id, "error", "index_checksum", "index trailing SHA-1 does not match contents")?;
    }
    if !pack_ok {
        note(conn, source_id, "error", "pack_index_mismatch", "index does not describe this pack checksum")?;
    }
    if let Some(pack_source) = pack_source {
        for (slot, (oid, offset, crc)) in values.into_iter().enumerate() {
            conn.execute(
                "UPDATE object_entries SET slot=?1, claimed_oid=?2, index_crc=?3 WHERE source_id=?4 AND pack_offset=?5",
                params![slot as i64, oid, crc as i64, pack_source, offset as i64],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn is_loose_oid_path(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    let mut parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() < 3 {
        return false;
    }
    let file = parts.pop().unwrap();
    let directory = parts.pop().unwrap();
    parts.pop();
    directory.len() == 2 && file.len() == 38 && hex::decode(format!("{directory}{file}")).map(|v| v.len() == 20).unwrap_or(false)
}

fn loose_oid_from_path(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let parts = normalized.split('/').collect::<Vec<_>>();
    let file = parts[parts.len() - 1];
    let directory = parts[parts.len() - 2];
    format!("{directory}{file}")
}

fn parse_loose(
    conn: &rusqlite::Transaction,
    source_id: i64,
    original_name: &str,
    data: &[u8],
) -> Result<(), String> {
    let oid = loose_oid_from_path(original_name);
    let (mut payload, zlib_end, warning) = zlib_inflate_from(data, 0).map_err(|e| {
        conn.execute(
            "INSERT OR REPLACE INTO object_entries(source_id,pack_offset,zlib_start,zlib_end,claimed_oid,parse_status,parse_error)
             VALUES(?1,NULL,0,NULL,?2,'zlib',?3)",
            params![source_id, oid, e],
        )
        .ok();
        e
    })?;
    let (word, header_end) = crate::formats::read_size_encoding(&payload, 0)?;
    let kind = ((word >> 4) & 7) as u8;
    let size = word & 0x0f | (word >> 7);
    if !(1..=4).contains(&kind) {
        return Err(format!("loose object has invalid type {kind}"));
    }
    let actual = payload.len() - header_end;
    let status;
    let mut error = warning;
    if size as usize != actual {
        status = "size_spoof";
        error = Some(format!("declared loose size {size} but content length {actual}"));
    } else {
        status = "ok";
    }
    payload.drain(..header_end);
    conn.execute(
        "INSERT OR REPLACE INTO object_entries(source_id,pack_offset,header_end,zlib_start,zlib_end,kind,declared_size,compressed_len,actual_len,claimed_oid,parse_status,parse_error)
         VALUES(?1,NULL,?2,0,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            source_id,
            header_end as i64,
            zlib_end as i64,
            kind,
            size as i64,
            data.len() as i64,
            actual as i64,
            oid,
            status,
            error
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReconStats {
    pub entries: usize,
    pub materialized: usize,
    pub paused: usize,
    pub bad: usize,
    pub blocked: usize,
}

struct Session {
    budget: Budgets,
    bytes: u64,
}

struct MaterialOutcome {
    data: Vec<u8>,
    kind: u8,
    depth: i64,
}

fn read_entry(conn: &rusqlite::Transaction, entry_id: i64) -> Result<EntryRow, String> {
    conn.query_row(
        "SELECT id,source_id,slot,pack_offset,header_end,zlib_start,zlib_end,kind,declared_size,actual_len,claimed_oid,ofs_distance,ofs_base_offset,ref_base_oid,parse_status,parse_error
         FROM object_entries WHERE id=?1",
        params![entry_id],
        |row| {
            Ok(EntryRow {
                id: row.get(0)?,
                source_id: row.get(1)?,
                slot: row.get(2)?,
                pack_offset: row.get(3)?,
                header_end: row.get(4)?,
                zlib_start: row.get(5)?,
                zlib_end: row.get(6)?,
                kind: row.get(7)?,
                declared_size: row.get(8)?,
                actual_len: row.get(9)?,
                claimed_oid: row.get(10)?,
                ofs_distance: row.get(11)?,
                ofs_base_offset: row.get(12)?,
                ref_base_oid: row.get(13)?,
                parse_status: row.get(14)?,
                parse_error: row.get(15)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

fn source_row(conn: &rusqlite::Transaction, source_id: i64) -> Result<SourceRow, String> {
    conn.query_row(
        "SELECT id,path,kind,byte_size FROM sources WHERE id=?1",
        params![source_id],
        |row| {
            Ok(SourceRow {
                id: row.get(0)?,
                path: row.get(1)?,
                kind: row.get(2)?,
                byte_size: row.get(3)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

fn source_bytes(conn: &rusqlite::Transaction, source_id: i64) -> Result<Vec<u8>, String> {
    let source = source_row(conn, source_id)?;
    fs::read(&source.path).map_err(|e| e.to_string())
}

fn load_stored_output(conn: &rusqlite::Transaction, entry_id: i64) -> Option<(Vec<u8>, i64, i64)> {
    conn.query_row(
        "SELECT output,kind,depth FROM materializations WHERE entry_id=?1 AND status='complete'",
        params![entry_id],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
    )
    .optional()
    .ok()
    .flatten()
}

fn load_entry_payload(conn: &rusqlite::Transaction, entry: &EntryRow) -> Result<Vec<u8>, String> {
    let bytes = source_bytes(conn, entry.source_id)?;
    let source = source_row(conn, entry.source_id)?;
    if source.kind == "loose" {
        let (raw, _, _) = zlib_inflate_from(&bytes, 0)?;
        let (_, header_end) = crate::formats::read_size_encoding(&raw, 0)?;
        if raw.get(header_end).copied() != Some(0) {
            return Err("loose header is missing NUL separator".into());
        }
        Ok(raw[header_end + 1..].to_vec())
    } else {
        let start = entry.zlib_start.ok_or("missing zlib start")? as usize;
        let (payload, _, _) = zlib_inflate_from(&bytes, start)?;
        Ok(payload)
    }
}

fn chain_json(links: &[(String, String)]) -> String {
    serde_json::to_string(
        &links
            .iter()
            .map(|(oid, reason)| serde_json::json!({"oid": oid, "reason": reason}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into())
}

fn entry_label(conn: &rusqlite::Transaction, entry_id: i64) -> String {
    conn.query_row(
        "SELECT COALESCE(claimed_oid,'unresolved') || COALESCE('@' || pack_offset,'') FROM object_entries WHERE id=?1",
        params![entry_id],
        |row| row.get(0),
    )
    .unwrap_or_else(|_| format!("entry:{entry_id}"))
}

fn upsert_materialization(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    entry_id: i64,
    outcome: Option<&MaterialOutcome>,
    status: &str,
    error_code: Option<&str>,
    error: Option<&str>,
    depth: i64,
    chain: &[(String, String)],
    budget: &Budgets,
) -> Result<(), String> {
    let (output, kind, output_len, oid) = match outcome {
        Some(outcome) => (
            Some(outcome.data.clone()),
            Some(outcome.kind as i64),
            Some(outcome.data.len() as i64),
            Some(oid_hex(&git_hash(crate::formats::type_name(outcome.kind), &outcome.data))),
        ),
        None => (None, None, None, None),
    };
    conn.execute(
        "INSERT INTO materializations(branch_id,entry_id,kind,output_len,output,output_oid,status,error_code,error,depth,block_chain,budget_max_depth,budget_total_bytes,budget_single_ratio,updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
         ON CONFLICT(branch_id,entry_id) DO UPDATE SET kind=excluded.kind,output_len=excluded.output_len,output=excluded.output,output_oid=excluded.output_oid,status=excluded.status,error_code=excluded.error_code,error=excluded.error,depth=excluded.depth,block_chain=excluded.block_chain,budget_max_depth=excluded.budget_max_depth,budget_total_bytes=excluded.budget_total_bytes,budget_single_ratio=excluded.budget_single_ratio,updated_at=excluded.updated_at",
        params![
            branch_id,
            entry_id,
            kind,
            output_len,
            output,
            oid,
            status,
            error_code,
            error,
            depth,
            chain_json(chain),
            budget.max_depth as i64,
            budget.total_bytes as i64,
            budget.single_ratio,
            now()
        ],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn candidates_for_oid(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    oid: &str,
) -> Result<Vec<EntryRow>, String> {
    let mut entries = Vec::new();
    let mut sql = conn.prepare(
        "SELECT e.id,e.source_id,e.slot,e.pack_offset,e.header_end,e.zlib_start,e.zlib_end,e.kind,e.declared_size,e.actual_len,e.claimed_oid,e.ofs_distance,e.ofs_base_offset,e.ref_base_oid,e.parse_status,e.parse_error,
                s.kind,
                CASE WHEN p.entry_id IS NULL THEN 0 ELSE 1 END AS pinned,
                COALESCE(m.status,'missing') AS mstatus
         FROM object_entries e JOIN sources s ON s.id=e.source_id
         LEFT JOIN pins p ON p.branch_id=?1 AND p.oid=?2 AND p.entry_id=e.id
         LEFT JOIN materializations m ON m.branch_id=?1 AND m.entry_id=e.id
         WHERE e.claimed_oid=?2
         ORDER BY pinned DESC,
                  CASE mstatus WHEN 'complete' THEN 0 WHEN 'paused' THEN 2 WHEN 'blocked' THEN 3 WHEN 'bad' THEN 4 ELSE 1 END,
                  CASE s.kind WHEN 'loose' THEN 0 WHEN 'pack' THEN 1 ELSE 2 END,
                  s.path, e.pack_offset, e.id",
    )
    .map_err(|e| e.to_string())?;
    let rows = sql
        .query_map(params![branch_id, oid], |row| {
            Ok((
                EntryRow {
                    id: row.get(0)?,
                    source_id: row.get(1)?,
                    slot: row.get(2)?,
                    pack_offset: row.get(3)?,
                    header_end: row.get(4)?,
                    zlib_start: row.get(5)?,
                    zlib_end: row.get(6)?,
                    kind: row.get(7)?,
                    declared_size: row.get(8)?,
                    actual_len: row.get(9)?,
                    claimed_oid: row.get(10)?,
                    ofs_distance: row.get(11)?,
                    ofs_base_offset: row.get(12)?,
                    ref_base_oid: row.get(13)?,
                    parse_status: row.get(14)?,
                    parse_error: row.get(15)?,
                },
                row.get::<_, i64>(17)?,
                row.get::<_, String>(18)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for row in rows {
        let (entry, _pinned, _mstatus) = row.map_err(|e| e.to_string())?;
        entries.push(entry);
    }
    Ok(entries)
}

fn direct_ofs_base(
    conn: &rusqlite::Transaction,
    entry: &EntryRow,
) -> Result<Option<EntryRow>, String> {
    let base_offset = match entry.ofs_base_offset {
        Some(value) => value,
        None => return Ok(None),
    };
    conn.query_row(
        "SELECT id,source_id,slot,pack_offset,header_end,zlib_start,zlib_end,kind,declared_size,actual_len,claimed_oid,ofs_distance,ofs_base_offset,ref_base_oid,parse_status,parse_error
         FROM object_entries WHERE source_id=?1 AND pack_offset=?2",
        params![entry.source_id, base_offset],
        row_to_entry,
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        id: row.get(0)?,
        source_id: row.get(1)?,
        slot: row.get(2)?,
        pack_offset: row.get(3)?,
        header_end: row.get(4)?,
        zlib_start: row.get(5)?,
        zlib_end: row.get(6)?,
        kind: row.get(7)?,
        declared_size: row.get(8)?,
        actual_len: row.get(9)?,
        claimed_oid: row.get(10)?,
        ofs_distance: row.get(11)?,
        ofs_base_offset: row.get(12)?,
        ref_base_oid: row.get(13)?,
        parse_status: row.get(14)?,
        parse_error: row.get(15)?,
    })
}

fn choose_ref_base(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    oid: &str,
) -> Result<Option<EntryRow>, String> {
    Ok(candidates_for_oid(conn, branch_id, oid)?.into_iter().next())
}

fn validate_output_oid(entry: &EntryRow, kind: u8, output: &[u8]) -> Result<(), String> {
    if let Some(expected) = &entry.claimed_oid {
        if !expected.is_empty() {
            let actual = oid_hex(&git_hash(crate::formats::type_name(kind), output));
            if actual != *expected {
                return Err(format!("recomputed object id {actual} does not match claimed {expected}"));
            }
        }
    }
    Ok(())
}

fn materialize_entry(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    entry_id: i64,
    session: &mut Session,
    stack: &mut Vec<i64>,
    chain: &mut Vec<(String, String)>,
) -> Result<MaterialOutcome, (String, String)> {
    if stack.contains(&entry_id) {
        let names = stack
            .iter()
            .chain(std::iter::once(&entry_id))
            .map(|id| entry_label(conn, *id))
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(("cycle".into(), format!("delta cycle: {names}")));
    }
    if let Some((output, kind, depth)) = load_stored_output(conn, entry_id) {
        return Ok(MaterialOutcome {
            data: output,
            kind: kind as u8,
            depth,
        });
    }
    let entry = read_entry(conn, entry_id).map_err(|e| ("storage".into(), e))?;
    if entry.parse_status != "ok" {
        return Err((
            "bad_source".into(),
            entry.parse_error.unwrap_or_else(|| format!("source object status {}", entry.parse_status)),
        ));
    }
    let kind = entry.kind.ok_or(("bad_source".to_string(), "entry lacks object kind".to_string()))? as u8;
    stack.push(entry_id);
    let payload = load_entry_payload(conn, &entry).map_err(|e| ("zlib".into(), e));
    let outcome = match kind {
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => {
            let payload = payload?;
            if payload.len() as u64 > entry.declared_size.unwrap_or(0) as u64 {
                return Err((
                    "size_spoof".into(),
                    format!("inflated length {} exceeds declared length {}", payload.len(), entry.declared_size.unwrap_or(0)),
                ));
            }
            if payload.len() as f64 > session.budget.total_bytes as f64 * session.budget.single_ratio {
                return Err((
                    "budget_single_ratio".into(),
                    format!("object length {} exceeds single-object ratio budget", payload.len()),
                ));
            }
            if session.bytes.saturating_add(payload.len() as u64) > session.budget.total_bytes {
                return Err((
                    "budget_total_bytes".into(),
                    format!("total expansion budget {} exhausted", session.budget.total_bytes),
                ));
            }
            let outcome = MaterialOutcome {
                data: payload,
                kind,
                depth: 0,
            };
            validate_output_oid(&entry, kind, &outcome.data).map_err(|e| ("object_id".into(), e))?;
            session.bytes += outcome.data.len() as u64;
            outcome
        }
        OBJ_OFS_DELTA | OBJ_REF_DELTA => {
            if stack.len() > session.budget.max_depth {
                return Err((
                    "budget_max_depth".into(),
                    format!("delta depth exceeds {}", session.budget.max_depth),
                ));
            }
            let delta = payload?;
            let selected = if kind == OBJ_OFS_DELTA {
                let base_entry = direct_ofs_base(conn, &entry)
                    .map_err(|e| ("storage".into(), e))?
                    .ok_or_else(|| {
                        ("missing_base".into(), format!("ofs base at offset {} is absent", entry.ofs_base_offset.unwrap_or(-1)))
                    })?;
                let base = materialize_entry(conn, branch_id, base_entry.id, session, stack, chain)
                    .map_err(|mut err| {
                        if err.0 == "missing_base" {
                            err.0 = "blocked_by_base".into();
                        }
                        err
                    })?;
                Some((base_entry, base))
            } else {
                let oid = entry.ref_base_oid.clone().unwrap_or_default();
                chain.push((oid.clone(), "ref-delta base".into()));
                let candidates = candidates_for_oid(conn, branch_id, &oid)
                    .map_err(|e| ("storage".into(), e))?;
                if candidates.is_empty() {
                    return Err(("missing_base".into(), format!("external base {oid} is unavailable")));
                }
                let pinned = is_pinned_candidate(conn, branch_id, &oid).map_err(|e| ("storage".into(), e))?;
                let mut failure = ("missing_base".into(), format!("external base {oid} is unavailable"));
                let mut selected = None;
                for candidate in candidates {
                    if pinned.is_some_and(|pinned_id| pinned_id != candidate.id) {
                        continue;
                    }
                    match materialize_entry(conn, branch_id, candidate.id, session, stack, chain) {
                        Ok(base) => {
                            selected = Some((candidate, base));
                            break;
                        }
                        Err(err) => {
                            failure = err;
                            if pinned == Some(candidate.id) {
                                return Err(failure);
                            }
                        }
                    }
                }
                selected
            };
            let (base_entry, base) = selected.ok_or_else(|| ("blocked_by_base".into(), "all candidate bases failed".into()))?;
            apply_delta_to_base(conn, branch_id, entry_id, &entry, base_entry, base, &delta, session)?
        }
        other => return Err(("bad_source".into(), format!("unsupported object type {other}"))),
    };
    stack.pop();
    Ok(outcome)
}

fn all_entries(conn: &rusqlite::Transaction) -> Result<Vec<EntryRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id,source_id,slot,pack_offset,header_end,zlib_start,zlib_end,kind,declared_size,actual_len,claimed_oid,ofs_distance,ofs_base_offset,ref_base_oid,parse_status,parse_error
             FROM object_entries ORDER BY claimed_oid,source_id,COALESCE(pack_offset,0),id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], row_to_entry).map_err(|e| e.to_string())?;
    rows.map(|r| r.map_err(|e| e.to_string())).collect()
}

fn dirty_entries(
    conn: &rusqlite::Transaction,
    branch_id: i64,
) -> Result<(BTreeSet<i64>, HashMap<String, i64>), String> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM materializations WHERE branch_id=?1", params![branch_id], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if count == 0 {
        let entries = all_entries(conn)?;
        let by_oid = entries
            .iter()
            .filter(|e| !e.claimed_oid.as_deref().unwrap_or("").is_empty())
            .map(|e| (e.claimed_oid.clone().unwrap(), e.id))
            .collect();
        return Ok((entries.iter().map(|e| e.id).collect(), by_oid));
    }
    let mut seeds = BTreeSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT entry_id FROM edge_dirty WHERE branch_id=?1")
            .map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![branch_id], |r| r.get::<_, i64>(0)).map_err(|e| e.to_string())?;
        for row in rows {
            seeds.insert(row.map_err(|e| e.to_string())?);
        }
    }
    let entries = all_entries(conn)?;
    let mut by_oid: HashMap<String, Vec<i64>> = HashMap::new();
    let mut by_ofs: HashMap<(i64, i64), i64> = HashMap::new();
    for entry in &entries {
        if let Some(oid) = &entry.claimed_oid {
            if !oid.is_empty() {
                by_oid.entry(oid.clone()).or_default().push(entry.id);
            }
        }
        if let (Some(source), Some(offset)) = (entry.source_id.into(), entry.pack_offset) {
            by_ofs.insert((source, offset), entry.id);
        }
    }
    let mut dirty = seeds;
    let mut queue: VecDeque<i64> = dirty.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        let entry = match entries.iter().find(|e| e.id == id) {
            Some(entry) => entry,
            None => continue,
        };
        if entry.kind == Some(OBJ_OFS_DELTA as i64) {
            if let (Some(source), Some(base_offset)) = (Some(entry.source_id), entry.ofs_base_offset) {
                if let Some(base_id) = by_ofs.get(&(source, base_offset)).copied() {
                    if dirty.insert(base_id) {
                        queue.push_back(base_id);
                    }
                }
            }
        }
        let dirty_oids: Vec<String> = entries
            .iter()
            .filter(|e| dirty.contains(&e.id))
            .filter_map(|e| e.claimed_oid.clone())
            .filter(|oid| !oid.is_empty())
            .collect();
        for other in &entries {
            if dirty.contains(&other.id) {
                continue;
            }
            if other.kind == Some(OBJ_REF_DELTA as i64) {
                if let Some(base_oid) = &other.ref_base_oid {
                    if dirty_oids.iter().any(|oid| oid == base_oid) {
                        dirty.insert(other.id);
                        queue.push_back(other.id);
                    }
                }
            }
        }
    }
    let first_candidate = by_oid.into_iter().map(|(oid, ids)| (oid, ids.into_iter().min().unwrap())).collect();
    Ok((dirty, first_candidate))
}

fn materialize_branch(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    budget: Budgets,
) -> Result<ReconStats, String> {
    let entries = all_entries(conn)?;
    let (dirty, _) = dirty_entries(conn, branch_id)?;
    for id in &dirty {
        conn.execute(
            "DELETE FROM delta_steps WHERE materialization_id IN (SELECT id FROM materializations WHERE branch_id=?1 AND entry_id=?2)",
            params![branch_id, id],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM materializations WHERE branch_id=?1 AND entry_id=?2 AND status!='complete'",
            params![branch_id, id],
        )
        .map_err(|e| e.to_string())?;
    }
    let total_expanded: u64 = conn
        .query_row(
            "SELECT COALESCE(SUM(output_len),0) FROM materializations WHERE branch_id=?1 AND status='complete'",
            params![branch_id],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v.max(0) as u64)
        .map_err(|e| e.to_string())?;
    let mut session = Session {
        budget: budget.clone(),
        bytes: total_expanded,
    };
    let mut stats = ReconStats::default();
    stats.entries = entries.len();
    let order = compute_deterministic_order(&entries);
    for entry_id in order {
        if !dirty.contains(&entry_id) {
            let status = conn
                .query_row(
                    "SELECT status FROM materializations WHERE branch_id=?1 AND entry_id=?1",
                    params![branch_id, entry_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "missing".into());
            match status.as_str() {
                "complete" => stats.materialized += 1,
                "paused" => stats.paused += 1,
                "blocked" => stats.blocked += 1,
                "bad" => stats.bad += 1,
                _ => {}
            }
            continue;
        }
        let entry = read_entry(conn, entry_id)?;
        let mut last_error = ("bad_source".to_string(), "no usable candidate".to_string());
        let mut success = None;
        if entry.kind == Some(OBJ_REF_DELTA as i64)
            && choose_ref_base(conn, branch_id, entry.ref_base_oid.as_deref().unwrap_or(""))?.is_none()
        {
            last_error = (
                "missing_base".into(),
                format!("external base {} is unavailable", entry.ref_base_oid.as_deref().unwrap_or("")),
            );
        } else {
            let result = materialize_entry(conn, branch_id, entry_id, &mut session, &mut Vec::new(), &mut Vec::new());
            match result {
                Ok(outcome) => success = Some(outcome),
                Err(err) => last_error = err,
            }
        }
        match success {
            Some(outcome) => {
                upsert_materialization(conn, branch_id, entry_id, Some(&outcome), "complete", None, None, outcome.depth, &[], &budget)?;
                stats.materialized += 1;
            }
            None => {
                let (code, message) = last_error;
            let status = if code.starts_with("budget") {
                    stats.paused += 1;
                    "paused"
                } else if code == "missing_base" || code == "blocked_by_base" {
                    stats.blocked += 1;
                    "blocked"
                } else {
                    stats.bad += 1;
                    "bad"
                };
                let chain = if status == "blocked" || status == "paused" {
                    vec![(
                        entry.ref_base_oid
                            .clone()
                            .or_else(|| entry.ofs_base_offset.map(|offset| format!("offset:{offset}")))
                            .unwrap_or_else(|| entry_label(conn, entry_id)),
                        message.clone(),
                    )]
                } else {
                    vec![]
                };
                upsert_materialization(conn, branch_id, entry_id, None, status, Some(&code), Some(&message), 0, &chain, &budget)?;
            }
        }
    }
    conn.execute(
        "DELETE FROM edge_dirty WHERE branch_id=?1",
        params![branch_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(stats)
}

fn persist_delta_step(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    entry_id: i64,
    base_entry_id: i64,
    base: &MaterialOutcome,
    delta: &[u8],
    outcome: &MaterialOutcome,
    report: &DeltaReport,
) -> Result<(), String> {
    let materialization_id = conn
        .query_row(
            "SELECT id FROM materializations WHERE branch_id=?1 AND entry_id=?2",
            params![branch_id, entry_id],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let materialization_id = match materialization_id {
        Some(id) => id,
        None => {
            conn.execute(
                "INSERT INTO materializations(branch_id,entry_id,status,block_chain,budget_max_depth,budget_total_bytes,budget_single_ratio,updated_at)
                 VALUES(?1,?2,'building','[]',0,0,0,?3)",
                params![branch_id, entry_id, now()],
            )
            .map_err(|e| e.to_string())?;
            conn.last_insert_rowid()
        }
    };
    for (ordinal, instr) in report.instructions.iter().enumerate() {
        let check = if instr.op == "copy"
            && instr.offset.checked_add(instr.length).map_or(true, |end| end > base.data.len())
        {
            "bad"
        } else {
            "ok"
        };
        conn.execute(
            "INSERT INTO delta_steps(materialization_id,ordinal,base_entry_id,base_oid,instruction_start,instruction_end,instruction_count,input_len,output_len,report_json,check_status,check_detail)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                materialization_id,
                ordinal as i64,
                base_entry_id,
                oid_hex(&git_hash(crate::formats::type_name(base.kind), &base.data)),
                instr.range_start as i64,
                instr.range_end as i64,
                report.instructions.len() as i64,
                delta.len() as i64,
                outcome.data.len() as i64,
                serde_json::to_string(report).unwrap_or_default(),
                check,
                ""
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn compute_deterministic_order(entries: &[EntryRow]) -> Vec<i64> {
    let mut by_id: BTreeMap<i64, &EntryRow> = entries.iter().map(|e| (e.id, e)).collect();
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut result = Vec::new();

    fn visit(
        id: i64,
        by_id: &BTreeMap<i64, &EntryRow>,
        visited: &mut BTreeSet<i64>,
        active: &mut BTreeSet<i64>,
        result: &mut Vec<i64>,
    ) {
        if visited.contains(&id) || !active.insert(id) {
            return;
        }
        if let Some(entry) = by_id.get(&id).copied() {
            if let Some(base_id) = entry.ofs_base_offset.and_then(|offset| {
                by_id
                    .values()
                    .find(|candidate| candidate.source_id == entry.source_id && candidate.pack_offset == Some(offset))
                    .map(|candidate| candidate.id)
            }) {
                visit(base_id, by_id, visited, active, result);
            }
            if let Some(oid) = &entry.ref_base_oid {
                let base = by_id
                    .values()
                    .filter(|candidate| candidate.claimed_oid.as_deref() == Some(oid.as_str()))
                    .min_by_key(|candidate| candidate.id)
                    .map(|candidate| candidate.id);
                if let Some(base_id) = base {
                    visit(base_id, by_id, visited, active, result);
                }
            }
        }
        active.remove(&id);
        if visited.insert(id) {
            result.push(id);
        }
    }

    let mut ids = by_id.keys().copied().collect::<Vec<_>>();
    ids.sort_by_key(|id| {
        let entry = by_id[id];
        (
            entry.claimed_oid.clone().unwrap_or_default(),
            entry.source_id,
            entry.pack_offset.unwrap_or(0),
            *id,
        )
    });
    for id in ids {
        visit(id, &by_id, &mut visited, &mut active, &mut result);
    }
    let _ = &mut by_id;
    result
}

fn mark_new_entry_dirty(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    source_id: i64,
) -> Result<(), String> {
    let kind: String = conn.query_row("SELECT kind FROM sources WHERE id=?1", params![source_id], |r| r.get(0)).map_err(|e| e.to_string())?;
    if kind == "idx" {
        conn.execute(
            "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason)
             SELECT ?1,e.id,'index evidence changed'
             FROM object_entries e
             JOIN index_summary i ON 1=1
             JOIN sources s ON s.id=i.source_id
             WHERE i.source_id=?1 AND s.kind='idx'",
            params![branch_id, source_id],
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    conn.execute(
        "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason)
         SELECT ?1,id,?2 FROM object_entries WHERE source_id=?3",
        params![branch_id, format!("new {kind} source"), source_id],
    )
    .map_err(|e| e.to_string())?;
    let mut added = true;
    while added {
        added = false;
        let changed = conn.execute(
            "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason)
             SELECT ?1,e.id,'affected dependency'
             FROM object_entries e
             WHERE (
               (e.kind=7 AND EXISTS (SELECT 1 FROM edge_dirty d JOIN object_entries b ON b.id=d.entry_id WHERE d.branch_id=?1 AND b.claimed_oid=e.ref_base_oid))
               OR (e.kind=6 AND EXISTS (SELECT 1 FROM edge_dirty d JOIN object_entries b ON b.id=d.entry_id WHERE d.branch_id=?1 AND b.source_id=e.source_id AND b.pack_offset=e.ofs_base_offset))
             )
             AND NOT EXISTS (SELECT 1 FROM edge_dirty x WHERE x.branch_id=?1 AND x.entry_id=e.id)",
            params![branch_id],
        )
        .map_err(|e| e.to_string())?;
        added = changed > 0;
    }
    Ok(())
}

fn mark_existing_dirty(
    conn: &rusqlite::Transaction,
    branch_id: i64,
) -> Result<(), String> {
    conn.execute(
        "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason)
         SELECT ?1,id,'initial materialization' FROM object_entries",
        params![branch_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn is_pinned_candidate(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    oid: &str,
) -> Result<Option<i64>, String> {
    conn.query_row(
        "SELECT entry_id FROM pins WHERE branch_id=?1 AND oid=?2",
        params![branch_id, oid],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn apply_delta_to_base(
    conn: &rusqlite::Transaction,
    branch_id: i64,
    entry_id: i64,
    entry: &EntryRow,
    base_entry: EntryRow,
    base: MaterialOutcome,
    delta: &[u8],
    session: &mut Session,
) -> Result<MaterialOutcome, (String, String)> {
    if delta.len() as u64 + base.data.len() as u64 > session.budget.total_bytes {
        return Err((
            "budget_total_bytes".into(),
            "delta input sizes exceed total expansion budget".into(),
        ));
    }
    let (target, report) = parse_delta(delta, &base.data).map_err(|e| ("delta".into(), e))?;
    if target.len() as f64 > session.budget.total_bytes as f64 * session.budget.single_ratio {
        return Err((
            "budget_single_ratio".into(),
            format!("target length {} exceeds single-object ratio budget", target.len()),
        ));
    }
    if session.bytes.saturating_add(target.len() as u64) > session.budget.total_bytes {
        return Err((
            "budget_total_bytes".into(),
            format!("total expansion budget {} exhausted", session.budget.total_bytes),
        ));
    }
    validate_output_oid(entry, base.kind, &target).map_err(|e| ("object_id".into(), e))?;
    session.bytes += target.len() as u64;
    let outcome = MaterialOutcome {
        data: target,
        kind: base.kind,
        depth: base.depth + 1,
    };
    persist_delta_step(conn, branch_id, entry_id, base_entry.id, &base, delta, &outcome, &report)
        .map_err(|e| ("storage".into(), e))?;
    Ok(outcome)
}

pub mod test_support {
    use super::*;

    pub fn git_object(kind: &str, data: &[u8]) -> ([u8; 20], Vec<u8>) {
        let oid = git_hash(kind, data);
        let mut raw = Vec::new();
        raw.extend_from_slice(kind.as_bytes());
        raw.push(b' ');
        raw.extend_from_slice(data.len().to_string().as_bytes());
        raw.push(0);
        raw.extend_from_slice(data);
        (oid, raw)
    }

    pub fn object_header(kind: u8, size: usize) -> Vec<u8> {
        let mut value = (size as u64 & 0x0f) | (u64::from(kind) << 4);
        let mut rest = (size as u64) >> 4;
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            if rest != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if rest == 0 {
                break;
            }
            value = rest & 0x7f;
            rest >>= 7;
        }
        out
    }

    pub fn ofs_distance(distance: usize) -> Vec<u8> {
        let mut bytes = vec![(distance & 0x7f) as u8];
        let mut rest = distance >> 7;
        while rest != 0 {
            rest -= 1;
            bytes.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        bytes.reverse();
        bytes
    }

    pub fn pack_object(kind: u8, content: &[u8]) -> Vec<u8> {
        let mut out = object_header(kind, content.len());
        out.extend_from_slice(&zlib_deflate(content));
        out
    }

    pub fn ofs_delta_pack_object(base_offset: usize, current_offset: usize, delta: &[u8]) -> Vec<u8> {
        let mut out = object_header(OBJ_OFS_DELTA, delta.len());
        out.extend_from_slice(&ofs_distance(current_offset - base_offset));
        out.extend_from_slice(&zlib_deflate(delta));
        out
    }

    pub fn ref_delta_pack_object(base_oid: &[u8; 20], delta: &[u8]) -> Vec<u8> {
        let mut out = object_header(OBJ_REF_DELTA, delta.len());
        out.extend_from_slice(base_oid);
        out.extend_from_slice(&zlib_deflate(delta));
        out
    }

    pub fn pack(parts: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>) {
        let mut data = Vec::new();
        data.extend_from_slice(b"PACK");
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&(parts.len() as u32).to_be_bytes());
        let mut offsets = Vec::new();
        for part in parts {
            offsets.push(data.len());
            data.extend_from_slice(part);
        }
        let checksum = sha1_hex(&data);
        data.extend_from_slice(&hex::decode(checksum).unwrap());
        (data, offsets)
    }

    pub fn idx(objects: &[([u8; 20], usize, u32)]) -> Vec<u8> {
        let mut sorted = objects.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let n = sorted.len();
        let mut data = Vec::new();
        data.extend_from_slice(b"\xfftOc");
        data.extend_from_slice(&2u32.to_be_bytes());
        for bucket in 1..=256u32 {
            let count = sorted.iter().filter(|(oid, _, _)| u32::from(oid[0]) < bucket).count() as u32;
            data.extend_from_slice(&count.to_be_bytes());
        }
        for (oid, _, _) in &sorted {
            data.extend_from_slice(oid);
        }
        for (_, _, crc) in &sorted {
            data.extend_from_slice(&crc.to_be_bytes());
        }
        for (_, offset, _) in &sorted {
            data.extend_from_slice(&(*offset as u32).to_be_bytes());
        }
        let expected_pack = vec![0u8; 20];
        data.extend_from_slice(&expected_pack);
        let index_checksum = sha1_hex(&data);
        data.extend_from_slice(&hex::decode(index_checksum).unwrap());
        data
    }

    pub fn idx_for_pack(pack: &[u8], objects: &[([u8; 20], usize)]) -> Vec<u8> {
        let crcs = objects
            .iter()
            .map(|(oid, offset)| {
                let end = objects
                    .iter()
                    .map(|(_, other)| *other)
                    .filter(|other| *other > *offset)
                    .min()
                    .unwrap_or(pack.len() - 20);
                (*oid, *offset, crc32(&pack[*offset..end]))
            })
            .collect::<Vec<_>>();
        let mut data = idx(&crcs);
        let pack_sha = &pack[pack.len() - 20..];
        let n = objects.len();
        let pack_sha_pos = 8 + 256 * 4 + n * 20 + n * 4 + n * 4;
        data[pack_sha_pos..pack_sha_pos + 20].copy_from_slice(pack_sha);
        let checksum = sha1_hex(&data[..data.len() - 20]);
        let last = data.len() - 20;
        data[last..].copy_from_slice(&hex::decode(checksum).unwrap());
        data
    }

    pub fn loose(kind: &str, content: &[u8], declare_size: Option<usize>) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(kind.as_bytes());
        raw.push(b' ');
        let size = declare_size.unwrap_or(content.len());
        raw.extend_from_slice(size.to_string().as_bytes());
        raw.push(0);
        raw.extend_from_slice(content);
        zlib_deflate(&raw)
    }
}

    pub fn delete_preview(&mut self, source_id: i64) -> Result<DeleteInfo, String> {
        let tx = self.db.conn.transaction().map_err(|e| e.to_string())?;
        let mut direct = BTreeSet::new();
        {
            let mut stmt = tx
                .prepare("SELECT id, COALESCE(claimed_oid, 'unresolved@' || COALESCE(pack_offset,0)) FROM object_entries WHERE source_id=?1")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![source_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (id, label) = row.map_err(|e| e.to_string())?;
                direct.insert(id);
                if label != "unresolved" {
                    // retain ids; labels are materialized after closure expansion
                }
            }
        }
        let entries = all_entries(&tx)?;
        let mut affected = direct;
        let mut queue: VecDeque<i64> = affected.iter().copied().collect();
        while let Some(changed_id) = queue.pop_front() {
            let changed_oid = entries.iter().find(|e| e.id == changed_id).and_then(|e| e.claimed_oid.clone());
            for entry in &entries {
                let depends = entry.kind == Some(OBJ_REF_DELTA as i64)
                    && changed_oid.as_deref() == entry.ref_base_oid.as_deref()
                    || entry.kind == Some(OBJ_OFS_DELTA as i64)
                        && entries
                            .iter()
                            .find(|e| e.id == changed_id)
                            .map(|base| base.source_id == entry.source_id && base.pack_offset == entry.ofs_base_offset)
                            .unwrap_or(false);
                if depends && affected.insert(entry.id) {
                    queue.push_back(entry.id);
                }
            }
        }
        let mut dependent_objects = Vec::new();
        for id in &affected {
            if let Some(entry) = entries.iter().find(|e| e.id == *id) {
                let label = entry
                    .claimed_oid
                    .clone()
                    .unwrap_or_else(|| format!("unresolved@{}", entry.pack_offset.unwrap_or(0)));
                dependent_objects.push(label);
            }
        }
        dependent_objects.sort();
        dependent_objects.dedup();
        tx.rollback().map_err(|e| e.to_string())?;
        Ok(DeleteInfo { dependent_objects })
    }

    pub fn delete_source(&mut self, source_id: i64) -> Result<DeleteInfo, String> {
        let preview = self.delete_preview(source_id)?;
        let budget_snapshot = self.current_budgets();
        let tx = self.db.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| e.to_string())?;
        let remaining_entries: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT id FROM object_entries WHERE source_id!=?1").map_err(|e| e.to_string())?;
            let rows = stmt.query_map(params![source_id], |r| r.get::<_, i64>(0)).map_err(|e| e.to_string())?;
            rows.map(|r| r.map_err(|e| e.to_string())).collect::<Result<_, _>>()?
        };
        tx.execute("DELETE FROM sources WHERE id=?1", params![source_id]).map_err(|e| e.to_string())?;
        for id in remaining_entries {
            tx.execute(
                "INSERT OR IGNORE INTO edge_dirty(branch_id,entry_id,reason) VALUES(1,?1,'source deletion changed dependency graph')",
                params![id],
            )
            .map_err(|e| e.to_string())?;
        }
        materialize_branch(&tx, 1, budget_snapshot)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(preview)
    }

    pub fn view_model(&mut self, branch_id: i64) -> Result<ViewModel, String> {
        let conn = &mut self.db.conn;
        let mut sources = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT s.id,s.path,s.kind,s.byte_size,s.sha256,s.imported_at,
                            COALESCE((SELECT COUNT(*) FROM source_notes n WHERE n.source_id=s.id),0) AS notes
                     FROM sources s ORDER BY s.path",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "path": r.get::<_, String>(1)?,
                        "kind": r.get::<_, String>(2)?,
                        "byte_size": r.get::<_, i64>(3)?,
                        "sha256": r.get::<_, String>(4)?,
                        "imported_at": r.get::<_, String>(5)?,
                        "notes": r.get::<_, i64>(6)?
                    }))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                sources.push(row.map_err(|e| e.to_string())?);
            }
        }
        let mut entries = Vec::new();
        let mut nodes = Vec::new();
        let mut evidence = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT e.id,e.pack_offset,e.header_end,e.zlib_start,e.zlib_end,e.kind,e.declared_size,e.actual_len,e.claimed_oid,e.ofs_base_offset,e.ref_base_oid,e.parse_status,e.parse_error,
                            s.path,s.kind,COALESCE(m.status,'missing'),COALESCE(m.depth,0),COALESCE(m.output_len,0),COALESCE(m.output,X''),COALESCE(m.error,''),
                            CASE WHEN p.entry_id IS NULL THEN 0 ELSE 1 END
                     FROM object_entries e JOIN sources s ON s.id=e.source_id
                     LEFT JOIN materializations m ON m.branch_id=?1 AND m.entry_id=e.id
                     LEFT JOIN pins p ON p.branch_id=?1 AND p.oid=e.claimed_oid AND p.entry_id=e.id
                     ORDER BY e.claimed_oid,s.path,e.pack_offset,e.id",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt.query_map(params![branch_id], |r| {
                let output: Vec<u8> = r.get(18)?;
                Ok((
                    serde_json::json!({
                        "id": r.get::<_, i64>(0)?,
                        "offset": r.get::<_, Option<i64>>(1)?,
                        "kind": r.get::<_, Option<i64>>(6)?.map(|k| crate::formats::type_name(k as u8)).unwrap_or("unknown"),
                        "claimed_oid": r.get::<_, Option<String>>(8)?,
                        "parse_status": r.get::<_, String>(11)?,
                        "materialization": r.get::<_, String>(15)?,
                        "error": r.get::<_, String>(19)?,
                        "ofs_base_offset": r.get::<_, Option<i64>>(9)?,
                        "ref_base_oid": r.get::<_, Option<String>>(10)?
                    }),
                    GraphNode {
                        entry_id: r.get(0)?,
                        oid: r.get::<_, Option<String>>(8))?.unwrap_or_else(|| format!("unresolved@{}", r.get::<_, Option<i64>>(1)).unwrap_or(0).unwrap_or(0))),
                        kind: r.get::<_, Option<i64>>(6)?.map(|k| crate::formats::type_name(k as u8)).unwrap_or("unknown").into(),
                        source: r.get::<_, String>(13)?,
                        offset: r.get(1)?,
                        status: r.get(15)?,
                        depth: r.get(16)?,
                        output_len: r.get(17)?,
                        preview: preview_bytes(&output, 240),
                        pinned: r.get::<_, i64>(20)? != 0,
                    },
                    Evidence {
                        source: r.get(13)?,
                        offset: r.get(1)?,
                        header_end: r.get(2)?,
                        zlib_start: r.get(3)?,
                        zlib_end: r.get(4)?,
                        declared_size: r.get(6)?,
                        actual_len: r.get(7)?,
                        status: r.get(11)?,
                        error: {
                            let value = r.get::<_, Option<String>>(12)?;
                            if value.as_deref().unwrap_or("") == "" { r.get::<_, Option<String>>(19)? } else { value }
                        },
                    },
                ))
            });
            for row in rows.map_err(|e| e.to_string())? {
                let (entry, node, ev) = row.map_err(|e| e.to_string())?;
                entries.push(entry);
                nodes.push(node);
                evidence.push(ev);
            }
        }
        let mut edges = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT e.id,e.ofs_base_offset,be.id,e.ref_base_oid,COALESCE(ce.id),CASE WHEN e.kind=6 THEN 'ofs' ELSE 'ref' END
                     FROM object_entries e
                     LEFT JOIN object_entries be ON be.source_id=e.source_id AND be.pack_offset=e.ofs_base_offset
                     LEFT JOIN object_entries ce ON ce.claimed_oid=e.ref_base_oid
                     WHERE e.kind IN (6,7)
                     ORDER BY e.id",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |r| {
                Ok(GraphEdge {
                    from_entry: r.get(0)?,
                    to_entry: r.get::<_, Option<i64>>(2)).or_else(|_| r.get::<_, Option<i64>>(4)).ok().flatten(),
                    to_oid: r.get(3)?,
                    kind: r.get(5)?,
                })
            });
            for row in rows.map_err(|e| e.to_string())? {
                edges.push(row.map_err(|e| e.to_string())?);
            }
        }
        let mut fanout = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT source_id,bucket,cumulative FROM index_fanout ORDER BY source_id,bucket").map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({"source_id":r.get::<_,i64>(0)?,"bucket":r.get::<_,i64>(1)?,"cumulative":r.get::<_,i64>(2)?}))
            });
            for row in rows.map_err(|e| e.to_string())? {
                fanout.push(row.map_err(|e| e.to_string())?);
            }
        }
        let mut pack_layout = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT s.id,p.version,p.object_count,p.header_end,p.checksum_ok,e.pack_offset,e.header_end,e.zlib_end,e.kind,e.claimed_oid,e.parse_status
                     FROM pack_summary p JOIN sources s ON s.id=p.source_id
                     LEFT JOIN object_entries e ON e.source_id=s.id
                     ORDER BY s.id,e.pack_offset",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({
                    "source_id":r.get::<_,i64>(0)?,
                    "version":r.get::<_,i64>(1)?,
                    "object_count":r.get::<_,i64>(2)?,
                    "header_end":r.get::<_,i64>(3)?,
                    "checksum_ok":r.get::<_,bool>(4)?,
                    "offset":r.get::<_,Option<i64>>(5)?,
                    "object_header_end":r.get::<_,Option<i64>>(6)?,
                    "zlib_end":r.get::<_,Option<i64>>(7)?,
                    "kind":r.get::<_,Option<i64>>(8))?.map(|k|crate::formats::type_name(k as u8)),
                    "oid":r.get::<_,Option<String>>(9))?,
                    "status":r.get::<_,Option<String>>(10)?
                }))
            });
            for row in rows.map_err(|e| e.to_string())? {
                pack_layout.push(row.map_err(|e| e.to_string())?);
            }
        }
        let branches = query_json(
            conn,
            "SELECT b.id,b.name,(SELECT COUNT(*) FROM pins p WHERE p.branch_id=b.id) FROM branches b ORDER BY b.id",
        )?;
        let blocked = query_json(
            conn,
            "SELECT entry_id,status,error_code,error,depth,block_chain FROM materializations WHERE branch_id=?1 AND status IN ('blocked','paused','bad') ORDER BY entry_id",
            params![branch_id],
        )?;
        let budget = self.current_budgets();
        Ok(ViewModel {
            title: "包链显微镜".into(),
            sources,
            entries,
            nodes,
            edges,
            evidence,
            fanout,
            pack_layout,
            branches,
            branch_id,
            budgets: serde_json::json!({"max_depth":budget.max_depth,"total_bytes":budget.total_bytes,"single_ratio":budget.single_ratio}),
            blocked,
        })
    }
}

fn query_json(conn: &mut rusqlite::Connection, sql: &str) -> Result<Vec<serde_json::Value>, String> {
    query_json_params::<rusqlite::types::Value>(conn, sql, rusqlite::params_from_iter(std::iter::empty::<rusqlite::types::Value>()))
}

fn query_json_params<P: rusqlite::Params>(conn: &mut rusqlite::Connection, sql: &str, params: P) -> Result<Vec<serde_json::Value>, String> {
    let _ = params;
    let _ = sql;
    let _ = conn;
    Ok(Vec::new())
}
