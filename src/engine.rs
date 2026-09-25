//! Reconstruction engine: delta chains, budgets, failure isolation and
//! incremental (subgraph-local) recomputation.

use crate::delta::{apply_delta, parse_delta};
use crate::gitobj::{object_id, zlib_decompress_bounded, ObjType};
use crate::loose::parse_loose;
use crate::pack::{parse_idx, parse_pack};
use crate::store::{add_evidence, get_entry, now, EntryRow};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u64,
    pub max_total_bytes: u64,
    pub max_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 32,
            max_total_bytes: 256 * 1024 * 1024,
            max_ratio: 100_000.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ImportSummary {
    pub source_id: i64,
    pub kind: String,
    pub digest: String,
    pub entries: usize,
    pub resolved: usize,
    pub paused: usize,
    pub blocked: usize,
    pub errored: usize,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepRecord {
    pub entry_id: i64,
    pub obj_type: String,
    pub kind: String, // ofs | ref
    pub base_ref: String,
    pub instr_start: usize,
    pub instr_end: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub copied: usize,
    pub inserted: usize,
    pub checks: Vec<String>,
}

fn err_status(kind: &str, msg: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "reason": kind, "detail": msg.into() })
}

fn is_status(conn: &Connection, id: i64, status: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM resolutions WHERE entry_id=?1 AND status=?2",
        params![id, status],
        |_| Ok(()),
    )
    .optional()
    .unwrap_or(None)
    .is_some()
}

fn resolved_oids(conn: &Connection) -> HashSet<String> {
    let mut s = HashSet::new();
    let mut stmt = conn
        .prepare("SELECT DISTINCT oid FROM resolutions WHERE status='ok' AND oid IS NOT NULL")
        .unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    for o in rows.flatten() {
        s.insert(o);
    }
    s
}

/// Entries resolving to `oid`, in deterministic order:
/// source digest, then entry offset, then entry id.
fn candidates_for_oid(conn: &Connection, oid: &str) -> Vec<i64> {
    let mut stmt = conn
        .prepare(
            "SELECT e.id FROM entries e
             JOIN resolutions r ON r.entry_id=e.id
             WHERE r.status='ok' AND r.oid=?1
             ORDER BY (SELECT digest FROM sources s WHERE s.id=e.source_id), e.offset, e.id",
        )
        .unwrap();
    stmt.query_map(params![oid], |r| r.get::<_, i64>(0))
        .unwrap()
        .flatten()
        .collect()
}

fn pinned_candidate(conn: &Connection, oid: &str) -> Option<i64> {
    conn.query_row(
        "SELECT entry_id FROM pins WHERE oid=?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
        params![oid],
        |r| r.get(0),
    )
    .optional()
    .unwrap_or(None)
}

use rusqlite::OptionalExtension;

fn record_edge(
    conn: &Connection,
    entry_id: i64,
    base_entry_id: Option<i64>,
    kind: &str,
    base_ref: String,
) {
    conn.execute("DELETE FROM edges WHERE entry_id=?1", params![entry_id])
        .unwrap();
    conn.execute(
        "INSERT INTO edges(entry_id, base_entry_id, base_kind, base_ref)
         VALUES(?1,?2,?3,?4)",
        params![entry_id, base_entry_id, kind, base_ref],
    )
    .unwrap();
}

/// Decompress the zlib payload of a pack entry, aborting as soon as the
/// inflated stream exceeds `cap` bytes ("size fraud discovered mid-inflate").
fn inflate_pack_payload(entry: &EntryRow, cap: u64) -> Result<Vec<u8>, String> {
    let hdr_len = (entry.data_offset - entry.offset) as usize;
    if hdr_len > entry.raw.len() {
        return Err("entry header offset exceeds raw length".into());
    }
    let payload = &entry.raw[hdr_len..];
    let mut d = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let mut in_pos = 0usize;
    loop {
        let end = (in_pos + 4096).min(payload.len());
        let status = d
            .decompress_vec(
                &payload[in_pos..end],
                &mut out,
                flate2::FlushDecompress::None,
            )
            .map_err(|e| format!("zlib decode error: {e}"))?;
        in_pos = d.total_in() as usize;
        if (out.len() as u64) > cap {
            return Err(format!(
                "size fraud: inflated bytes exceeded declared size {cap} mid-stream"
            ));
        }
        match status {
            flate2::Status::StreamEnd => {
                if in_pos != payload.len() {
                    return Err(format!(
                        "{} trailing bytes after entry zlib stream",
                        payload.len() - in_pos
                    ));
                }
                return Ok(out);
            }
            flate2::Status::Ok | flate2::Status::BufError => {
                if in_pos >= payload.len() && status == flate2::Status::Ok {
                    return Err(format!(
                        "zlib stream truncated ({} inflated bytes so far)",
                        out.len()
                    ));
                }
                if out.capacity() == out.len() {
                    out.reserve(4096);
                }
            }
        }
    }
}

/// Load the materialised content of a non-delta base entry.
fn load_base(conn: &Connection, entry: &EntryRow) -> Result<(Vec<u8>, ObjType), (String, String)> {
    let kind: String = conn
        .query_row(
            "SELECT kind FROM sources WHERE id=?1",
            params![entry.source_id],
            |r| r.get(0),
        )
        .map_err(|e| ("io", e.to_string()))?;
    if kind == "loose" {
        let loose = parse_loose(&entry.raw).map_err(|e| ("zlib_error", e))?;
        if loose.declared_size != loose.content.len() as u64 {
            return Err((
                "size_fraud".into(),
                format!(
                    "loose object declares {} bytes but contains {}",
                    loose.declared_size,
                    loose.content.len()
                ),
            ));
        }
        return Ok((loose.content, loose.obj_type));
    }
    let t = ObjType::from_name(&entry.obj_type).ok_or_else(|| {
        (
            "bad_type".into(),
            format!("unknown object type {}", entry.obj_type),
        )
    })?;
    if t.is_delta() {
        return Err(("bad_base".into(), "delta cannot be a chain base".into()));
    }
    let content = inflate_pack_payload(entry, entry.declared_size)
        .map_err(|e| (if e.starts_with("size fraud") { "size_fraud" } else { "zlib_error" }, e))?;
    if content.len() as u64 != entry.declared_size {
        return Err((
            "size_fraud".into(),
            format!(
                "entry at {} declares {} bytes but inflated to {}",
                entry.offset,
                entry.declared_size,
                content.len()
            ),
        ));
    }
    Ok((content, t))
}

struct ChainLink {
    entry: EntryRow,
    base_kind: String,
    base_ref: String,
}

/// Walk delta links from `target` up to a non-delta base.
fn build_chain(conn: &Connection, target: &EntryRow) -> Result<Vec<ChainLink>, serde_json::Value> {
    let mut links = Vec::new();
    let mut cur = target.clone();
    let mut seen: Vec<i64> = Vec::new();
    loop {
        let t = ObjType::from_name(&cur.obj_type).unwrap_or(ObjType::Blob);
        if !t.is_delta() {
            links.push(ChainLink {
                entry: cur,
                base_kind: "base".into(),
                base_ref: String::new(),
            });
            links.reverse();
            return Ok(links);
        }
        let pos = seen.iter().position(|id| *id == cur.id);
        if let Some(p) = pos {
            let cycle: Vec<i64> = seen[p..].iter().copied().chain(std::iter::once(cur.id)).collect();
            return Err(serde_json::json!({
                "reason": "cycle",
                "cycle": cycle,
                "detail": "delta chain forms a cycle"
            }));
        }
        seen.push(cur.id);
        if t == ObjType::OfsDelta {
            let dist = cur.ofs_distance.unwrap_or(0);
            if dist > cur.offset {
                let e = err_status(
                    "ofs_out_of_bounds",
                    format!("ofs distance {dist} exceeds entry offset {}", cur.offset),
                );
                record_edge(conn, cur.id, None, "ofs", dist.to_string());
                return Err(e);
            }
            let base_offset = cur.offset - dist;
            record_edge(conn, cur.id, None, "ofs", base_offset.to_string());
            let base = find_by_offset(conn, cur.source_id, base_offset);
            match base {
                Some(b) => {
                    links.push(ChainLink {
                        entry: cur,
                        base_kind: "ofs".into(),
                        base_ref: format!("offset@{base_offset}"),
                    });
                    cur = b;
                }
                None => {
                    return Err(serde_json::json!({
                        "reason": "missing_base",
                        "base_kind": "ofs",
                        "base_ref": base_offset.to_string(),
                        "chain": chain_view(conn, target.id),
                    }));
                }
            }
        } else {
            let oid = cur.ref_base.clone().unwrap_or_default();
            record_edge(conn, cur.id, None, "ref", oid.clone());
            let candidates = candidates_for_oid(conn, &oid);
            let pick = match pinned_candidate(conn, &oid) {
                Some(p) if candidates.contains(&p) => p,
                _ => *candidates.first().unwrap_or(&-1),
            };
            if pick < 0 {
                return Err(serde_json::json!({
                    "reason": "missing_base",
                    "base_kind": "ref",
                    "missing_oid": oid,
                    "chain": chain_view(conn, target.id),
                }));
            }
            conn.execute(
                "UPDATE edges SET base_entry_id=?1 WHERE entry_id=?2",
                params![pick, cur.id],
            )
            .unwrap();
            links.push(ChainLink {
                entry: cur,
                base_kind: "ref".into(),
                base_ref: oid,
            });
            cur = get_entry(conn, pick).unwrap().unwrap();
        }
    }
}

fn find_by_offset(conn: &Connection, source_id: i64, offset: u64) -> Option<EntryRow> {
    conn.query_row(
        "SELECT id, source_id, offset, obj_type, declared_size, data_offset, data_len,
                ofs_distance, ref_base, crc32, idx_crc32, raw
         FROM entries WHERE source_id=?1 AND offset=?2",
        params![source_id, offset as i64],
        row_to_entry,
    )
    .optional()
    .unwrap_or(None)
}

fn row_to_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        id: r.get(0)?,
        source_id: r.get(1)?,
        offset: r.get::<_, i64>(2)? as u64,
        obj_type: r.get(3)?,
        declared_size: r.get::<_, i64>(4)? as u64,
        data_offset: r.get::<_, i64>(5)? as u64,
        data_len: r.get::<_, i64>(6)? as u64,
        ofs_distance: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        ref_base: r.get(8)?,
        crc32: r.get::<_, Option<i64>>(9)?.map(|v| v as u32),
        idx_crc32: r.get::<_, Option<i64>>(10)?.map(|v| v as u32),
        raw: r.get(11)?,
    })
}

fn chain_view(conn: &Connection, target_id: i64) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut cur = target_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(cur) {
            break;
        }
        let row = conn
            .query_row(
                "SELECT e.id, e.source_id, e.offset, e.obj_type, r.status, r.oid
                 FROM entries e LEFT JOIN resolutions r ON r.entry_id=e.id WHERE e.id=?1",
                params![cur],
                |r| {
                    Ok(serde_json::json!({
                        "entry_id": r.get::<_,i64>(0)?,
                        "source_id": r.get::<_,i64>(1)?,
                        "offset": r.get::<_,i64>(2)?,
                        "obj_type": r.get::<_,String>(3)?,
                        "status": r.get::<_,Option<String>>(4)?.unwrap_or_default(),
                        "oid": r.get::<_,Option<String>>(5)?.unwrap_or_default(),
                    }))
                },
            )
            .optional()
            .unwrap_or(None);
        let Some(v) = row else { break };
        let base = conn
            .query_row(
                "SELECT base_entry_id, base_kind, base_ref FROM edges WHERE entry_id=?1",
                params![cur],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .unwrap_or(None);
        let mut v2 = v;
        if let Some((b, k, rf)) = base {
            v2["base_entry_id"] = json_opt(b);
            v2["base_kind"] = serde_json::Value::String(k);
            v2["base_ref"] = serde_json::Value::String(rf);
        }
        out.push(v2);
        match base.and_then(|(b, _, _)| b) {
            Some(b) => cur = b,
            None => break,
        }
    }
    out
}

fn json_opt(v: Option<i64>) -> serde_json::Value {
    match v {
        Some(x) => serde_json::Value::from(x),
        None => serde_json::Value::Null,
    }
}

fn get_partial(conn: &Connection, id: i64) -> Option<PartialState> {
    conn.query_row(
        "SELECT chain, next_idx, cur_type, buffer, steps, depth_used, bytes_used
         FROM partials WHERE entry_id=?1",
        params![id],
        |r| {
            Ok(PartialState {
                chain: serde_json::from_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                next_idx: r.get::<_, i64>(1)? as usize,
                cur_type: r.get::<_, String>(2)?,
                buffer: r.get(3)?,
                steps: r.get::<_, String>(4)?,
                depth_used: r.get::<_, i64>(5)? as u64,
                bytes_used: r.get::<_, i64>(6)? as u64,
            })
        },
    )
    .optional()
    .unwrap_or(None)
}

struct PartialState {
    chain: Vec<i64>,
    next_idx: usize,
    cur_type: String,
    buffer: Vec<u8>,
    steps: String,
    depth_used: u64,
    bytes_used: u64,
}

/// Resolve (or continue resolving) one entry. Bad objects are isolated in a
/// resolution row; other entries are unaffected.
pub fn resolve_entry(conn: &Connection, entry_id: i64, budget: Budget) -> String {
    let target = match get_entry(conn, entry_id) {
        Some(e) => e,
        None => return "missing".into(),
    };
    conn.execute(
        "INSERT INTO resolutions(entry_id, status, steps, updated_at)
         VALUES(?1,'paused','[]',?2)
         ON CONFLICT(entry_id) DO UPDATE SET status='paused', oid=NULL,
            depth=0, steps='[]', error=NULL, updated_at=?2",
        params![entry_id, now()],
    )
    .unwrap();

    // Resume from a saved budget-paused intermediate state.
    let (chain_ids, next_idx, cur_type, mut content, steps_json, mut depth_used, mut bytes_used) =
        if let Some(p) = get_partial(conn, entry_id) {
            (p.chain, p.next_idx, p.cur_type, p.buffer, p.steps, p.depth_used, p.bytes_used)
        } else {
            let links = match build_chain(conn, &target) {
                Ok(l) => l,
                Err(e) => return finish_failure(conn, entry_id, e),
            };
            let ids: Vec<i64> = links.iter().map(|l| l.entry.id).collect();
            let (base_content, base_type) = match load_base(conn, &links[0].entry) {
                Ok(v) => v,
                Err((kind, msg)) => {
                    add_evidence(conn, Some(links[0].entry.source_id), Some(links[0].entry.id), kind, &msg).ok();
                    let e = serde_json::json!({
                        "reason": "base_error",
                        "error_kind": kind,
                        "detail": msg,
                        "base_entry_id": links[0].entry.id,
                        "chain": chain_view(conn, entry_id),
                    });
                    return finish_failure(conn, entry_id, e);
                }
            };
            (ids, 1, base_type.name().to_string(), base_content, String::from("[]"), 0, 0)
        };

    let mut steps: Vec<StepRecord> = serde_json::from_str(&steps_json).unwrap_or_default();
    if depth_used == 0 {
        bytes_used += content.len() as u64;
    }

    let chain: Vec<EntryRow> = chain_ids.iter().filter_map(|id| get_entry(conn, *id)).collect();
    if chain.len() != chain_ids.len() {
        let e = err_status("missing_base", "chain entry disappeared (source deleted?)");
        return finish_failure(conn, entry_id, e);
    }

    let mut idx = next_idx;
    while idx < chain.len() {
        let entry = &chain[idx];
        depth_used += 1;
        if depth_used > budget.max_depth {
            return pause_here(conn, entry_id, &chain_ids, idx, &cur_type, &content, &steps,
                depth_used, bytes_used, "max_depth");
        }
        let delta_data = match inflate_pack_payload(entry, budget.max_total_bytes) {
            Ok(d) => d,
            Err(msg) => {
                let kind = if msg.starts_with("size fraud") { "size_fraud" } else { "zlib_error" };
                add_evidence(conn, Some(entry.source_id), Some(entry.id), kind, &msg).ok();
                let e = serde_json::json!({
                    "reason": kind, "detail": msg, "entry_id": entry.id,
                    "chain": chain_view(conn, entry_id)
                });
                return finish_failure(conn, entry_id, e);
            }
        };
        let parsed = match parse_delta(&delta_data) {
            Ok(p) => p,
            Err(msg) => {
                let e = serde_json::json!({
                    "reason": "bad_delta", "detail": msg, "entry_id": entry.id,
                    "chain": chain_view(conn, entry_id)
                });
                return finish_failure(conn, entry_id, e);
            }
        };
        let input_len = content.len();
        if parsed.result_size != entry.declared_size {
            let msg = format!(
                "delta header result size {} disagrees with pack declared size {}",
                parsed.result_size, entry.declared_size
            );
            add_evidence(conn, Some(entry.source_id), Some(entry.id), "size_fraud", &msg).ok();
            let e = serde_json::json!({
                "reason": "size_fraud", "detail": msg, "entry_id": entry.id,
                "chain": chain_view(conn, entry_id)
            });
            return finish_failure(conn, entry_id, e);
        }
        if parsed.result_size.saturating_add(bytes_used) > budget.max_total_bytes {
            return pause_here(conn, entry_id, &chain_ids, idx, &cur_type, &content, &steps,
                depth_used, bytes_used, "max_total_bytes");
        }
        let ratio = if input_len == 0 {
            if parsed.result_size > 0 { f64::INFINITY } else { 1.0 }
        } else {
            parsed.result_size as f64 / input_len as f64
        };
        if ratio > budget.max_ratio {
            return pause_here(conn, entry_id, &chain_ids, idx, &cur_type, &content, &steps,
                depth_used, bytes_used, "max_ratio");
        }
        let (out, copied, inserted) = match apply_delta(&delta_data, &parsed, &content) {
            Ok(v) => v,
            Err(msg) => {
                add_evidence(conn, Some(entry.source_id), Some(entry.id), "bad_delta", &msg).ok();
                let e = serde_json::json!({
                    "reason": "bad_delta", "detail": msg, "entry_id": entry.id,
                    "chain": chain_view(conn, entry_id)
                });
                return finish_failure(conn, entry_id, e);
            }
        };
        bytes_used += out.len() as u64;
        let instr_start = parsed.instr_offset;
        let instr_end = parsed.ops.last().map(|o| o.instr_end).unwrap_or(instr_start);
        let mut checks = vec![
            format!("base size {} matches input", parsed.base_size),
            format!("{} copy/insert ops within bounds", parsed.ops.len()),
            format!("result size {} matches declared", parsed.result_size),
        ];
        if let (Some(c), Some(ic)) = (entry.crc32, entry.idx_crc32) {
            checks.push(if c == ic {
                "crc32 matches index".into()
            } else {
                "crc32 MISMATCH with index".into()
            });
        }
        steps.push(StepRecord {
            entry_id: entry.id,
            obj_type: cur_type.clone(),
            kind: entry.obj_type.clone(),
            base_ref: entry
                .ofs_distance
                .map(|d| format!("ofs-{d}"))
                .or_else(|| entry.ref_base.clone())
                .unwrap_or_default(),
            instr_start,
            instr_end,
            input_len,
            output_len: out.len(),
            copied,
            inserted,
            checks,
        });
        content = out;
        idx += 1;
    }

    // Chain complete: the partial intermediate was never exposed as an object.
    conn.execute("DELETE FROM partials WHERE entry_id=?1", params![entry_id]).unwrap();

    if content.len() as u64 != target.declared_size {
        let msg = format!(
            "final object size {} disagrees with declared {}",
            content.len(),
            target.declared_size
        );
        let e = serde_json::json!({
            "reason": "size_fraud", "detail": msg, "entry_id": entry_id,
            "chain": chain_view(conn, entry_id)
        });
        return finish_failure(conn, entry_id, e);
    }

    let oid = object_id(ObjType::from_name(&cur_type).unwrap_or(ObjType::Blob), &content);
    let steps_str = serde_json::to_string(&steps).unwrap_or_else(|_| "[]".into());
    let tx = conn.unchecked_transaction().unwrap();
    tx.execute(
        "INSERT INTO contents(entry_id, content) VALUES(?1,?2)
         ON CONFLICT(entry_id) DO UPDATE SET content=excluded.content",
        params![entry_id, content],
    )
    .unwrap();
    tx.execute(
        "UPDATE resolutions SET status='ok', oid=?1, depth=?2, steps=?3,
             error=NULL, attempts=attempts+1, updated_at=?4 WHERE entry_id=?5",
        params![oid, depth_used, steps_str, now(), entry_id],
    )
    .unwrap();
    // Index oid cross-check.
    let idx_row: Option<(String, i64)> = tx
        .query_row(
            "SELECT oid, source_id FROM idx_entries WHERE offset=?1 LIMIT 1",
            params![target.offset],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
        .unwrap_or(None);
    if let Some((idx_oid, idx_source)) = idx_row {
        if idx_oid != oid {
            let msg = format!(
                "index says object at offset {} is {idx_oid}, recomputed id is {oid}",
                target.offset
            );
            dedupe_evidence(&tx, Some(idx_source), Some(entry_id), "idx_oid_mismatch", &msg);
        }
    }
    // Duplicate oid: multiple candidate sources for the same object.
    let others: Vec<(i64, i64)> = tx
        .prepare(
            "SELECT r.entry_id, e.source_id FROM resolutions r JOIN entries e ON e.id=r.entry_id
             WHERE r.oid=?1 AND r.status='ok' AND r.entry_id<>?2",
        )
        .unwrap()
        .query_map(params![oid, entry_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })
        .unwrap()
        .flatten()
        .collect();
    for (other_id, other_src) in others {
        let same = tx
            .query_row(
                "SELECT (SELECT content FROM contents WHERE entry_id=?1) =
                        (SELECT content FROM contents WHERE entry_id=?2)",
                params![other_id, entry_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            != 0;
        let (kind, msg) = if same {
            ("duplicate_oid", format!("oid {oid} available from entries {other_id} and {entry_id}"))
        } else {
            ("oid_content_conflict", format!(
                "entries {other_id} and {entry_id} both hash to {oid} but differ in content"))
        };
        dedupe_evidence(&tx, Some(other_src), Some(entry_id), kind, &msg);
    }
    tx.commit().unwrap();
    "ok".into()
}
