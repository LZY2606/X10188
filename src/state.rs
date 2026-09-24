//! 供页面展示的聚合查询：pack 布局、delta DAG、对象预览、错误证据。

use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::Connection;
use serde_json::json;

use crate::engine::Engine;

impl Engine {
    pub fn state_json(&self, branch: &str) -> serde_json::Value {
        let conn = self.conn.lock().unwrap();
        let budget = self.get_budget();
        let sources = sources_json(&conn);
        let candidates = candidates_json(&conn, branch);
        let edges = edges_json(&conn, branch);
        let steps = steps_json(&conn, branch);
        let budget_used = total_used(&conn, branch);
        json!({
            "title": "包链显微镜",
            "branch": branch,
            "branches": branches_json(&conn),
            "budget": {
                "max_depth": budget.max_depth,
                "total_budget": budget.total_budget,
                "per_object_cap": budget.per_object_cap,
                "per_object_ratio": budget.per_object_ratio,
                "used": budget_used,
            },
            "sources": sources,
            "candidates": candidates,
            "edges": edges,
            "steps": steps,
        })
    }
}

fn branches_json(conn: &Connection) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut st = conn.prepare("SELECT id,note,created_at FROM branches ORDER BY id").unwrap();
    let rows = st
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "note": r.get::<_, Option<String>>(1).unwrap_or(None),
            }))
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    out
}

fn sources_json(conn: &Connection) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut st = conn
        .prepare(
            "SELECT s.id,s.kind,s.file_name,s.rel_path,s.size,s.sha256,s.paired_pack_rel,\
             s.pack_sha_match,s.trailer_ok,s.parse_error FROM sources s ORDER BY s.id",
        )
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "kind": r.get::<_, String>(1)?,
                "file_name": r.get::<_, String>(2)?,
                "rel_path": r.get::<_, String>(3)?,
                "size": r.get::<_, i64>(4)?,
                "sha256": r.get::<_, String>(5)?,
                "paired_pack_rel": r.get::<_, Option<String>>(6).unwrap_or(None),
                "pack_sha_match": r.get::<_, Option<i64>>(7).unwrap_or(None),
                "trailer_ok": r.get::<_, Option<i64>>(8).unwrap_or(None),
                "parse_error": r.get::<_, Option<String>>(9).unwrap_or(None),
            }))
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    out
}

fn total_used(conn: &Connection, branch: &str) -> u64 {
    conn.query_row(
        "SELECT COALESCE(SUM(out_len),0) FROM resolutions WHERE branch_id=?1 AND status='resolved'",
        rusqlite::params![branch],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0) as u64
}

fn preview_payload(b64: &str, max: usize) -> serde_json::Value {
    let data = crate::engine::base64_decode(b64).unwrap_or_default();
    let head = data.iter().take(max).copied().collect::<Vec<_>>();
    let printable = head
        .iter()
        .map(|&b| if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) { b as char } else { '·' })
        .collect::<String>();
    json!({
        "len": data.len(),
        "hex": hex::encode(head),
        "text": printable,
        "truncated": data.len() > max,
    })
}

fn candidates_json(conn: &Connection, branch: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut st = conn
        .prepare(
            "SELECT c.id,c.source_id,c.kind,c.entry_index,c.pack_offset,c.entry_range_start,\
             c.entry_range_end,c.zlib_range_start,c.zlib_range_end,c.claimed_oid,c.actual_oid,\
             c.obj_type,c.declared_size,c.inflated_len,c.ofs_base_offset,c.ref_base_oid,\
             c.entry_crc32,c.crc_ok,c.payload_b64,c.parse_error,c.parse_ok,\
             r.status,r.out_type,r.out_len,r.chain_len,r.error,r.blocked_chain \
             FROM candidates c LEFT JOIN resolutions r \
             ON r.candidate_id=c.id AND r.branch_id=?1 \
             WHERE c.kind IN ('pack_entry','loose') ORDER BY c.source_id,c.pack_offset,c.id",
        )
        .unwrap();
    let rows = st
        .query_map(rusqlite::params![branch], |r| {
            let payload_b64: String = r.get::<_, Option<String>>(18).unwrap_or(None).unwrap_or_default();
            let crc: Option<i64> = r.get(16).unwrap_or(None);
            let chain_json: Option<String> = r.get(26).unwrap_or(None);
            let blocked: Vec<i64> = chain_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "source_id": r.get::<_, i64>(1)?,
                "kind": r.get::<_, String>(2)?,
                "entry_index": r.get::<_, Option<i64>>(3).unwrap_or(None),
                "pack_offset": r.get::<_, Option<i64>>(4).unwrap_or(None),
                "entry_range": [r.get::<_, Option<i64>>(5).unwrap_or(None), r.get::<_, Option<i64>>(6).unwrap_or(None)],
                "zlib_range": [r.get::<_, Option<i64>>(7).unwrap_or(None), r.get::<_, Option<i64>>(8).unwrap_or(None)],
                "claimed_oid": r.get::<_, Option<String>>(9).unwrap_or(None),
                "actual_oid": r.get::<_, Option<String>>(10).unwrap_or(None),
                "obj_type": r.get::<_, String>(11)?,
                "declared_size": r.get::<_, i64>(12).unwrap_or(0),
                "inflated_len": r.get::<_, i64>(13).unwrap_or(0),
                "ofs_base_offset": r.get::<_, Option<i64>>(14).unwrap_or(None),
                "ref_base_oid": r.get::<_, Option<String>>(15).unwrap_or(None),
                "entry_crc32": crc.map(|v| format!("{:08x}", v as u32)),
                "crc_ok": r.get::<_, Option<i64>>(17).unwrap_or(None),
                "preview": preview_payload(&payload_b64, 160),
                "parse_error": r.get::<_, Option<String>>(19).unwrap_or(None),
                "parse_ok": r.get::<_, i64>(20)? != 0,
                "status": r.get::<_, Option<String>>(21).ok().flatten().unwrap_or_else(|| "new".to_string()),
                "out_type": r.get::<_, Option<String>>(22).unwrap_or(None),
                "out_len": r.get::<_, Option<i64>>(23).unwrap_or(None),
                "chain_len": r.get::<_, Option<i64>>(24).unwrap_or(None),
                "resolve_error": r.get::<_, Option<String>>(25).unwrap_or(None),
                "blocked_chain": blocked,
            }))
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    out
}

fn edges_json(conn: &Connection, branch: &str) -> Vec<serde_json::Value> {
    // delta -> base 边（ofs 与 ref），供 DAG/环可视化。
    let mut out = Vec::new();
    let mut st = conn
        .prepare(
            "SELECT c.id,c.source_id,c.ofs_base_offset,c.ref_base_oid,c.obj_type, \
             (SELECT p.id FROM candidates p WHERE p.kind='pack_entry' \
                AND p.source_id=c.source_id AND p.pack_offset=c.ofs_base_offset) AS ofs_base \
             FROM candidates c WHERE c.obj_type IN ('ofs-delta','ref-delta') \
             AND c.kind IN ('pack_entry','loose')",
        )
        .unwrap();
    let by_oid: HashMap<String, i64> = {
        let mut m = HashMap::new();
        let mut q = conn
            .prepare(
                "SELECT claimed_oid,id FROM candidates WHERE claimed_oid IS NOT NULL \
                 AND kind IN ('pack_entry','loose') ORDER BY id",
            )
            .unwrap();
        let rows = q
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .unwrap();
        for r in rows.flatten() {
            m.entry(r.0).or_insert(r.1);
        }
        m
    };
    let rows = st
        .query_map([], |r| {
            let id: i64 = r.get(0)?;
            let source_id: i64 = r.get(1)?;
            let ofs_base: Option<i64> = r.get(5).unwrap_or(None);
            let ref_oid: Option<String> = r.get(3).unwrap_or(None);
            let ty: String = r.get(4)?;
            let (kind, target) = if ty == "ofs-delta" {
                ("ofs", ofs_base.map(|v| v.to_string()))
            } else {
                ("ref", ref_oid.as_ref().and_then(|o| by_oid.get(o)).map(|v| v.to_string()))
            };
            Ok(json!({
                "from": id,
                "kind": kind,
                "to": target,
                "ref_oid": ref_oid,
                "source_id": source_id,
            }))
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    let _ = branch;
    out
}

fn steps_json(conn: &Connection, branch: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut st = conn
        .prepare(
            "SELECT s.resolution_id,s.step,s.base_candidate_id,s.base_oid,s.instr_start,\
             s.instr_end,s.input_len,s.output_len,s.check_ok,s.detail,r.candidate_id \
             FROM delta_steps s JOIN resolutions r ON r.id=s.resolution_id \
             WHERE r.branch_id=?1 ORDER BY r.candidate_id,s.step",
        )
        .unwrap();
    let rows = st
        .query_map(rusqlite::params![branch], |r| {
            Ok(json!({
                "candidate_id": r.get::<_, i64>(10)?,
                "step": r.get::<_, i64>(1)?,
                "base_candidate_id": r.get::<_, Option<i64>>(2).unwrap_or(None),
                "base_oid": r.get::<_, Option<String>>(3).unwrap_or(None),
                "instr_range": [r.get::<_, i64>(4)?, r.get::<_, i64>(5)?],
                "input_len": r.get::<_, i64>(6)?,
                "output_len": r.get::<_, i64>(7)?,
                "check_ok": r.get::<_, i64>(8)? != 0,
                "detail": r.get::<_, String>(9)?,
            }))
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    out
}

#[allow(dead_code)]
fn _arc_use(_a: Arc<()>) {}
