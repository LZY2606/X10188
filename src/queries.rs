//! Read-only JSON queries backing the web UI.

use crate::engine::{branch_id, Engine};
use crate::error::AppResult;
use rusqlite::params;
use serde_json::json;

pub async fn state(engine: &Engine, branch: &str) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let bid = branch_id(&conn, branch)?;
    let budget: (i64, i64, i64, i64, i64, i64, Option<String>) = conn.query_row(
        "SELECT depth_limit, depth_used, byte_budget, bytes_used, ratio_limit, paused, last_pause
         FROM budget WHERE branch_id=?1",
        params![bid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
    )?;
    let counts: (i64, i64, i64, i64) = conn.query_row(
        "SELECT
           SUM(status='complete'),
           SUM(status='blocked'),
           SUM(status='paused'),
           SUM(status='bad')
         FROM resolved WHERE branch_id=?1",
        params![bid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let mut branches = Vec::new();
    {
        let mut s = conn.prepare("SELECT id, name FROM branches ORDER BY id")?;
        let rows = s
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for r in rows.flatten() {
            branches.push(json!({"id": r.0, "name": r.1}));
        }
    }
    Ok(json!({
        "branch": branch,
        "branches": branches,
        "budget": {
            "depth_limit": budget.0,
            "depth_used": budget.1,
            "byte_budget": budget.2,
            "bytes_used": budget.3,
            "ratio_limit_mib": budget.4,
            "paused": budget.5 != 0,
            "last_pause": budget.6,
        },
        "counts": {
            "complete": counts.0,
            "blocked": counts.1,
            "paused": counts.2,
            "bad": counts.3,
        }
    }))
}

pub async fn sources(engine: &Engine) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let mut out = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, kind, file_name, content_sha256, size, import_seq, parse_fatal
         FROM sources ORDER BY import_seq",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "file_name": r.get::<_, String>(2)?,
            "sha256": r.get::<_, String>(3)?,
            "size": r.get::<_, i64>(4)?,
            "import_seq": r.get::<_, i64>(5)?,
            "parse_fatal": r.get::<_, Option<String>>(6)?,
        }))
    })?;
    for r in rows.flatten() {
        out.push(r);
    }
    drop(stmt);

    let mut ev_stmt = conn.prepare(
        "SELECT source_id, level, code, message, detail FROM source_evidence
         WHERE code NOT IN ('packsum','idx_packsum','idx_attached') ORDER BY id",
    )?;
    let mut evidence = Vec::new();
    let erows = ev_stmt.query_map([], |r| {
        Ok(json!({
            "source_id": r.get::<_, i64>(0)?,
            "level": r.get::<_, String>(1)?,
            "code": r.get::<_, String>(2)?,
            "message": r.get::<_, String>(3)?,
            "detail": r.get::<_, Option<String>>(4)?,
        }))
    })?;
    for r in erows.flatten() {
        evidence.push(r);
    }
    Ok(json!({ "sources": out, "evidence": evidence }))
}

pub async fn pack_layout(engine: &Engine, source_id: i64) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let head: (String, String, i64, Option<String>) = conn.query_row(
        "SELECT kind, file_name, size, parse_fatal FROM sources WHERE id=?1",
        params![source_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if head.0 != "pack" {
        return Err(crate::error::AppError::Conflict("source is not a pack".into()));
    }
    let mut entries = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, ordinal, header_offset, data_offset, end_offset, obj_type,
                declared_size, inflated_size, crc32, idx_crc32, ref_base, ofs_distance,
                base_header_offset, oid, claimed_oid, bad, bad_reason
         FROM candidates WHERE source_id=?1 ORDER BY ordinal",
    )?;
    let rows = stmt.query_map(params![source_id], |r| {
        Ok(json!({
            "candidate_id": r.get::<_, i64>(0)?,
            "ordinal": r.get::<_, i64>(1)?,
            "header_offset": r.get::<_, i64>(2)?,
            "data_offset": r.get::<_, i64>(3)?,
            "end_offset": r.get::<_, i64>(4)?,
            "type": r.get::<_, String>(5)?,
            "declared_size": r.get::<_, i64>(6)?,
            "inflated_size": r.get::<_, i64>(7)?,
            "crc32": format!("{:08x}", r.get::<_, i64>(8)? as u32),
            "idx_crc32": r.get::<_, Option<i64>>(9)?.map(|c| format!("{c:08x}")),
            "ref_base": r.get::<_, Option<String>>(10)?,
            "ofs_distance": r.get::<_, Option<i64>>(11)?,
            "base_header_offset": r.get::<_, Option<i64>>(12)?,
            "oid": r.get::<_, Option<String>>(13)?,
            "claimed_oid": r.get::<_, Option<String>>(14)?,
            "bad": r.get::<_, i64>(15)? != 0,
            "bad_reason": r.get::<_, Option<String>>(16)?,
        }))
    })?;
    for r in rows.flatten() {
        entries.push(r);
    }
    let mut evidence = Vec::new();
    let mut es = conn.prepare(
        "SELECT level, code, message, detail FROM source_evidence
         WHERE source_id=?1 ORDER BY id",
    )?;
    for r in es
        .query_map(params![source_id], |r| {
            Ok(json!({
                "level": r.get::<_, String>(0)?,
                "code": r.get::<_, String>(1)?,
                "message": r.get::<_, String>(2)?,
                "detail": r.get::<_, Option<String>>(3)?,
            }))
        })?
        .flatten()
    {
        evidence.push(r);
    }
    let fanout: Option<serde_json::Value> = conn
        .query_row(
            "SELECT detail FROM source_evidence e
             JOIN sources s ON s.id=e.source_id
             WHERE s.kind='idx' AND e.code='idx_fanout'
               AND e.detail IS NOT NULL
               AND EXISTS (
                 SELECT 1 FROM source_evidence p
                 WHERE p.source_id=?1 AND p.code='packsum'
                   AND p.detail IN (
                     SELECT d2.detail FROM source_evidence d2
                     WHERE d2.source_id=e.source_id AND d2.code='idx_packsum'))
             LIMIT 1",
            params![source_id],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    Ok(json!({
        "source_id": source_id,
        "file_name": head.1,
        "size": head.2,
        "parse_fatal": head.3,
        "entries": entries,
        "evidence": evidence,
        "fanout": fanout,
    }))
}

pub async fn objects(engine: &Engine, branch: &str) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let bid = branch_id(&conn, branch)?;
    let mut out = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT r.oid, r.status, r.obj_type, r.final_size, r.failure, r.candidate_id,
                (SELECT COUNT(*) FROM delta_steps d WHERE d.branch_id=r.branch_id AND d.oid=r.oid)
         FROM resolved r WHERE r.branch_id=?1
         ORDER BY CASE r.status WHEN 'complete' THEN 0 WHEN 'paused' THEN 1
                  WHEN 'blocked' THEN 2 ELSE 3 END, r.oid",
    )?;
    for r in stmt
        .query_map(params![bid], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "status": r.get::<_, String>(1)?,
                "type": r.get::<_, Option<String>>(2)?,
                "size": r.get::<_, Option<i64>>(3)?,
                "failure": r.get::<_, Option<String>>(4)?,
                "candidate_id": r.get::<_, Option<i64>>(5)?,
                "steps": r.get::<_, i64>(6)?,
            }))
        })?
        .flatten()
    {
        out.push(r);
    }
    Ok(json!({ "branch": branch, "objects": out }))
}

pub async fn object_detail(
    engine: &Engine,
    branch: &str,
    oid: &str,
) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let bid = branch_id(&conn, branch)?;
    let main: Option<(String, Option<String>, Option<i64>, Option<i64>, Option<String>, Option<String>, Option<String>, i64)> =
        conn.query_row(
            "SELECT status, obj_type, final_size, candidate_id, failure, resume_hint, content_path, check_ok
             FROM resolved WHERE branch_id=?1 AND oid=?2",
            params![bid, oid],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get::<_, i64>(7)?,
                ))
            },
        )
        .ok();

    let mut candidates = Vec::new();
    let mut cs = conn.prepare(
        "SELECT c.id, c.source_id, s.file_name, c.origin, c.obj_type, c.header_offset,
                c.declared_size, c.inflated_size, c.bad, c.bad_reason,
                COALESCE((SELECT 1 FROM pins p WHERE p.branch_id=?1 AND p.oid=?2
                          AND p.candidate_id=c.id),0)
         FROM candidates c JOIN sources s ON s.id=c.source_id
         WHERE c.oid=?2 ORDER BY c.bad, s.content_sha256, c.id",
    )?;
    for r in cs
        .query_map(params![bid, oid], |r| {
            Ok(json!({
                "candidate_id": r.get::<_, i64>(0)?,
                "source_id": r.get::<_, i64>(1)?,
                "file_name": r.get::<_, String>(2)?,
                "origin": r.get::<_, String>(3)?,
                "type": r.get::<_, String>(4)?,
                "header_offset": r.get::<_, Option<i64>>(5)?,
                "declared_size": r.get::<_, Option<i64>>(6)?,
                "inflated_size": r.get::<_, Option<i64>>(7)?,
                "bad": r.get::<_, i64>(8)? != 0,
                "bad_reason": r.get::<_, Option<String>>(9)?,
                "pinned": r.get::<_, i64>(10)? != 0,
            }))
        })?
        .flatten()
    {
        candidates.push(r);
    }

    let mut steps = Vec::new();
    let mut ds = conn.prepare(
        "SELECT step, base_oid, base_candidate_id, candidate_id, in_size, out_size,
                declared_base_size, declared_target_size, instr_count,
                instr_range_start, instr_range_end, check_ok, detail
         FROM delta_steps WHERE branch_id=?1 AND oid=?2 ORDER BY step",
    )?;
    for r in ds
        .query_map(params![bid, oid], |r| {
            Ok(json!({
                "step": r.get::<_, i64>(0)?,
                "base_oid": r.get::<_, Option<String>>(1)?,
                "base_candidate_id": r.get::<_, Option<i64>>(2)?,
                "candidate_id": r.get::<_, i64>(3)?,
                "in_size": r.get::<_, i64>(4)?,
                "out_size": r.get::<_, i64>(5)?,
                "declared_base_size": r.get::<_, i64>(6)?,
                "declared_target_size": r.get::<_, i64>(7)?,
                "instr_count": r.get::<_, i64>(8)?,
                "instr_range": [r.get::<_, i64>(9)?, r.get::<_, i64>(10)?],
                "check_ok": r.get::<_, i64>(11)? != 0,
                "instructions": serde_json::from_str::<serde_json::Value>(
                    &r.get::<_, String>(12)?).unwrap_or(serde_json::Value::Null),
            }))
        })?
        .flatten()
    {
        steps.push(r);
    }

    let mut blockers = Vec::new();
    let mut bs = conn.prepare(
        "SELECT ordinal, level, code, message, candidate_id, chain
         FROM blockers WHERE branch_id=?1 AND oid=?2 ORDER BY ordinal, id",
    )?;
    for r in bs
        .query_map(params![bid, oid], |r| {
            let chain_text: Option<String> = r.get(5)?;
            Ok(json!({
                "ordinal": r.get::<_, i64>(0)?,
                "level": r.get::<_, String>(1)?,
                "code": r.get::<_, String>(2)?,
                "message": r.get::<_, String>(3)?,
                "candidate_id": r.get::<_, Option<i64>>(4)?,
                "chain": chain_text.and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(serde_json::Value::Null),
            }))
        })?
        .flatten()
    {
        blockers.push(r);
    }

    let preview = if let Some((_, _, _, _, _, _, Some(rel), _)) = &main {
        if let Ok(bytes) = engine.store.read_content(rel) {
            Some(build_preview(&bytes))
        } else {
            None
        }
    } else {
        None
    };

    Ok(json!({
        "oid": oid,
        "status": main.as_ref().map(|m| m.0.clone()),
        "obj_type": main.as_ref().and_then(|m| m.1.clone()),
        "final_size": main.as_ref().and_then(|m| m.2),
        "chosen_candidate": main.as_ref().and_then(|m| m.3),
        "failure": main.as_ref().and_then(|m| m.4.clone()),
        "resume_hint": main.as_ref().and_then(|m| m.5.clone()),
        "check_ok": main.as_ref().map(|m| m.7 != 0),
        "candidates": candidates,
        "delta_steps": steps,
        "blockers": blockers,
        "preview": preview,
    }))
}

fn build_preview(bytes: &[u8]) -> serde_json::Value {
    let limit = 4096;
    let slice = &bytes[..bytes.len().min(limit)];
    let is_text = slice
        .iter()
        .take(2048)
        .all(|b| *b == b'\n' || *b == b'\r' || *b == b'\t' || (0x20..=0x7e).contains(b));
    if is_text {
        json!({
            "kind": "text",
            "truncated": bytes.len() > limit,
            "text": String::from_utf8_lossy(slice).to_string(),
            "total_size": bytes.len(),
        })
    } else {
        json!({
            "kind": "binary",
            "truncated": bytes.len() > limit,
            "hex": hex::encode(slice),
            "total_size": bytes.len(),
        })
    }
}

pub async fn dag(engine: &Engine, branch: &str) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let bid = branch_id(&conn, branch)?;
    let mut nodes = Vec::new();
    let mut ns = conn.prepare(
        "SELECT r.oid, r.status, COALESCE(r.obj_type,''), COALESCE(r.final_size,0)
         FROM resolved r WHERE r.branch_id=?1",
    )?;
    for r in ns
        .query_map(params![bid], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "status": r.get::<_, String>(1)?,
                "type": r.get::<_, String>(2)?,
                "size": r.get::<_, i64>(3)?,
            }))
        })?
        .flatten()
    {
        nodes.push(r);
    }

    // Edges come from delta_steps (only reconstructed edges exist there),
    // plus graph_edges for blocked/paused chains.
    let mut edges: Vec<serde_json::Value> = Vec::new();
    let mut es = conn.prepare(
        "SELECT DISTINCT d.oid, d.base_oid, 'delta' FROM delta_steps d
         WHERE d.branch_id=?1 AND d.base_oid IS NOT NULL",
    )?;
    for r in es
        .query_map(params![bid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .flatten()
    {
        edges.push(json!({ "from": r.1, "to": r.0, "kind": r.2 }));
    }
    drop(es);

    // graph_edges: map candidate -> resolved oid, base candidate -> oid.
    let mut gs = conn.prepare(
        "SELECT c.oid, g.kind, g.base_oid,
                (SELECT bc.oid FROM candidates bc WHERE bc.source_id=c.source_id
                 AND bc.header_offset=g.base_header_offset) AS ofs_base
         FROM graph_edges g JOIN candidates c ON c.id=g.candidate_id
         WHERE c.oid IS NOT NULL",
    )?;
    for r in gs
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .flatten()
    {
        let base = r.2.or(r.3);
        if let Some(base) = base {
            edges.push(json!({ "from": base, "to": r.0, "kind": r.1 }));
        }
    }
    edges.sort_by(|a, b| {
        a["to"].as_str().unwrap_or("").cmp(b["to"].as_str().unwrap_or(""))
    });
    edges.dedup();
    Ok(json!({ "nodes": nodes, "edges": edges }))
}

pub async fn blockers(engine: &Engine, branch: &str) -> AppResult<serde_json::Value> {
    let conn = engine.inner.lock().await;
    let bid = branch_id(&conn, branch)?;
    let mut out = Vec::new();
    let mut bs = conn.prepare(
        "SELECT b.oid, b.ordinal, b.level, b.code, b.message, b.candidate_id, b.chain
         FROM blockers b WHERE b.branch_id=?1 AND b.level='error'
         ORDER BY b.oid, b.ordinal",
    )?;
    for r in bs
        .query_map(params![bid], |r| {
            let chain_text: Option<String> = r.get(6)?;
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "ordinal": r.get::<_, i64>(1)?,
                "level": r.get::<_, String>(2)?,
                "code": r.get::<_, String>(3)?,
                "message": r.get::<_, String>(4)?,
                "candidate_id": r.get::<_, Option<i64>>(5)?,
                "chain": chain_text
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(serde_json::Value::Null),
            }))
        })?
        .flatten()
    {
        out.push(r);
    }
    Ok(json!({ "blockers": out }))
}
