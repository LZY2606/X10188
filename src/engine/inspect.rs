use crate::db::Db;
use crate::hexutil::{content_summary, to_hex};
use crate::idx::parse_idx;
use rusqlite::params;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub struct PackView {
    pub pack_id: i64,
    pub filename: String,
    pub version: i64,
    pub object_count: i64,
    pub trailer_oid: String,
    pub computed_checksum: String,
    pub checksum_ok: bool,
    pub matched: bool,
    pub idx_filename: Option<String>,
    pub idx_checksum_ok: bool,
    pub mismatch_note: Option<String>,
    pub fanout: Option<Vec<FanoutBucket>>,
}

#[derive(Serialize)]
pub struct FanoutBucket {
    pub prefix: String,
    pub cumulative: i64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Preview {
    Text { text: String },
    Binary { hex: String },
}

#[derive(Serialize)]
pub struct StepView {
    pub seq: i64,
    pub base_oid: Option<String>,
    pub instr_start: i64,
    pub instr_end: i64,
    pub in_len: i64,
    pub out_len: i64,
    pub check_ok: bool,
    pub note: String,
}

#[derive(Serialize)]
pub struct CandidateView {
    pub node_id: i64,
    pub source_filename: String,
    pub pack_offset: Option<i64>,
    pub status: String,
    pub pinned: bool,
}

#[derive(Serialize)]
pub struct NodeView {
    pub id: i64,
    pub oid: String,
    pub short_oid: String,
    pub kind: String,
    pub final_kind: Option<String>,
    pub status: String,
    pub error_code: Option<String>,
    pub error_note: Option<String>,
    pub source_filename: String,
    pub source_kind: String,
    pub pack_id: Option<i64>,
    pub pack_offset: Option<i64>,
    pub zlib_start: Option<i64>,
    pub entry_end: Option<i64>,
    pub declared_size: Option<i64>,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub depth: Option<i64>,
    pub idx_crc: Option<i64>,
    pub computed_crc: Option<i64>,
    pub crc_ok: Option<bool>,
    pub raw_summary: Option<String>,
    pub resolved_summary: Option<String>,
    pub resolved_preview: Option<Preview>,
    pub duplicate_sources: Vec<String>,
    pub candidates: Vec<CandidateView>,
    pub steps: Vec<StepView>,
    pub evidence: Vec<EvidenceView>,
    pub blocking_chain: Vec<ChainLink>,
}

#[derive(Serialize)]
pub struct EvidenceView {
    pub level: String,
    pub code: String,
    pub message: String,
    pub at_offset: Option<i64>,
}

#[derive(Serialize)]
pub struct ChainLink {
    pub node_id: i64,
    pub oid: String,
    pub kind: String,
    pub status: String,
    pub missing_oid: Option<String>,
}

#[derive(Serialize)]
pub struct EdgeView {
    pub from_node: i64,
    pub to_node: Option<i64>,
    pub to_oid: String,
    pub kind: String,
}

#[derive(Serialize)]
pub struct BudgetView {
    pub max_depth: i64,
    pub total_bytes: i64,
    pub single_ratio: i64,
    pub used_total_bytes: i64,
    pub single_bytes: i64,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub packs: Vec<PackView>,
    pub nodes: Vec<NodeView>,
    pub edges: Vec<EdgeView>,
    pub sources: Vec<SourceView>,
    pub budget: BudgetView,
    pub counts: StatusCounts,
}

#[derive(Serialize, Default)]
pub struct StatusCounts {
    pub total: usize,
    pub resolved: usize,
    pub blocked: usize,
    pub error: usize,
    pub paused: usize,
    pub pending: usize,
}

#[derive(Serialize)]
pub struct SourceView {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub size: i64,
    pub linked_oid: Option<String>,
    pub pack_id: Option<i64>,
}

fn q(conn: &rusqlite::Connection, sql: &str) -> String {
    conn.query_row(sql, [], |r| r.get::<_, String>(0)).unwrap_or_default()
}

pub fn snapshot(db: &Db) -> Snapshot {
    let conn = db.0.lock().unwrap();

    let max_depth: i64 = q(&conn, "SELECT v FROM kv WHERE k='budget_max_depth'").parse().unwrap_or(0);
    let total_bytes: i64 = q(&conn, "SELECT v FROM kv WHERE k='budget_total_bytes'").parse().unwrap_or(0);
    let single_ratio: i64 = q(&conn, "SELECT v FROM kv WHERE k='budget_single_ratio'").parse().unwrap_or(0);
    let used: i64 = q(&conn, "SELECT v FROM kv WHERE k='budget_used_total_bytes'").parse().unwrap_or(0);
    let budget = BudgetView {
        max_depth,
        total_bytes,
        single_ratio,
        used_total_bytes: used,
        single_bytes: total_bytes * single_ratio / 100,
    };

    let mut sources = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id,filename,kind,size,linked_oid,pack_id FROM sources ORDER BY filename,id")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(SourceView {
                    id: r.get(0)?,
                    filename: r.get(1)?,
                    kind: r.get(2)?,
                    size: r.get(3)?,
                    linked_oid: r.get(4)?,
                    pack_id: r.get(5)?,
                })
            })
            .unwrap();
        for r in rows.flatten() {
            sources.push(r);
        }
    }

    let mut packs = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT p.id,s.filename,p.version,p.object_count,p.trailer_oid,
                        p.computed_checksum,p.matched,p.idx_source_id,p.idx_checksum_ok,
                        p.mismatch_note,s2.filename,s2.stored_path
                 FROM packs p
                 JOIN sources s ON s.id=p.source_id
                 LEFT JOIN sources s2 ON s2.id=p.idx_source_id
                 ORDER BY p.id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                ))
            })
            .unwrap();
        for row in rows.flatten() {
            let (id, fname, ver, cnt, trailer, computed, matched, idx_src, idx_ok, note,
                idx_fname, idx_path) = row;
            let fanout = idx_path.as_ref().and_then(|p| {
                fs::read(p).ok().and_then(|b| parse_idx(&b).ok()).map(|idx| {
                    idx.fanout
                        .iter()
                        .enumerate()
                        .filter(|(i, c)| *i == 0 || **c != idx.fanout[i.saturating_sub(1)])
                        .map(|(i, c)| FanoutBucket {
                            prefix: format!("{:02x}", i),
                            cumulative: *c as i64,
                        })
                        .collect::<Vec<_>>()
                })
            });
            packs.push(PackView {
                pack_id: id,
                filename: fname,
                version: ver,
                object_count: cnt,
                checksum_ok: trailer == computed,
                trailer_oid: trailer,
                computed_checksum: computed,
                matched: matched != 0,
                idx_filename: idx_fname,
                idx_checksum_ok: idx_ok != 0,
                mismatch_note: note,
                fanout,
            });
            let _ = idx_src;
        }
    }

    let mut edges = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT from_node,to_node,to_oid,kind FROM edges ORDER BY from_node")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(EdgeView {
                    from_node: r.get(0)?,
                    to_node: r.get(1)?,
                    to_oid: r.get(2)?,
                    kind: r.get(3)?,
                })
            })
            .unwrap();
        for r in rows.flatten() {
            edges.push(r);
        }
    }

    let node_ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM nodes ORDER BY id").unwrap();
        stmt.query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    };

    let mut counts = StatusCounts::default();
    let mut nodes = Vec::new();
    for id in node_ids {
        let v = build_node(&conn, id);
        match v.status.as_str() {
            "resolved" => counts.resolved += 1,
            "blocked" => counts.blocked += 1,
            "error" => counts.error += 1,
            "paused" => counts.paused += 1,
            _ => counts.pending += 1,
        }
        nodes.push(v);
    }
    counts.total = nodes.len();

    Snapshot {
        packs,
        nodes,
        edges,
        sources,
        budget,
        counts,
    }
}

fn stage_data(conn: &rusqlite::Connection, node_id: i64, stage: &str) -> Option<(String, Vec<u8>)> {
    conn.query_row(
        &format!(
            "SELECT kind,data FROM objects WHERE node_id=?1 AND stage='{}'",
            stage
        ),
        params![node_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )
    .ok()
}

fn build_node(conn: &rusqlite::Connection, id: i64) -> NodeView {
    let (
        oid,
        kind,
        final_kind,
        status,
        error_code,
        error_note,
        source_id,
        source_kind,
        source_filename,
        pack_id,
        pack_offset,
        zlib_start,
        entry_end,
        declared_size,
        base_offset,
        base_oid,
        depth,
        idx_crc,
        computed_crc,
        crc_ok_i,
    ) = conn
        .query_row(
            "SELECT n.oid,n.kind,n.final_kind,n.status,n.error_code,n.error_note,
                    n.source_id,s.kind,s.filename,n.pack_id,n.pack_offset,n.zlib_start,
                    n.entry_end,n.declared_size,n.base_offset,n.base_oid,n.resolve_depth,
                    n.idx_crc,n.computed_crc,n.crc_ok
             FROM nodes n JOIN sources s ON s.id=n.source_id WHERE n.id=?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, Option<i64>>(9)?,
                    r.get::<_, Option<i64>>(10)?,
                    r.get::<_, Option<i64>>(11)?,
                    r.get::<_, Option<i64>>(12)?,
                    r.get::<_, Option<i64>>(13)?,
                    r.get::<_, Option<i64>>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, Option<i64>>(16)?,
                    r.get::<_, Option<i64>>(17)?,
                    r.get::<_, Option<i64>>(18)?,
                    r.get::<_, Option<i64>>(19)?,
                ))
            },
        )
        .unwrap();

    let raw = stage_data(conn, id, "raw");
    let resolved = stage_data(conn, id, "resolved");
    let raw_summary = raw.as_ref().map(|(k, d)| content_summary(k, d));
    let resolved_summary = resolved.as_ref().map(|(k, d)| content_summary(k, d));
    let resolved_preview = resolved.as_ref().map(|(k, d)| make_preview(k, d));

    let mut dup = Vec::new();
    if !oid.is_empty() {
        let mut stmt = conn
            .prepare(
                "SELECT s.filename FROM nodes n JOIN sources s ON s.id=n.source_id
                 WHERE n.oid=?1 AND n.id!=?2 ORDER BY s.filename,n.id",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![oid, id], |r| r.get::<_, String>(0))
            .unwrap();
        for r in rows.flatten() {
            dup.push(r);
        }
    }

    let mut candidates = Vec::new();
    if !oid.is_empty() {
        let mut stmt = conn
            .prepare(
                "SELECT n.id,s.filename,n.pack_offset,n.status,n.pinned FROM nodes n
                 JOIN sources s ON s.id=n.source_id
                 WHERE n.oid=?1 ORDER BY n.pinned DESC,s.filename,n.pack_offset,n.id",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![oid], |r| {
                Ok(CandidateView {
                    node_id: r.get(0)?,
                    source_filename: r.get(1)?,
                    pack_offset: r.get(2)?,
                    status: r.get(3)?,
                    pinned: r.get::<_, i64>(4)? != 0,
                })
            })
            .unwrap();
        for r in rows.flatten() {
            candidates.push(r);
        }
    }

    let mut steps = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT st.seq,
                        (SELECT oid FROM nodes WHERE id=st.base_node),
                        st.instr_start,st.instr_end,st.in_len,st.out_len,st.check_ok,st.note
                 FROM steps st WHERE st.node_id=?1 ORDER BY st.seq",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![id], |r| {
                Ok(StepView {
                    seq: r.get(0)?,
                    base_oid: r.get(1)?,
                    instr_start: r.get(2)?,
                    instr_end: r.get(3)?,
                    in_len: r.get(4)?,
                    out_len: r.get(5)?,
                    check_ok: r.get::<_, i64>(6)? != 0,
                    note: r.get(7)?,
                })
            })
            .unwrap();
        for r in rows.flatten() {
            steps.push(r);
        }
    }

    let mut evidence = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT level,code,message,at_offset FROM evidence
                 WHERE node_id=?1 ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![id], |r| {
                Ok(EvidenceView {
                    level: r.get(0)?,
                    code: r.get(1)?,
                    message: r.get(2)?,
                    at_offset: r.get(3)?,
                })
            })
            .unwrap();
        for r in rows.flatten() {
            evidence.push(r);
        }
    }

    let blocking_chain = if status == "blocked" || status == "paused" || status == "error" {
        build_chain(conn, id)
    } else {
        Vec::new()
    };

    NodeView {
        id,
        short_oid: if oid.len() >= 12 { oid[..12].to_string() } else { oid.clone() },
        oid,
        kind,
        final_kind,
        status,
        error_code,
        error_note,
        source_filename,
        source_kind,
        pack_id,
        pack_offset,
        zlib_start,
        entry_end,
        declared_size,
        base_offset,
        base_oid,
        depth,
        idx_crc,
        computed_crc,
        crc_ok: crc_ok_i.map(|v| v != 0),
        raw_summary,
        resolved_summary,
        resolved_preview,
        duplicate_sources: dup,
        candidates,
        steps,
        evidence,
        blocking_chain,
    }
}

fn make_preview(kind: &str, data: &[u8]) -> Preview {
    let textish = matches!(kind, "commit" | "tag")
        || data
            .iter()
            .take(2048)
            .all(|&b| b == b'\n' || b == b'\t' || (32..=126).contains(&b));
    if textish {
        Preview::Text {
            text: String::from_utf8_lossy(&data[..data.len().min(4096)]).into_owned(),
        }
    } else {
        Preview::Binary {
            hex: to_hex(&data[..data.len().min(128)]),
        }
    }
}

fn build_chain(conn: &rusqlite::Connection, start: i64) -> Vec<ChainLink> {
    let mut chain = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = start;
    loop {
        if !seen.insert(cur) {
            break;
        }
        let row: (String, String, String) = conn
            .query_row(
                "SELECT oid,kind,status FROM nodes WHERE id=?1",
                params![cur],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let (missing_oid, next): (String, Option<i64>) = conn
            .query_row(
                "SELECT to_oid,to_node FROM edges WHERE from_node=?1 LIMIT 1",
                params![cur],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((String::new(), None));
        chain.push(ChainLink {
            node_id: cur,
            oid: if row.0.is_empty() { format!("node#{}", cur) } else { row.0 },
            kind: row.1,
            status: row.2,
            missing_oid: if next.is_none() && !missing_oid.is_empty() {
                Some(missing_oid)
            } else {
                None
            },
        });
        match next {
            Some(n) => cur = n,
            None => break,
        }
    }
    chain
}

#[derive(Serialize, Default)]
pub struct PinReport {
    pub oid: String,
    pub pinned_node: i64,
    pub reset_nodes: Vec<i64>,
}

pub fn pin_candidate(db: &Db, node_id: i64) -> PinReport {
    let mut conn = db.0.lock().unwrap();
    let tx = conn.transaction().unwrap();
    let oid: String = tx
        .query_row("SELECT oid FROM nodes WHERE id=?1", params![node_id], |r| {
            r.get(0)
        })
        .unwrap();

    tx.execute("UPDATE nodes SET pinned=0 WHERE oid=?1", params![oid])
        .unwrap();
    tx.execute("UPDATE nodes SET pinned=1 WHERE id=?1", params![node_id])
        .unwrap();

    let reset = reset_descendants(&tx, &oid);
    tx.commit().unwrap();

    PinReport {
        oid,
        pinned_node: node_id,
        reset_nodes: reset,
    }
}

pub fn unpin_oid(db: &Db, oid: &str) {
    let mut conn = db.0.lock().unwrap();
    conn.execute("UPDATE nodes SET pinned=0 WHERE oid=?1", params![oid])
        .unwrap();
}

fn reset_descendants(tx: &rusqlite::Transaction, oid: &str) -> Vec<i64> {
    let mut frontier = vec![oid.to_string()];
    let mut reset = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while let Some(target) = frontier.pop() {
        let mut stmt = tx
            .prepare(
                "SELECT DISTINCT n.id,n.oid FROM nodes n
                 WHERE n.id IN (
                    SELECT from_node FROM edges WHERE to_oid=?1
                 ) AND n.status IN ('resolved','blocked','paused','error')",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![target], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap();
        let mut found = Vec::new();
        for r in rows.flatten() {
            found.push(r);
        }
        drop(stmt);
        for (nid, noid) in found {
            if seen.insert(nid) {
                tx.execute("DELETE FROM steps WHERE node_id=?1", params![nid]).unwrap();
                tx.execute("DELETE FROM evidence WHERE node_id=?1", params![nid]).unwrap();
                tx.execute(
                    "DELETE FROM objects WHERE node_id=?1 AND stage='resolved'",
                    params![nid],
                ).unwrap();
                tx.execute(
                    "UPDATE nodes SET status='pending',error_code=NULL,error_note=NULL,
                     final_kind=NULL,resolved_kind=NULL WHERE id=?1",
                    params![nid],
                ).unwrap();
                reset.push(nid);
                frontier.push(noid);
            }
        }
    }
    reset
}

#[derive(Serialize, Default)]
pub struct DeleteCheck {
    pub source_id: i64,
    pub filename: String,
    pub can_delete: bool,
    pub dependent_objects: Vec<DependentObject>,
}

#[derive(Serialize)]
pub struct DependentObject {
    pub node_id: i64,
    pub oid: String,
    pub status: String,
    pub relation: String,
}

pub fn delete_source_check(db: &Db, source_id: i64) -> DeleteCheck {
    let conn = db.0.lock().unwrap();
    let filename: String = conn
        .query_row(
            "SELECT filename FROM sources WHERE id=?1",
            params![source_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    let mut dependent_objects = Vec::new();

    let own_nodes: Vec<(i64, String, String)> = {
        let mut stmt = conn
            .prepare("SELECT id,oid,status FROM nodes WHERE source_id=?1")
            .unwrap();
        stmt.query_map(params![source_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    };

    for (nid, oid, status) in &own_nodes {
        dependent_objects.push(DependentObject {
            node_id: *nid,
            oid: if oid.is_empty() {
                format!("node#{}", nid)
            } else {
                oid.clone()
            },
            status: status.clone(),
            relation: "contained by source".into(),
        });
        let mut stmt = conn
            .prepare(
                "SELECT n.id,n.oid,n.status FROM edges e
                 JOIN nodes n ON n.id=e.from_node
                 WHERE e.to_node=?1 AND n.source_id!=?2",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![nid, source_id], |r| {
                Ok(DependentObject {
                    node_id: r.get(0)?,
                    oid: {
                        let o: String = r.get(1)?;
                        if o.is_empty() {
                            "?".into()
                        } else {
                            o
                        }
                    },
                    status: r.get(2)?,
                    relation: "delta built on object from this source".into(),
                })
            })
            .unwrap();
        for r in rows.flatten() {
            dependent_objects.push(r);
        }
    }

    DeleteCheck {
        source_id,
        filename,
        can_delete: dependent_objects.is_empty(),
        dependent_objects,
    }
}

#[derive(Serialize, Default)]
pub struct DeleteReport {
    pub deleted_source: i64,
    pub removed_nodes: usize,
    pub blocked_after: Vec<String>,
}

pub fn delete_source(db: &Db, source_id: i64, force: bool) -> DeleteReport {
    let check = delete_source_check(db, source_id);
    if !force && !check.can_delete {
        return DeleteReport::default();
    }
    let mut conn = db.0.lock().unwrap();
    let tx = conn.transaction().unwrap();
    let (stored, kind): (String, String) = tx
        .query_row(
            "SELECT stored_path,kind FROM sources WHERE id=?1",
            params![source_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();

    let removed_nodes = tx
        .execute("DELETE FROM nodes WHERE source_id=?1", params![source_id])
        .unwrap();
    if kind == "idx" {
        tx.execute(
            "UPDATE packs SET idx_source_id=NULL,matched=0,
             mismatch_note='index removed' WHERE idx_source_id=?1",
            params![source_id],
        )
        .unwrap();
    }
    tx.execute("DELETE FROM sources WHERE id=?1", params![source_id])
        .unwrap();
    tx.commit().unwrap();
    let _ = fs::remove_file(stored);

    DeleteReport {
        deleted_source: source_id,
        removed_nodes,
        blocked_after: Vec::new(),
    }
}
