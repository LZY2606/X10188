use crate::store::{
    branch_id, get_budget, list_branches, list_candidates, list_issues, list_sources, Budget,
};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct ResolvedRow {
    pub ckey: String,
    pub oid: Option<String>,
    pub status: String,
    pub obj_type: Option<String>,
    pub content_len: Option<i64>,
    pub depth: Option<i64>,
    pub charged_bytes: Option<i64>,
    pub reason: Option<String>,
    pub evidence: Option<String>,
    pub base_ckey: Option<String>,
    pub chain_json: String,
}

#[derive(Serialize, Clone)]
pub struct StepRowApi {
    pub ordinal: i64,
    pub ckey: String,
    pub delta_kind: Option<String>,
    pub base_ckey: String,
    pub base_oid: Option<String>,
    pub input_len: i64,
    pub output_len: i64,
    pub instruction_start: i64,
    pub instruction_end: i64,
    pub copies: i64,
    pub inserts: i64,
    pub check_ok: bool,
}

#[derive(Serialize)]
pub struct EdgeApi {
    pub from: String,
    pub to: String,
}

#[derive(Serialize)]
pub struct BranchState {
    pub name: String,
    pub budget: Budget,
    pub objects: Vec<ObjectView>,
    pub edges: Vec<EdgeApi>,
}

#[derive(Serialize)]
pub struct CandidateView {
    pub ckey: String,
    pub source_id: i64,
    pub source_kind: String,
    pub oid: Option<String>,
    pub obj_type: String,
    pub offset: Option<i64>,
    pub end_offset: Option<i64>,
    pub declared_size: i64,
    pub actual_size: Option<i64>,
    pub ofs_distance: Option<i64>,
    pub ref_base: Option<String>,
    pub crc_ok: Option<bool>,
    pub parse_error: Option<String>,
    pub preview: String,
}

#[derive(Serialize)]
pub struct ObjectView {
    pub key: String,
    pub oid: Option<String>,
    pub status: String,
    pub obj_type: Option<String>,
    pub content_len: Option<i64>,
    pub depth: Option<i64>,
    pub reason: Option<String>,
    pub evidence: Option<String>,
    pub chain: Vec<serde_json::Value>,
    pub steps: Vec<StepRowApi>,
    pub candidates: Vec<CandidateView>,
}

#[derive(Serialize)]
pub struct AppStateJson {
    pub branches: Vec<(i64, String)>,
    pub current_branch: String,
    pub sources: Vec<crate::store::SourceRow>,
    pub issues: Vec<crate::store::IssueRow>,
    pub packs: Vec<serde_json::Value>,
    pub idxs: Vec<serde_json::Value>,
    pub branch: BranchState,
}

fn list_resolved(conn: &Connection, branch: i64) -> rusqlite::Result<Vec<ResolvedRow>> {
    let mut stmt = conn.prepare(
        "SELECT ckey, oid, status, obj_type, content_len, depth, charged_bytes, reason, evidence, base_ckey, chain_json
         FROM resolved WHERE branch_id=? ORDER BY ckey",
    )?;
    let rows = stmt.query_map(params![branch], |r| {
        Ok(ResolvedRow {
            ckey: r.get(0)?,
            oid: r.get(1)?,
            status: r.get(2)?,
            obj_type: r.get(3)?,
            content_len: r.get(4)?,
            depth: r.get(5)?,
            charged_bytes: r.get(6)?,
            reason: r.get(7)?,
            evidence: r.get(8)?,
            base_ckey: r.get(9)?,
            chain_json: r.get::<_, String>(10)?,
        })
    })?;
    rows.collect()
}

fn list_steps(conn: &Connection, branch: i64) -> rusqlite::Result<Vec<StepRowApi>> {
    let mut stmt = conn.prepare(
        "SELECT ordinal, ckey, delta_kind, base_ckey, base_oid, input_len, output_len,
                instruction_start, instruction_end, copies, inserts, check_ok
         FROM steps WHERE branch_id=? ORDER BY ckey, ordinal",
    )?;
    let rows = stmt.query_map(params![branch], |r| {
        Ok(StepRowApi {
            ordinal: r.get(0)?,
            ckey: r.get(1)?,
            delta_kind: r.get(2)?,
            base_ckey: r.get(3)?,
            base_oid: r.get(4)?,
            input_len: r.get(5)?,
            output_len: r.get(6)?,
            instruction_start: r.get(7)?,
            instruction_end: r.get(8)?,
            copies: r.get(9)?,
            inserts: r.get(10)?,
            check_ok: r.get::<_, i64>(11)? != 0,
        })
    })?;
    rows.collect()
}

fn preview_bytes(data: Option<&Vec<u8>>) -> String {
    match data {
        Some(b) if !b.is_empty() => {
            let cut = b.len().min(2048);
            match std::str::from_utf8(&b[..cut]) {
                Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') => {
                    let mut v = s.to_string();
                    if b.len() > cut {
                        v.push_str("\n…[截断]");
                    }
                    v
                }
                _ => {
                    let hex: String = b[..cut].iter().take(64).map(|x| format!("{:02x}", x)).collect();
                    format!("<binary {} bytes> {}", b.len(), hex)
                }
            }
        }
        _ => String::new(),
    }
}

pub fn build_state(conn: &Connection, branch_name: &str) -> rusqlite::Result<AppStateJson> {
    let branch = branch_id(conn, branch_name)?;
    let budget = get_budget(conn, branch)?;
    let candidates = list_candidates(conn)?;
    let resolved = list_resolved(conn, branch)?;
    let steps = list_steps(conn, branch)?;

    let mut by_oid: BTreeMap<Option<String>, Vec<&crate::store::CandidateRow>> = BTreeMap::new();
    let mut by_ckey: BTreeMap<String, Vec<&crate::store::CandidateRow>> = BTreeMap::new();
    for c in &candidates {
        by_ckey.entry(c.ckey.clone()).or_default().push(c);
    }
    let resolved_by_ckey: BTreeMap<&str, &ResolvedRow> =
        resolved.iter().map(|r| (r.ckey.as_str(), r)).collect();
    for c in &candidates {
        let group_oid = if let Some(r) = resolved_by_ckey.get(c.ckey.as_str()) {
            r.oid.clone().or_else(|| c.oid.clone())
        } else {
            c.oid.clone()
        };
        by_oid.entry(group_oid).or_default().push(c);
    }

    let steps_by_ckey: BTreeMap<&str, Vec<&StepRowApi>> = {
        let mut m: BTreeMap<&str, Vec<&StepRowApi>> = BTreeMap::new();
        for s in &steps {
            m.entry(s.ckey.as_str()).or_default().push(s);
        }
        m
    };

    let mut objects: Vec<ObjectView> = Vec::new();
    let mut keys_seen = std::collections::HashSet::new();
    for r in &resolved {
        keys_seen.insert(r.ckey.clone());
        let mut cands: Vec<&crate::store::CandidateRow> =
            by_ckey.get(&r.ckey).map(|v| v.iter().copied().collect()).unwrap_or_default();
        cands.sort_by(|a, b| {
            a.source_id
                .cmp(&b.source_id)
                .then_with(|| a.offset.unwrap_or(-1).cmp(&b.offset.unwrap_or(-1)))
                .then_with(|| a.ckey.cmp(&b.ckey))
        });
        let chain: Vec<serde_json::Value> =
            serde_json::from_str(&r.chain_json).unwrap_or_else(|_| Vec::new());
        objects.push(ObjectView {
            key: r.ckey.clone(),
            oid: r.oid.clone(),
            status: r.status.clone(),
            obj_type: r.obj_type.clone(),
            content_len: r.content_len,
            depth: r.depth,
            reason: r.reason.clone(),
            evidence: r.evidence.clone(),
            chain,
            steps: steps_by_ckey
                .get(r.ckey.as_str())
                .map(|v| v.iter().map(|s| (**s).clone()).collect())
                .unwrap_or_default(),
            candidates: cands
                .into_iter()
                .map(|c| CandidateView {
                    ckey: c.ckey.clone(),
                    source_id: c.source_id,
                    source_kind: c.source_kind.clone(),
                    oid: c.oid.clone(),
                    obj_type: c.obj_type.clone(),
                    offset: c.offset,
                    end_offset: c.end_offset,
                    declared_size: c.declared_size,
                    actual_size: c.actual_size,
                    ofs_distance: c.ofs_distance,
                    ref_base: c.ref_base.clone(),
                    crc_ok: c.crc_ok,
                    parse_error: c.parse_error.clone(),
                    preview: preview_bytes(c.content.as_ref()),
                })
                .collect(),
        });
    }
    for c in &candidates {
        if !keys_seen.contains(&c.ckey) {
            objects.push(ObjectView {
                key: c.ckey.clone(),
                oid: c.oid.clone(),
                status: "new".into(),
                obj_type: Some(c.obj_type.clone()),
                content_len: c.actual_size,
                depth: None,
                reason: None,
                evidence: None,
                chain: Vec::new(),
                steps: vec![],
                candidates: vec![CandidateView {
                    ckey: c.ckey.clone(),
                    source_id: c.source_id,
                    source_kind: c.source_kind.clone(),
                    oid: c.oid.clone(),
                    obj_type: c.obj_type.clone(),
                    offset: c.offset,
                    end_offset: c.end_offset,
                    declared_size: c.declared_size,
                    actual_size: c.actual_size,
                    ofs_distance: c.ofs_distance,
                    ref_base: c.ref_base.clone(),
                    crc_ok: c.crc_ok,
                    parse_error: c.parse_error.clone(),
                    preview: preview_bytes(c.content.as_ref()),
                }],
            });
        }
    }

    let mut edges = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT ckey, base_ckey FROM relink WHERE branch_id=? ORDER BY ckey, base_ckey",
        )?;
        let rows = stmt.query_map(params![branch], |r| {
            Ok(EdgeApi {
                from: r.get(0)?,
                to: r.get(1)?,
            })
        })?;
        for e in rows {
            edges.push(e?);
        }
    }

    let mut packs = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT p.source_id, s.filename, p.parse_json, p.idx_id, p.checksum_ok, p.object_count
             FROM packs p JOIN sources s ON s.id=p.source_id ORDER BY p.source_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "source_id": r.get::<_, i64>(0)?,
                "filename": r.get::<_, String>(1)?,
                "parse": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(2)?).unwrap_or(serde_json::json!({})),
                "idx_id": r.get::<_, Option<i64>>(3)?,
                "checksum_ok": r.get::<_, Option<i64>>(4)?,
                "object_count": r.get::<_, Option<i64>>(5)?,
            }))
        })?;
        for r in rows {
            packs.push(r?);
        }
    }
    let mut idxs = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT i.source_id, s.filename, i.fanout_json, i.pack_id, i.checksum_ok, i.parse_json
             FROM idxs i JOIN sources s ON s.id=i.source_id ORDER BY i.source_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "source_id": r.get::<_, i64>(0)?,
                "filename": r.get::<_, String>(1)?,
                "fanout": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(2)?).unwrap_or(serde_json::json!([])),
                "pack_id": r.get::<_, Option<i64>>(3)?,
                "checksum_ok": r.get::<_, Option<i64>>(4)?,
                "parse": serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(5)?).unwrap_or(serde_json::json!({})),
            }))
        })?;
        for r in rows {
            idxs.push(r?);
        }
    }

    Ok(AppStateJson {
        branches: list_branches(conn)?,
        current_branch: branch_name.to_string(),
        sources: list_sources(conn)?,
        issues: list_issues(conn)?,
        packs,
        idxs,
        branch: BranchState {
            name: branch_name.to_string(),
            budget,
            objects,
            edges,
        },
    })
}
