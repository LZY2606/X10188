//! Read models used by the HTTP layer: pack layout, delta DAG, object
//! inventory, per-step forensics, conflicts and deletion impact.

use rusqlite::params;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::db::Db;

#[derive(Debug, Serialize)]
pub struct SourceView {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub bytes: i64,
    pub sha1: String,
    pub trailer_oid: String,
    pub note: String,
    pub entry_count: i64,
    pub dependents: i64,
}

#[derive(Debug, Serialize)]
pub struct ObjectView {
    pub entry_id: i64,
    pub source_id: i64,
    pub filename: String,
    pub obj_type: String,
    pub status: String,
    pub oid: Option<String>,
    pub claimed_oid: Option<String>,
    pub size: Option<i64>,
    pub declared_size: Option<i64>,
    pub depth: Option<i64>,
    pub raw_offset: Option<i64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub content_sha1: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DagNode {
    pub id: i64,
    pub label: String,
    pub oid: String,
    pub obj_type: String,
    pub status: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Serialize)]
pub struct DagEdge {
    pub from: i64,
    pub to: i64,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct DagView {
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

#[derive(Debug, Serialize)]
pub struct StepView {
    pub ordinal: i64,
    pub base_kind: String,
    pub base_ref: String,
    pub instr_start: i64,
    pub instr_end: i64,
    pub copy_ops: i64,
    pub insert_ops: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub expected_size: i64,
    pub check_ok: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DetailView {
    pub object: ObjectView,
    pub preview: String,
    pub hex_head: String,
    pub steps: Vec<StepView>,
    pub blocking_chain: serde_json::Value,
    pub pack_regions: Vec<RegionView>,
}

#[derive(Debug, Serialize)]
pub struct RegionView {
    pub offset: i64,
    pub data_start: i64,
    pub data_end: i64,
    pub obj_type: String,
    pub crc_ok: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConflictView {
    pub oid: String,
    pub candidates: Vec<ConflictCandidate>,
    pub pinned_source: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ConflictCandidate {
    pub entry_id: i64,
    pub source_id: i64,
    pub filename: String,
    pub raw_offset: Option<i64>,
    pub verified: bool,
    pub content_sha1: Option<String>,
}

impl Db {
    pub fn list_sources(&self) -> Vec<SourceView> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT s.id,s.kind,s.filename,s.bytes,s.sha1,s.trailer_oid,s.note,
                        (SELECT COUNT(*) FROM entries e WHERE e.source_id=s.id)
                 FROM sources s ORDER BY s.id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(SourceView {
                id: r.get(0)?, kind: r.get(1)?, filename: r.get(2)?, bytes: r.get(3)?,
                sha1: r.get(4)?, trailer_oid: r.get(5)?, note: r.get(6)?,
                entry_count: r.get(7)?, dependents: 0,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn list_objects(&self, branch_id: i64) -> Vec<ObjectView> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT e.id,e.source_id,s.filename,
                        COALESCE(r.obj_type,e.obj_type),COALESCE(r.status,'pending'),
                        r.oid,e.claimed_oid,r.size,e.declared_size,r.depth,
                        e.raw_offset,r.error_code,r.error_message,r.content_sha1
                 FROM entries e
                 JOIN sources s ON s.id=e.source_id
                 LEFT JOIN results r ON r.entry_id=e.id AND r.branch_id=?1
                 ORDER BY e.parse_seq,e.id",
            )
            .unwrap();
        stmt.query_map([branch_id], |r| {
            Ok(ObjectView {
                entry_id: r.get(0)?, source_id: r.get(1)?, filename: r.get(2)?,
                obj_type: r.get(3)?, status: r.get(4)?, oid: r.get(5)?,
                claimed_oid: r.get(6)?, size: r.get(7)?, declared_size: r.get(8)?,
                depth: r.get(9)?, raw_offset: r.get(10)?, error_code: r.get(11)?,
                error_message: r.get(12)?, content_sha1: r.get(13)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn dag(&self, branch_id: i64) -> DagView {
        let objs = self.list_objects(branch_id);
        // Group by source to lay out columns; order deterministic by (oid, source, entry).
        let mut source_order: Vec<i64> = objs.iter().map(|o| o.source_id).collect();
        source_order.sort_unstable();
        source_order.dedup();
        let x_for = |sid: i64| -> f64 {
            source_order.iter().position(|s| *s == sid).unwrap_or(0) as f64 * 220.0
        };
        let mut per_source_count: HashMap<i64, usize> = HashMap::new();
        let mut nodes = Vec::new();
        for o in &objs {
            let idx = *per_source_count.get(&o.source_id).unwrap_or(&0);
            per_source_count.insert(o.source_id, idx + 1);
            let label = o.oid.clone().or_else(|| o.claimed_oid.clone())
                .map(|h| h.chars().take(10).collect())
                .unwrap_or_else(|| format!("#{}", o.entry_id));
            nodes.push(DagNode {
                id: o.entry_id,
                label,
                oid: o.oid.clone().or_else(|| o.claimed_oid.clone()).unwrap_or_default(),
                obj_type: o.obj_type.clone(),
                status: o.status.clone(),
                x: x_for(o.source_id),
                y: idx as f64 * 90.0,
            });
        }

        let conn = self.conn.lock().unwrap();
        let mut edges = Vec::new();
        // Structural ofs edges + ref edges resolved through current branch results.
        let mut stmt = conn
            .prepare(
                "SELECT e.id,e.ofs_base_offset,e.source_id,e.ref_base_oid,e.obj_type
                 FROM entries e WHERE e.obj_type IN ('ofs-delta','ref-delta')",
            )
            .unwrap();
        struct ERaw(i64, Option<i64>, i64, Option<String>, String);
        let raws: Vec<ERaw> = stmt.query_map([], |r| {
            Ok(ERaw(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        }).unwrap().filter_map(|r| r.ok()).collect();
        drop(stmt);
        let oid_to_entry: HashMap<String, i64> = objs
            .iter()
            .filter(|o| o.oid.is_some() || o.claimed_oid.is_some())
            .map(|o| (o.oid.clone().or(o.claimed_oid.clone()).unwrap(), o.entry_id))
            .collect();
        let node_ids: HashSet<i64> = nodes.iter().map(|n| n.id).collect();
        for ERaw(id, ofs, src, refoid, typ) in raws {
            if typ == "ofs-delta" {
                if let Some(off) = ofs {
                    if let Some(target) = conn
                        .query_row(
                            "SELECT id FROM entries WHERE source_id=?1 AND raw_offset=?2",
                            params![src, off], |r| r.get::<_, i64>(0))
                        .ok()
                    {
                        if node_ids.contains(&id) && node_ids.contains(&target) {
                            edges.push(DagEdge { from: id, to: target, kind: "ofs".into() });
                        }
                    }
                }
            } else if let Some(oid) = refoid {
                if let Some(target) = oid_to_entry.get(&oid) {
                    edges.push(DagEdge { from: id, to: *target, kind: "ref".into() });
                } else {
                    // dangling external base: represent as missing node
                    nodes.push(DagNode {
                        id: -(oid.len() as i64), label: format!("missing:{oid}"),
                        oid: oid.clone(), obj_type: "missing".into(),
                        status: "missing".into(), x: x_for(src) + 110.0, y: -40.0,
                    });
                    edges.push(DagEdge { from: id, to: -(oid.len() as i64), kind: "ref-missing".into() });
                }
            }
        }
        DagView { nodes, edges }
    }
}

impl Db {
    pub fn object_detail(&self, branch_id: i64, entry_id: i64) -> Option<DetailView> {
        let objs = self.list_objects(branch_id);
        let object = objs.into_iter().find(|o| o.entry_id == entry_id)?;

        let mut preview = String::new();
        let mut hex_head = String::new();
        if object.status == "resolved" {
            let conn = self.conn.lock().unwrap();
            let content: Vec<u8> = conn
                .query_row(
                    "SELECT content FROM contents WHERE branch_id=?1 AND entry_id=?2",
                    params![branch_id, entry_id], |r| r.get(0))
                .ok()?;
            let kind = match object.obj_type.as_str() {
                "commit" => crate::gitfmt::ObjType::Commit,
                "tree" => crate::gitfmt::ObjType::Tree,
                "blob" => crate::gitfmt::ObjType::Blob,
                "tag" => crate::gitfmt::ObjType::Tag,
                _ => crate::gitfmt::ObjType::Blob,
            };
            preview = crate::gitfmt::preview_content(kind, &content, 4000);
            hex_head = content
                .iter()
                .take(64)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
        }

        let steps = {
            let conn = self.conn.lock().unwrap();
            let mut st = conn
                .prepare(
                    "SELECT ordinal,base_kind,base_ref,instr_start,instr_end,copy_ops,
                            insert_ops,input_len,output_len,expected_size,check_ok,detail
                     FROM steps WHERE branch_id=?1 AND entry_id=?2 ORDER BY ordinal",
                )
                .unwrap();
            st.query_map([branch_id, entry_id], |r| {
                Ok(StepView {
                    ordinal: r.get(0)?, base_kind: r.get(1)?, base_ref: r.get(2)?,
                    instr_start: r.get(3)?, instr_end: r.get(4)?, copy_ops: r.get(5)?,
                    insert_ops: r.get(6)?, input_len: r.get(7)?, output_len: r.get(8)?,
                    expected_size: r.get(9)?, check_ok: r.get::<_, i64>(10)? != 0,
                    detail: r.get(11)?,
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };

        let blocking_chain = {
            let conn = self.conn.lock().unwrap();
            let raw: Option<String> = conn
                .query_row(
                    "SELECT blocking_chain FROM results WHERE branch_id=?1 AND entry_id=?2",
                    params![branch_id, entry_id], |r| r.get(0))
                .ok()
                .flatten();
            serde_json::from_str(&raw.unwrap_or_else(|| "[]".into())).unwrap_or(serde_json::json!([]))
        };

        let pack_regions = {
            let conn = self.conn.lock().unwrap();
            let mut st = conn
                .prepare(
                    "SELECT raw_offset,data_start,data_end,obj_type,crc32_expected,crc32_actual
                     FROM entries WHERE source_id=(SELECT source_id FROM entries WHERE id=?1)
                     ORDER BY raw_offset",
                )
                .unwrap();
            st.query_map([entry_id], |r| {
                let exp: Option<i64> = r.get(4)?;
                let act: Option<i64> = r.get(5)?;
                Ok(RegionView {
                    offset: r.get(0)?, data_start: r.get(1)?, data_end: r.get(2)?,
                    obj_type: r.get(3)?,
                    crc_ok: exp.and_then(|e| act.map(|a| e == a)),
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };

        Some(DetailView { object, preview, hex_head, steps, blocking_chain, pack_regions })
    }

    /// All oids with more than one candidate source (duplicate / conflict).
    pub fn conflicts(&self, branch_id: i64) -> Vec<ConflictView> {
        let objs = self.list_objects(branch_id);
        let mut groups: HashMap<String, Vec<&ObjectView>> = HashMap::new();
        for o in &objs {
            let key = o.oid.clone().or_else(|| o.claimed_oid.clone());
            if let Some(k) = key {
                groups.entry(k).or_default().push(o);
            }
        }
        let mut out = Vec::new();
        for (oid, mut items) in groups {
            if items.len() < 2 {
                continue;
            }
            items.sort_by_key(|o| (o.source_id, o.entry_id));
            let pinned = self.pinned_source(branch_id, &oid);
            let candidates = items
                .iter()
                .map(|o| ConflictCandidate {
                    entry_id: o.entry_id,
                    source_id: o.source_id,
                    filename: o.filename.clone(),
                    raw_offset: o.raw_offset,
                    verified: o.status == "resolved"
                        && o.oid.as_deref() == Some(oid.as_str()),
                    content_sha1: o.content_sha1.clone(),
                })
                .collect();
            out.push(ConflictView { oid, candidates, pinned_source: pinned });
        }
        out.sort_by(|a, b| a.oid.cmp(&b.oid));
        out
    }

    pub fn pinned_source(&self, branch_id: i64, oid: &str) -> Option<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT source_id FROM pins WHERE branch_id=?1 AND oid=?2",
            params![branch_id, oid], |r| r.get::<_, i64>(0))
            .ok()
    }
}
