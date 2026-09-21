//! In-memory graph of candidate objects for one analysis pass.

use std::collections::HashMap;

use rusqlite::OptionalExtension;

use crate::git::pack::{inflate_at, HARD_INFLATE_CAP};
use crate::git::{read_ofs_varint, read_size_varint, GitType};
use crate::store::Store;

/// A candidate location for one oid.
#[derive(Debug, Clone)]
pub struct CandidateNode {
    pub id: i64,
    pub oid: String,
    pub source_id: i64,
    pub locator: String,
    pub kind_name: String,
    pub offset: i64,
    pub raw_size: i64,
    pub inflate_size: i64,
    pub crc_ok: Option<bool>,
    pub parse_error: Option<String>,
    pub base_ref: Option<String>,
    pub base_offset: Option<i64>,
    pub stored_path: String,
    pub source_kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    /// candidate id -> node
    pub nodes: HashMap<i64, CandidateNode>,
    /// oid -> candidate ids, ordered by deterministic rank (pin first).
    pub by_oid: HashMap<String, Vec<i64>>,
    /// (pack source id, object offset) -> candidate id (ofs-delta targets).
    pub by_pack_offset: HashMap<(i64, i64), i64>,
}

impl Graph {
    /// Deterministic candidate rank: lower wins. Source id, then offset, then
    /// candidate id; parse errors sort last. Independent of import order.
    pub fn rank(node: &CandidateNode) -> (i64, i64, i64, bool) {
        (
            node.source_id,
            node.offset,
            node.id,
            node.parse_error.is_some(),
        )
    }

    pub fn best_for(&self, oid: &str) -> Option<&CandidateNode> {
        let ids = self.by_oid.get(oid)?;
        ids.first().and_then(|id| self.nodes.get(id))
    }
}

impl Store {
    /// Load every candidate, applying pinned overrides for this branch.
    pub fn load_graph(&self, branch: &str) -> rusqlite::Result<Graph> {
        let mut graph = Graph::default();
        {
            let conn = self.db.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT o.id, o.oid, o.source_id, o.locator, o.kind_name,
                        o.\"offset\", o.raw_size, o.inflate_size, o.crc_ok,
                        o.parse_error, o.base_ref, o.base_offset,
                        s.stored_path, s.kind
                 FROM objects o JOIN sources s ON s.id = o.source_id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(CandidateNode {
                    id: r.get(0)?,
                    oid: r.get(1)?,
                    source_id: r.get(2)?,
                    locator: r.get(3)?,
                    kind_name: r.get(4)?,
                    offset: r.get(5)?,
                    raw_size: r.get(6)?,
                    inflate_size: r.get(7)?,
                    crc_ok: r.get::<_, Option<i64>>(8)?.map(|v| v != 0),
                    parse_error: r.get(9)?,
                    base_ref: r.get(10)?,
                    base_offset: r.get(11)?,
                    stored_path: r.get(12)?,
                    source_kind: r.get(13)?,
                })
            })?;
            for node in rows {
                let node = node?;
                if !node.oid.is_empty() {
                    graph.by_oid.entry(node.oid.clone()).or_default().push(node.id);
                }
                if node.source_kind == "pack" {
                    graph
                        .by_pack_offset
                        .insert((node.source_id, node.offset), node.id);
                }
                graph.nodes.insert(node.id, node);
            }
        }

        for (oid, bucket) in graph.by_oid.iter_mut() {
            bucket.sort_by_key(|id| {
                let n = graph.nodes.get(id).unwrap();
                Graph::rank(n)
            });
            if let Some(pinned) = self.pinned_candidate(branch, oid)? {
                if let Some(pos) = bucket.iter().position(|id| *id == pinned) {
                    bucket.remove(pos);
                    bucket.insert(0, pinned);
                }
            }
        }
        Ok(graph)
    }

    pub fn pinned_candidate(
        &self,
        branch: &str,
        oid: &str,
    ) -> rusqlite::Result<Option<i64>> {
        let conn = self.db.lock().unwrap();
        conn.query_row(
            "SELECT candidate_id FROM pins WHERE branch=?1 AND oid=?2",
            rusqlite::params![branch, oid],
            |r| r.get(0),
        )
        .optional()
    }

    /// Read and inflate the raw bytes for one candidate.
    pub fn candidate_payload(
        &self,
        node: &CandidateNode,
    ) -> Result<(GitType, Vec<u8>), String> {
        let abs = self.data_dir.join(&node.stored_path);
        let bytes = std::fs::read(&abs)
            .map_err(|e| format!("read {} failed: {e}", abs.display()))?;
        match node.source_kind.as_str() {
            "loose" => {
                let raw = crate::git::inflate_limited(&bytes, HARD_INFLATE_CAP)?;
                let nul = raw
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or("loose object missing NUL")?;
                let header = std::str::from_utf8(&raw[..nul])
                    .map_err(|e| format!("loose header: {e}"))?;
                let name = header.split(' ').next().unwrap_or("");
                let kind = match name {
                    "commit" => GitType::Commit,
                    "tree" => GitType::Tree,
                    "blob" => GitType::Blob,
                    "tag" => GitType::Tag,
                    other => return Err(format!("unknown loose type {other}")),
                };
                Ok((kind, raw[nul + 1..].to_vec()))
            }
            "pack" => {
                let start = node.offset as usize;
                let first = *bytes
                    .get(start)
                    .ok_or_else(|| format!("pack offset {} missing", node.offset))?;
                let code = (first >> 4) & 0x07;
                let kind = GitType::from_code(code)
                    .ok_or_else(|| format!("bad type code {code}"))?;
                let (_size, extra) =
                    read_size_varint(&bytes[start + 1..], first)?;
                let mut p = start + 1 + extra;
                if matches!(kind, GitType::OfsDelta) {
                    let f = bytes[p];
                    let (_d, e) = read_ofs_varint(&bytes[p + 1..], f)?;
                    p += 1 + e;
                } else if matches!(kind, GitType::RefDelta) {
                    p += 20;
                }
                let (payload, _consumed) =
                    inflate_at(&bytes, p, HARD_INFLATE_CAP)?;
                Ok((kind, payload))
            }
            other => Err(format!("unsupported source kind {other}")),
        }
    }
}
