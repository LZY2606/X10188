//! Candidate table construction.
//!
//! Every possible provider of an object id is a *candidate*: a loose object, a
//! non-delta pack entry (whose oid is recomputed from content), a delta pack
//! entry (whose claimed oid is only known via an index), or an idx-only claim.
//! Ranking keys are content-derived (verification status, content hash, source
//! id, offset) so the final ordering never depends on import order.

use crate::db::{State, BRANCH_DEFAULT};
use crate::git::{object_id, GitType};
use rusqlite::params;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: i64,
    pub oid: String,
    pub kind: String,
    pub source_id: i64,
    pub pack_entry_id: Option<i64>,
    pub offset: Option<i64>,
    pub type_name: Option<String>,
    pub content_sha256: Option<String>,
    pub quality_rank: i64,
    pub parse_problem: bool,
    pub crc_matches: Option<bool>,
    pub idx_pack_mismatch: bool,
    pub note: Option<String>,
}

pub fn pack_node_key(source_id: i64, ordinal: i64) -> String {
    format!("pack:{source_id}:{ordinal}")
}
pub fn loose_node_key(source_id: i64) -> String {
    format!("loose:{source_id}")
}

struct PackRow {
    entry_id: i64,
    source_id: i64,
    ordinal: i64,
    offset: i64,
    type_name: String,
    content_sha256: String,
    inflated_path: Option<String>,
    crc32: i64,
    parse_error: Option<String>,
    size_ok: bool,
    adler_ok: bool,
}

struct LooseRow {
    source_id: i64,
    computed_oid: String,
    content_sha256: String,
}

struct IdxRow {
    idx_source_id: i64,
    oid: String,
    crc32: i64,
    offset: i64,
}

struct IdxInfo {
    source_id: i64,
    pack_checksum: String,
}

struct PackInfo {
    source_id: i64,
    trailer: String,
}

pub fn rebuild_candidates(state: &State) {
    let mut conn = state.db.lock().unwrap();
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Snapshot current resolved nodes so we can detect removed content.
    let mut prior: HashMap<(String, String), (String, Option<String>)> = HashMap::new();
    {
        let mut stmt = tx
            .prepare(
                "SELECT branch, node_key, content_sha256, candidate_id FROM resolved_node",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .unwrap();
        for r in rows.flatten() {
            prior.insert((r.0, r.1), (r.2.unwrap_or_default(), None));
        }
    }

    tx.execute("DELETE FROM candidate", []).ok();

    let packs: Vec<PackInfo> = tx
        .prepare("SELECT source_id, trailer_expected FROM pack_info")
        .unwrap()
        .query_map([], |r| {
            Ok(PackInfo {
                source_id: r.get(0)?,
                trailer: r.get(1)?,
            })
        })
        .unwrap()
        .flatten()
        .collect();
    let idx_infos: Vec<IdxInfo> = tx
        .prepare("SELECT source_id, pack_checksum FROM idx_info")
        .unwrap()
        .query_map([], |r| {
            Ok(IdxInfo {
                source_id: r.get(0)?,
                pack_checksum: r.get(1)?,
            })
        })
        .unwrap()
        .flatten()
        .collect();
    let loose: Vec<LooseRow> = tx
        .prepare("SELECT source_id, computed_oid, content_sha256 FROM loose_info")
        .unwrap()
        .query_map([], |r| {
            Ok(LooseRow {
                source_id: r.get(0)?,
                computed_oid: r.get(1)?,
                content_sha256: r.get(2)?,
            })
        })
        .unwrap()
        .flatten()
        .collect();
    let pack_rows: Vec<PackRow> = tx
        .prepare(
            "SELECT id, pack_source_id, ordinal, offset, type_name, content_sha256,
                    inflated_path, crc32, parse_error, size_matches_header, adler_ok
             FROM pack_entry ORDER BY pack_source_id, ordinal",
        )
        .unwrap()
        .query_map([], |r| {
            Ok(PackRow {
                entry_id: r.get(0)?,
                source_id: r.get(1)?,
                ordinal: r.get(2)?,
                offset: r.get(3)?,
                type_name: r.get(4)?,
                content_sha256: r.get(5)?,
                inflated_path: r.get(6)?,
                crc32: r.get(7)?,
                parse_error: r.get(8)?,
                size_ok: r.get::<_, i64>(9)? != 0,
                adler_ok: r.get::<_, i64>(10)? != 0,
            })
        })
        .unwrap()
        .flatten()
        .collect();
    let idx_rows: Vec<IdxRow> = tx
        .prepare("SELECT idx_source_id, oid, crc32, offset FROM idx_entry")
        .unwrap()
        .query_map([], |r| {
            Ok(IdxRow {
                idx_source_id: r.get(0)?,
                oid: r.get(1)?,
                crc32: r.get(2)?,
                offset: r.get(3)?,
            })
        })
        .unwrap()
        .flatten()
        .collect();

    // Map an idx file to its pack: exact trailer match wins; same-offset
    // fallback is used only when no checksum match exists.
    let mut idx_to_pack: HashMap<i64, Option<i64>> = HashMap::new();
    for idx in &idx_infos {
        let exact = packs.iter().find(|p| p.trailer == idx.pack_checksum);
        let mapped = if let Some(p) = exact {
            Some(p.source_id)
        } else {
            // Heuristic: pair by identical object offsets (same idx set found
            // in exactly one pack). Used only for display; flagged mismatch.
            None
        };
        idx_to_pack.insert(idx.source_id, mapped);
    }

    // Index entries grouped by the pack they describe.
    let mut idx_by_pack: BTreeMap<i64, Vec<&IdxRow>> = BTreeMap::new();
    let mut unmatched_idx: Vec<&IdxRow> = Vec::new();
    for row in &idx_rows {
        match idx_to_pack.get(&row.idx_source_id).copied().flatten() {
            Some(pack_sid) => idx_by_pack.entry(pack_sid).or_default().push(row),
            None => unmatched_idx.push(row),
        }
    }

    // ---- loose candidates (oid recomputed from inflated body) ----
    for l in &loose {
        insert_candidate(
            &tx,
            &l.computed_oid,
            "loose",
            l.source_id,
            None,
            Some(l.source_id),
            None,
            Some(l.source_id),
            None,
            None,
            Some(l.content_sha256.clone()),
            10,
            false,
            None,
            None,
            None,
            false,
            "loose object oid recomputed from content",
        );
    }

    // ---- pack entries ----
    let mut content_to_loose: HashMap<String, i64> = HashMap::new();
    for l in &loose {
        content_to_loose.insert(l.content_sha256.clone(), l.source_id);
    }

    for pr in &pack_rows {
        let node_key = pack_node_key(pr.source_id, pr.ordinal);
        let problem = pr.parse_error.is_some() || !pr.size_ok || !pr.adler_ok;
        let ty = GitType::from_pack_code(type_code_of(&pr.type_name)).unwrap_or(GitType::Blob);
        let index_rows: Vec<&&IdxRow> = idx_by_pack
            .get(&pr.source_id)
            .map(|v| v.iter().filter(|ir| ir.offset == pr.offset).collect())
            .unwrap_or_default();

        if ty.is_base() {
            // Recompute oid from inflated content (strip nothing: inflated
            // stream IS the object body for non-delta entries).
            let body = pr
                .inflated_path
                .as_ref()
                .and_then(|rel| std::fs::read(state.data_dir.join(rel)).ok());
            let computed = body.as_ref().map(|b| object_id(ty, b));
            let mut sha: Option<String> = Some(pr.content_sha256.clone());

            if let (Some(body), Some(oid)) = (body.as_ref(), computed) {
                let oid_hex = hex::encode(oid);
                let mut note = format!(
                    "oid recomputed from inflated {} body ({} bytes)",
                    ty.name(),
                    body.len()
                );
                let mut rank = 30i64;
                if problem {
                    rank = 90;
                }
                let (idx_src, idx_crc, crc_match, mismatch) =
                    pick_idx_evidence(&index_rows, pr.crc32, &idx_to_pack, &mut note);
                let _ = &mut sha;
                insert_candidate(
                    &tx,
                    &oid_hex,
                    "pack_base",
                    pr.source_id,
                    Some(pr.entry_id),
                    None,
                    Some(pr.offset),
                    idx_src,
                    idx_crc,
                    Some(pr.crc32),
                    Some(pr.content_sha256.clone()),
                    rank,
                    problem,
                    crc_match,
                    mismatch,
                    Some(&node_key),
                    &note,
                );
            } else if !index_rows.is_empty() {
                // Cannot recompute (inflate failure): fall back to idx claim,
                // clearly marked as unverified.
                for ir in index_rows {
                    let mut note = "oid taken from index; content could not be inflated".to_string();
                    let (idx_src, idx_crc, crc_match, mismatch) =
                        pick_idx_evidence(&[ir], pr.crc32, &idx_to_pack, &mut note);
                    insert_candidate(
                        &tx,
                        &ir.oid,
                        "pack_base",
                        pr.source_id,
                        Some(pr.entry_id),
                        None,
                        Some(pr.offset),
                        idx_src,
                        idx_crc,
                        Some(pr.crc32),
                        Some(pr.content_sha256.clone()),
                        95,
                        true,
                        crc_match,
                        mismatch,
                        Some(&node_key),
                        &note,
                    );
                }
            }
        } else {
            // Delta entries: the oid can only come from an index claim.
            if index_rows.is_empty() {
                // Thin/unnamed delta: register under a synthetic oid so it is
                // still visible and can be resolved once its chain leads to a
                // real base; candidate oid is empty placeholder keyed by node.
                insert_candidate(
                    &tx,
                    &format!("unresolved:{}", node_key),
                    "pack_delta",
                    pr.source_id,
                    Some(pr.entry_id),
                    None,
                    Some(pr.offset),
                    None,
                    None,
                    Some(pr.crc32),
                    Some(pr.content_sha256.clone()),
                    80,
                    problem,
                    None,
                    false,
                    Some(&node_key),
                    "delta has no index claim; awaiting base chain resolution",
                );
            } else {
                for ir in &index_rows {
                    let mut note = format!(
                        "oid claimed by index at offset {}; resolved through delta chain",
                        pr.offset
                    );
                    let (idx_src, idx_crc, crc_match, mismatch) =
                        pick_idx_evidence(&[ir], pr.crc32, &idx_to_pack, &mut note);
                    insert_candidate(
                        &tx,
                        &ir.oid,
                        "pack_delta",
                        pr.source_id,
                        Some(pr.entry_id),
                        None,
                        Some(pr.offset),
                        idx_src,
                        idx_crc,
                        Some(pr.crc32),
                        Some(pr.content_sha256.clone()),
                        if problem { 90 } else { 40 },
                        problem,
                        crc_match,
                        mismatch,
                        Some(&node_key),
                        &note,
                    );
                }
            }
        }
    }

    // ---- idx-only claims (index with no matching pack, or offsets not found)
    for ir in &unmatched_idx {
        insert_candidate(
            &tx,
            &ir.oid,
            "idx_only",
            ir.idx_source_id,
            None,
            None,
            Some(ir.offset),
            Some(ir.idx_source_id),
            Some(ir.crc32),
            None,
            None,
            70,
            false,
            None,
            true,
            None,
            "index claim without a pack whose checksum matches",
        );
    }
    // Claims present in an index that matches a pack but whose offset does not
    // correspond to any parsed entry.
    for (_pack_sid, rows) in &idx_by_pack {
        let known_offsets: HashSet<i64> = pack_rows
            .iter()
            .filter(|pr| Some(&pr.source_id) == std::option::Option::Some(&_pack_sid))
            .map(|pr| pr.offset)
            .collect();
        for ir in rows.iter() {
            if !known_offsets.contains(&ir.offset) {
                insert_candidate(
                    &tx,
                    &ir.oid,
                    "idx_only",
                    ir.idx_source_id,
                    None,
                    None,
                    Some(ir.offset),
                    Some(ir.idx_source_id),
                    Some(ir.crc32),
                    None,
                    None,
                    75,
                    false,
                    None,
                    false,
                    None,
                    "index offset does not correspond to any parsed pack entry",
                );
            }
        }
    }

    tx.commit().ok();
    drop(conn);
    invalidate_changed(state, prior);
}
