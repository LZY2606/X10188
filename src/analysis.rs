//! Orchestration layer between HTTP/CLI and the resolution engine.

use crate::engine::{Engine, RunReport};
use crate::importer::import_file;
use crate::store::Store;
use rusqlite::params;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

#[derive(Serialize, Default, Debug, Clone)]
pub struct ImportResult {
    pub kind: String,
    pub source_id: i64,
}

#[derive(Serialize, Debug, Clone)]
pub struct AnalysisOutcome {
    pub import: ImportResult,
    pub report: RunReport,
    pub budget_total_used: u64,
}

/// Analyze one uploaded file. Candidate rows are fully rebuilt from the
/// stored source set each time, and ordering is derived from source hashes
/// alone, so the import order cannot change final ranking.
pub fn analyze_after_import(
    guard: &Mutex<Store>,
    name: &str,
    data: &[u8],
) -> Result<AnalysisOutcome, String> {
    let mut store = guard.lock().unwrap();
    let (kind, source_id) = import_file(&mut store, name, data)?;
    crate::engine::rebuild_candidates(&mut store);

    // Only the default branch resolves automatically; other branches can
    // be refreshed explicitly via /api/branches/:name/reanalyze.
    let mut engine = Engine::new(&mut store, "default");
    let report = engine.run_all();
    engine.commit_budget();
    drop(engine);

    let used = store.budget().total_expanded_used;
    Ok(AnalysisOutcome {
        import: ImportResult {
            kind: format!("{:?}", kind).to_ascii_lowercase(),
            source_id,
        },
        report,
        budget_total_used: used,
    })
}

pub fn reanalyze_branch(guard: &Mutex<Store>, branch: &str) -> RunReport {
    let mut store = guard.lock().unwrap();
    let mut engine = Engine::new(&mut store, branch);
    let report = engine.run_all();
    engine.commit_budget();
    report
}

/// Retry resolution (typically after raising the budget or adding a base).
/// Only unresolved/paused objects are re-evaluated because `run_all`
/// resolves entries with no fresh memo; the stored resolution rows of
/// already-resolved objects are only rewritten with identical content.
pub fn retry(guard: &Mutex<Store>) -> RunReport {
    reanalyze_branch(guard, "default")
}

pub fn pin_candidate(guard: &Mutex<Store>, branch: &str, oid: &str, candidate_id: i64) {
    let mut store = guard.lock().unwrap();
    let bid = store.branch_id(branch).unwrap();
    store
        .conn
        .execute(
            "INSERT INTO pins(branch_id, oid, candidate_id, created_at)
             VALUES (?1,?2,?3,strftime('%s','now'))
             ON CONFLICT(branch_id, oid) DO UPDATE SET candidate_id=excluded.candidate_id",
            params![bid, oid, candidate_id],
        )
        .ok();
}

pub fn unpin(guard: &Mutex<Store>, branch: &str, oid: &str) {
    let mut store = guard.lock().unwrap();
    let bid = store.branch_id(branch).unwrap();
    store
        .conn
        .execute("DELETE FROM pins WHERE branch_id=?1 AND oid=?2", params![bid, oid])
        .ok();
}

/// A source is only deletable when no surviving object resolution still
/// depends on bytes originating from it. Returns the blocking objects.
pub fn delete_dependents(guard: &Mutex<Store>, source_id: i64) -> Result<usize, String> {
    let mut store = guard.lock().unwrap();
    let blockers = dependents_of_source(&mut store, source_id);
    if !blockers.is_empty() {
        return Err(format!(
            "{} object(s) still depend on this source: {}",
            blockers.len(),
            blockers.join(", ")
        ));
    }
    let path: String = store
        .conn
        .query_row(
            "SELECT stored_path FROM sources WHERE id=?1",
            params![source_id],
            |r| r.get(0),
        )
        .map_err(|_| "source not found".to_string())?;
    std::fs::remove_file(Path::new(&path)).ok();
    store
        .conn
        .execute("DELETE FROM sources WHERE id=?1", params![source_id])
        .ok();
    crate::engine::rebuild_candidates(&mut store);
    let mut engine = Engine::new(&mut store, "default");
    engine.run_all();
    engine.commit_budget();
    Ok(0)
}

pub fn dependents_preview(guard: &Mutex<Store>, source_id: i64) -> Vec<String> {
    let mut store = guard.lock().unwrap();
    dependents_of_source(&mut store, source_id)
}

fn dependents_of_source(store: &mut Store, source_id: i64) -> Vec<String> {
    let kind: String = store
        .conn
        .query_row(
            "SELECT kind FROM sources WHERE id=?1",
            params![source_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let mut out = Vec::new();
    match kind.as_str() {
        "pack" => {
            let mut stmt = store
                .conn
                .prepare(
                    "SELECT r.oid, r.status FROM resolutions r
                     JOIN candidates c ON c.id = r.candidate_id
                     JOIN entries e ON e.id = c.entry_id
                     JOIN packs p ON p.id = e.pack_id
                     WHERE p.source_id=?1 AND r.status='resolved'",
                )
                .unwrap();
            let rows = stmt
                .query_map(params![source_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .unwrap();
            for r in rows.flatten() {
                out.push(r.0);
            }
        }
        "loose" => {
            // Objects that resolved via ref-delta against this loose base.
            let mut stmt = store
                .conn
                .prepare(
                    "SELECT DISTINCT r.oid FROM resolutions r
                     JOIN delta_steps d ON d.oid = r.oid AND d.branch_id = r.branch_id
                     JOIN loose_objects l ON l.computed_oid = d.base_oid
                     WHERE l.source_id=?1 AND r.status='resolved'",
                )
                .unwrap();
            let rows = stmt
                .query_map(params![source_id], |r| r.get::<_, String>(0))
                .unwrap();
            for r in rows.flatten() {
                out.push(r);
            }
        }
        "idx" => {}
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}
