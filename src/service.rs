use crate::db::{now_secs, Store};
use crate::model::{Budgets, Budgets as B};
use crate::resolver;
use rusqlite::params;
use serde_json::{json, Value};

pub fn default_budgets() -> Budgets {
    B::default()
}

pub fn create_branch(store: &Store, name: &str) -> Result<i64, String> {
    let db = store.conn.lock().unwrap();
    db.execute(
        "INSERT INTO branches(name, created_at) VALUES(?1,?2)",
        params![name, now_secs()],
    )
    .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

pub fn list_branches(store: &Store) -> Value {
    let db = store.conn.lock().unwrap();
    let mut stmt = db.prepare("SELECT id,name,created_at FROM branches ORDER BY id").unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "created_at": r.get::<_, i64>(2)?,
            }))
        })
        .unwrap();
    Value::Array(rows.flatten().collect())
}

pub fn pin(store: &Store, branch_id: i64, oid: &str, candidate_id: i64) -> Result<(), String> {
    {
        let db = store.conn.lock().unwrap();
        let exists: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE id=?1",
                params![candidate_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if exists == 0 {
            return Err("candidate does not exist".into());
        }
        db.execute(
            "INSERT INTO pins(branch_id, oid, candidate_id) VALUES(?1,?2,?3)
             ON CONFLICT(branch_id,oid) DO UPDATE SET candidate_id=excluded.candidate_id",
            params![branch_id, oid, candidate_id],
        )
        .map_err(|e| e.to_string())?;
    }
    // Recompute only the subgraph that resolves this oid.
    let dependents = dependents_of_candidate(store, candidate_id);
    // The pinned base candidate itself plus anything that could reach it.
    resolver::recompute_affected(store, branch_id, default_budgets(), &dependents);
    Ok(())
}

pub fn unpin(store: &Store, branch_id: i64, oid: &str) {
    let db = store.conn.lock().unwrap();
    db.execute(
        "DELETE FROM pins WHERE branch_id=?1 AND oid=?2",
        params![branch_id, oid],
    )
    .ok();
}

fn dependents_of_candidate(store: &Store, base_cid: i64) -> Vec<i64> {
    let db = store.conn.lock().unwrap();
    let edges: Vec<(i64, Option<i64>)> = {
        let mut stmt = db
            .prepare("SELECT from_cid, to_cid FROM edges")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?)))
            .unwrap()
            .flatten()
            .collect()
    };
    drop(db);
    let mut set = std::collections::HashSet::new();
    set.insert(base_cid);
    let mut changed = true;
    while changed {
        changed = false;
        for (child, parent) in &edges {
            if let Some(p) = parent {
                if set.contains(p) && set.insert(*child) {
                    changed = true;
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Objects that still depend on a source (as direct container). Every candidate
/// belongs to exactly one source, so deletion is blocked while the source has
/// candidates referenced by resolved objects or unresolved chains.
pub fn source_dependents(store: &Store, source_id: i64) -> Value {
    let db = store.conn.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT c.id, c.declared_type, COALESCE(c.oid, c.idx_oid, ''),
                    COALESCE((SELECT status FROM resolved WHERE branch_id=1 AND candidate_id=c.id), 'unanalyzed')
             FROM candidates c WHERE c.source_id=?1 ORDER BY c.pack_offset, c.id",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![source_id], |r| {
            Ok(json!({
                "candidate_id": r.get::<_, i64>(0)?,
                "declared_type": r.get::<_, String>(1)?,
                "oid": r.get::<_, String>(2)?,
                "status": r.get::<_, String>(3)?,
            }))
        })
        .unwrap();
    let direct: Vec<Value> = rows.flatten().collect();
    drop(db);
    // Cross-source delta dependents: any edge pointing at a candidate in source.
    let db = store.conn.lock().unwrap();
    let mut dep = Vec::new();
    {
        let mut stmt = db
            .prepare(
                "SELECT e.from_cid, c2.source_id
                 FROM edges e JOIN candidates c1 ON e.to_cid=c1.id
                 JOIN candidates c2 ON e.from_cid=c2.id
                 WHERE c1.source_id=?1 AND c2.source_id!=?1",
            )
            .unwrap();
        let rows = stmt.query_map(params![source_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        });
        for r in rows.unwrap().flatten() {
            dep.push(json!({"candidate_id": r.0, "via_source_id": r.1}));
        }
    }
    json!({
        "source_id": source_id,
        "owned_candidates": direct,
        "cross_source_dependents": dep,
        "blocked": !direct.is_empty(),
    })
}

pub fn delete_source(store: &Store, source_id: i64, force: bool) -> Result<Value, String> {
    let info = source_dependents(store, source_id);
    if info["blocked"].as_bool().unwrap_or(false) && !force {
        return Ok(json!({"deleted": false, "dependents": info}));
    }
    {
        let db = store.conn.lock().unwrap();
        // gather candidate payload files to clean
        let cids: Vec<i64> = {
            let mut stmt = db
                .prepare("SELECT id FROM candidates WHERE source_id=?1")
                .unwrap();
            stmt.query_map(params![source_id], |r| r.get::<_, i64>(0))
                .unwrap()
                .flatten()
                .collect()
        };
        drop(db);
        for cid in cids {
            std::fs::remove_file(store.payload_path(cid)).ok();
            for b in 1..64 {
                store.remove_resolved(b, cid);
            }
        }
        let db = store.conn.lock().unwrap();
        db.execute("DELETE FROM sources WHERE id=?1", params![source_id])
            .map_err(|e| e.to_string())?;
    }
    std::fs::remove_file(store.source_path(source_id)).ok();
    // Remaining ref edges may now dangle; re-resolve all (order independent).
    let report = resolver::run_all(store, 1, default_budgets());
    Ok(json!({
        "deleted": true,
        "source_id": source_id,
        "rerun": {"ok": report.resolved_ok, "paused": report.paused, "bad": report.bad}
    }))
}
