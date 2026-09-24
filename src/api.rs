//! Axum HTTP surface: uploads, state queries, branches, pins, budgets.

use crate::analysis;
use crate::store::Store;
use axum::{
    extract::{Multipart, Path as AxPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub data_dir: PathBuf,
}

impl AppState {
    pub fn new(store: Store, data_dir: PathBuf) -> Self {
        AppState {
            store: Arc::new(Mutex::new(store)),
            data_dir,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/state", get(state_view))
        .route("/api/upload", post(upload))
        .route("/api/sources", get(list_sources))
        .route("/api/sources/:id/dependents", get(dependents))
        .route("/api/sources/:id", post(delete_source))
        .route("/api/objects", get(list_objects))
        .route("/api/objects/:oid", get(object_detail))
        .route("/api/packs", get(list_packs))
        .route("/api/packs/:id/layout", get(pack_layout))
        .route("/api/branches", get(list_branches).post(create_branch))
        .route("/api/branches/:name/reanalyze", post(branch_reanalyze))
        .route("/api/branches/:name/pins", post(set_pin))
        .route("/api/branches/:name/pins/:oid", post(remove_pin))
        .route("/api/evidence", get(list_evidence))
        .route("/api/budget", get(get_budget).post(set_budget))
        .route("/api/budget/reset", post(reset_budget))
        .route("/api/retry", post(retry_now))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../assets/index.html"))
}

async fn app_js() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("../assets/app.js"),
    )
}

#[derive(Serialize)]
struct ErrBody {
    error: String,
}
fn err(msg: impl Into<String>) -> (StatusCode, Json<ErrBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrBody {
            error: msg.into(),
        }),
    )
}

async fn upload(
    State(st): State<AppState>,
    mut mp: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrBody>)> {
    let mut results = Vec::new();
    while let Some(field) = mp.next_field().await.map_err(|e| err(e.to_string()))? {
        let name = field.file_name().unwrap_or("upload.bin").to_string();
        let bytes = field.bytes().await.map_err(|e| err(e.to_string()))?;
        let outcome = analysis::analyze_after_import(&st.store, &name, &bytes);
        match outcome {
            Ok(o) => results.push(serde_json::to_value(o).unwrap()),
            Err(e) => return Err(err(format!("{}: {}", name, e))),
        }
    }
    Ok(Json(serde_json::json!({ "imported": results })))
}

async fn list_sources(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let mut rows = Vec::new();
    let mut stmt = store
        .conn
        .prepare(
            "SELECT id, kind, original_name, bytes, imported_at, parse_status,
                    COALESCE(parse_error,'') FROM sources ORDER BY id",
        )
        .unwrap();
    let q = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "kind": r.get::<_, String>(1)?,
                "name": r.get::<_, String>(2)?,
                "bytes": r.get::<_, i64>(3)?,
                "imported_at": r.get::<_, i64>(4)?,
                "status": r.get::<_, String>(5)?,
                "error": r.get::<_, String>(6)?,
            }))
        })
        .unwrap();
    for r in q.flatten() {
        rows.push(r);
    }
    Json(serde_json::json!({ "sources": rows }))
}

async fn dependents(
    State(st): State<AppState>,
    AxPath(id): AxPath<i64>,
) -> impl IntoResponse {
    let deps = analysis::dependents_preview(&st.store, id);
    Json(serde_json::json!({ "dependents": deps }))
}

async fn delete_source(
    State(st): State<AppState>,
    AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrBody>)> {
    analysis::delete_dependents(&st.store, id)
        .map(|_| Json(serde_json::json!({ "deleted": id })))
        .map_err(err)
}

async fn list_objects(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let mut rows = Vec::new();
    let mut stmt = store
        .conn
        .prepare(
            "SELECT r.branch_id, r.oid, r.status, COALESCE(r.obj_type,''),
                    COALESCE(r.size,0), COALESCE(r.depth,0), r.expanded_bytes,
                    COALESCE(r.reason,''), b.name
             FROM resolutions r JOIN branches b ON b.id=r.branch_id
             ORDER BY b.name, r.oid",
        )
        .unwrap();
    let q = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "branch": r.get::<_, String>(8)?,
                "oid": r.get::<_, String>(1)?,
                "status": r.get::<_, String>(2)?,
                "type": r.get::<_, String>(3)?,
                "size": r.get::<_, i64>(4)?,
                "depth": r.get::<_, i64>(5)?,
                "expanded": r.get::<_, i64>(6)?,
                "reason": r.get::<_, String>(7)?,
            }))
        })
        .unwrap();
    for r in q.flatten() {
        rows.push(r);
    }
    Json(serde_json::json!({ "objects": rows }))
}

#[derive(Deserialize)]
struct DetailQuery {
    branch: Option<String>,
}

async fn object_detail(
    State(st): State<AppState>,
    AxPath(oid): AxPath<String>,
    Query(q): Query<DetailQuery>,
) -> impl IntoResponse {
    let branch = q.branch.unwrap_or_else(|| "default".into());
    let store = st.store.lock().unwrap();
    let bid = store
        .conn
        .query_row("SELECT id FROM branches WHERE name=?1", params![branch], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(1);
    let header = store.conn.query_row(
        "SELECT oid, status, COALESCE(obj_type,''), COALESCE(size,0), COALESCE(depth,0),
                expanded_bytes, COALESCE(reason,''), COALESCE(blocking_chain,''),
                COALESCE(content_path,'')
         FROM resolutions WHERE branch_id=?1 AND oid=?2",
        params![bid, oid],
        |r| {
            Ok(serde_json::json!({
                "oid": r.get::<_, String>(0)?,
                "status": r.get::<_, String>(1)?,
                "type": r.get::<_, String>(2)?,
                "size": r.get::<_, i64>(3)?,
                "depth": r.get::<_, i64>(4)?,
                "expanded": r.get::<_, i64>(5)?,
                "reason": r.get::<_, String>(6)?,
                "blocking_chain": serde_json::from_str::<serde_json::Value>(
                    &r.get::<_, String>(7)?).unwrap_or(serde_json::Value::Null),
            }))
        },
    );
    let header = match header {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({ "found": false })),
    };
    let path: String = store
        .conn
        .query_row(
            "SELECT COALESCE(content_path,'') FROM resolutions WHERE branch_id=?1 AND oid=?2",
            params![bid, oid],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let preview = if !path.is_empty() {
        std::fs::read(store.payload_path(&path)).unwrap_or_default()
    } else {
        Vec::new()
    };
    let preview_text = String::from_utf8_lossy(&preview).chars().take(2000).collect::<String>();

    let mut steps = Vec::new();
    {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT step, COALESCE(base_oid,''), base_kind, COALESCE(base_location,''),
                        cmd_start, cmd_end, cmd_count, in_len, out_len, check_ok,
                        COALESCE(check_detail,'')
                 FROM delta_steps WHERE branch_id=?1 AND oid=?2 ORDER BY step",
            )
            .unwrap();
        let qq = stmt
            .query_map(params![bid, oid], |r| {
                Ok(serde_json::json!({
                    "step": r.get::<_, i64>(0)?,
                    "base_oid": r.get::<_, String>(1)?,
                    "base_kind": r.get::<_, String>(2)?,
                    "base_location": r.get::<_, String>(3)?,
                    "cmd_start": r.get::<_, i64>(4)?,
                    "cmd_end": r.get::<_, i64>(5)?,
                    "cmd_count": r.get::<_, i64>(6)?,
                    "in_len": r.get::<_, i64>(7)?,
                    "out_len": r.get::<_, i64>(8)?,
                    "check_ok": r.get::<_, i64>(9)? == 1,
                    "check_detail": r.get::<_, String>(10)?,
                }))
            })
            .unwrap();
        for r in qq.flatten() {
            steps.push(r);
        }
    }

    let mut candidates = Vec::new();
    {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT c.id, c.origin, COALESCE(c.oid,''), c.chain_len, c.sort_key,
                        EXISTS(SELECT 1 FROM pins p WHERE p.candidate_id=c.id AND p.branch_id=?1)
                 FROM candidates c WHERE c.oid=?2 ORDER BY c.sort_key",
            )
            .unwrap();
        let qq = stmt
            .query_map(params![bid, oid], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "origin": r.get::<_, String>(1)?,
                    "oid": r.get::<_, String>(2)?,
                    "chain_len": r.get::<_, i64>(3)?,
                    "sort_key": r.get::<_, String>(4)?,
                    "pinned": r.get::<_, i64>(5)? == 1,
                }))
            })
            .unwrap();
        for r in qq.flatten() {
            candidates.push(r);
        }
    }

    Json(serde_json::json!({
        "found": true,
        "resolution": header,
        "preview": preview_text,
        "preview_is_text": String::from_utf8(preview).is_ok(),
        "steps": steps,
        "candidates": candidates,
    }))
}

async fn list_packs(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let mut packs = Vec::new();
    let mut stmt = store
        .conn
        .prepare(
            "SELECT p.id, s.original_name, p.version, p.num_objects, p.body_len,
                    p.checksum_ok, COALESCE(i.id,0)
             FROM packs p JOIN sources s ON s.id=p.source_id
             LEFT JOIN idx_files i ON i.paired_pack_id=p.id
             ORDER BY p.id",
        )
        .unwrap();
    let q = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "version": r.get::<_, i64>(2)?,
                "objects": r.get::<_, i64>(3)?,
                "body_len": r.get::<_, i64>(4)?,
                "checksum_ok": r.get::<_, i64>(5)? == 1,
                "idx_id": r.get::<_, i64>(6)?,
            }))
        })
        .unwrap();
    for r in q.flatten() {
        packs.push(r);
    }
    Json(serde_json::json!({ "packs": packs }))
}

async fn pack_layout(
    State(st): State<AppState>,
    AxPath(pack_id): AxPath<i64>,
) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let header = store.conn.query_row(
        "SELECT s.original_name, p.num_objects, p.body_len, p.checksum_ok
         FROM packs p JOIN sources s ON s.id=p.source_id WHERE p.id=?1",
        params![pack_id],
        |r| {
            Ok(serde_json::json!({
                "name": r.get::<_, String>(0)?,
                "num_objects": r.get::<_, i64>(1)?,
                "body_len": r.get::<_, i64>(2)?,
                "checksum_ok": r.get::<_, i64>(3)? == 1,
            }))
        },
    );
    let header = match header {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({ "found": false })),
    };

    // idx fanout for this pack (if paired).
    let mut fanout: Option<Vec<u32>> = None;
    let idx_row: Option<(i64, String)> = store
        .conn
        .query_row(
            "SELECT i.id, s.stored_path FROM idx_files i JOIN sources s ON s.id=i.source_id
             WHERE i.paired_pack_id=?1",
            params![pack_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .ok();
    if let Some((_idx_id, path)) = idx_row {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(parsed) = crate::idx::parse_idx(&bytes) {
                fanout = Some(parsed.fanout.to_vec());
            }
        }
    }

    let mut entries = Vec::new();
    {
        let mut stmt = store
            .conn
            .prepare(
                "SELECT offset, obj_type, declared_size, COALESCE(base_offset,-1),
                        COALESCE(base_oid,''), z_start, COALESCE(z_consumed,-1),
                        COALESCE(inflate_error,'')
                 FROM entries WHERE pack_id=?1 ORDER BY offset",
            )
            .unwrap();
        let q = stmt
            .query_map(params![pack_id], |r| {
                Ok(serde_json::json!({
                    "offset": r.get::<_, i64>(0)?,
                    "type": crate::gitobj::type_name(r.get::<_, i64>(1)? as u8),
                    "declared_size": r.get::<_, i64>(2)?,
                    "base_offset": r.get::<_, i64>(3)?,
                    "base_oid": r.get::<_, String>(4)?,
                    "z_start": r.get::<_, i64>(5)?,
                    "z_consumed": r.get::<_, i64>(6)?,
                    "error": r.get::<_, String>(7)?,
                }))
            })
            .unwrap();
        for r in q.flatten() {
            entries.push(r);
        }
    }
    Json(serde_json::json!({
        "found": true,
        "pack": header,
        "fanout": fanout,
        "entries": entries,
    }))
}

async fn list_branches(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let mut rows = Vec::new();
    let mut stmt = store
        .conn
        .prepare("SELECT id, name FROM branches ORDER BY id")
        .unwrap();
    let q = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
            }))
        })
        .unwrap();
    for r in q.flatten() {
        rows.push(r);
    }
    Json(serde_json::json!({ "branches": rows }))
}

#[derive(Deserialize)]
struct NewBranch {
    name: String,
}

async fn create_branch(
    State(st): State<AppState>,
    Json(body): Json<NewBranch>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrBody>)> {
    let mut store = st.store.lock().unwrap();
    let id = store
        .branch_id(&body.name)
        .map_err(|e| err(e.to_string()))?;
    Ok(Json(serde_json::json!({ "id": id, "name": body.name })))
}

async fn branch_reanalyze(
    State(st): State<AppState>,
    AxPath(name): AxPath<String>,
) -> impl IntoResponse {
    let report = analysis::reanalyze_branch(&st.store, &name);
    Json(serde_json::to_value(report).unwrap())
}

#[derive(Deserialize)]
struct PinBody {
    oid: String,
    candidate_id: i64,
}

async fn set_pin(
    State(st): State<AppState>,
    AxPath(name): AxPath<String>,
    Json(body): Json<PinBody>,
) -> impl IntoResponse {
    analysis::pin_candidate(&st.store, &name, &body.oid, body.candidate_id);
    analysis::reanalyze_branch(&st.store, &name);
    Json(serde_json::json!({ "pinned": true }))
}

async fn remove_pin(
    State(st): State<AppState>,
    AxPath((name, oid)): AxPath<(String, String)>,
) -> impl IntoResponse {
    analysis::unpin(&st.store, &name, &oid);
    analysis::reanalyze_branch(&st.store, &name);
    Json(serde_json::json!({ "unpinned": true }))
}

async fn list_evidence(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let mut rows = Vec::new();
    let mut stmt = store
        .conn
        .prepare(
            "SELECT subject, code, severity, message, COALESCE(detail,'')
             FROM evidence ORDER BY id DESC LIMIT 500",
        )
        .unwrap();
    let q = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "subject": r.get::<_, String>(0)?,
                "code": r.get::<_, String>(1)?,
                "severity": r.get::<_, String>(2)?,
                "message": r.get::<_, String>(3)?,
                "detail": r.get::<_, String>(4)?,
            }))
        })
        .unwrap();
    for r in q.flatten() {
        rows.push(r);
    }
    Json(serde_json::json!({ "evidence": rows }))
}

async fn get_budget(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let b = store.budget();
    Json(serde_json::json!({
        "max_depth": b.max_depth,
        "max_total_expanded": b.max_total_expanded,
        "max_single_ratio": b.max_single_ratio,
        "total_expanded_used": b.total_expanded_used,
        "remaining": b.max_total_expanded as i64 - b.total_expanded_used as i64,
    }))
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<u32>,
    max_total_expanded: Option<u64>,
    max_single_ratio: Option<f64>,
}

async fn set_budget(
    State(st): State<AppState>,
    Json(body): Json<BudgetBody>,
) -> impl IntoResponse {
    {
        let mut store = st.store.lock().unwrap();
        let mut b = store.budget();
        if let Some(v) = body.max_depth {
            b.max_depth = v;
        }
        if let Some(v) = body.max_total_expanded {
            b.max_total_expanded = v;
        }
        if let Some(v) = body.max_single_ratio {
            b.max_single_ratio = v.clamp(0.0, 1.0);
        }
        store.set_budget(&b);
    }
    Json(serde_json::json!({ "updated": true }))
}

async fn reset_budget(State(st): State<AppState>) -> impl IntoResponse {
    {
        let mut store = st.store.lock().unwrap();
        store.reset_used();
    }
    Json(serde_json::json!({ "reset": true }))
}

async fn retry_now(State(st): State<AppState>) -> impl IntoResponse {
    let report = analysis::retry(&st.store);
    Json(serde_json::to_value(report).unwrap())
}

async fn state_view(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.lock().unwrap();
    let b = store.budget();
    let mut counts: HashMap<String, i64> = HashMap::new();
    for status in ["resolved", "error", "missing_base", "paused_budget", "cycle"] {
        let n: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM resolutions WHERE status=?1",
                params![status],
                |r| r.get(0),
            )
            .unwrap_or(0);
        counts.insert(status.to_string(), n);
    }
    let sources: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM sources", [], |r| r.get(0))
        .unwrap_or(0);
    Json(serde_json::json!({
        "sources": sources,
        "counts": counts,
        "budget": {
            "max_depth": b.max_depth,
            "max_total_expanded": b.max_total_expanded,
            "max_single_ratio": b.max_single_ratio,
            "total_expanded_used": b.total_expanded_used,
        }
    }))
}
