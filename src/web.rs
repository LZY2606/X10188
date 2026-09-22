use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::{snapshot, types::Budget, Engine};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
}

pub fn router(engine: Arc<Engine>) -> Router {
    let state = AppState { engine };
    Router::new()
        .route("/", get(index))
        .route("/static/app.js", get(app_js))
        .route("/static/style.css", get(style_css))
        .route("/api/snapshot", get(get_snapshot))
        .route("/api/candidates/{id}", get(get_candidate))
        .route("/api/import", post(import_files))
        .route("/api/analyze", post(analyze))
        .route("/api/resume", post(resume))
        .route("/api/branches", post(create_branch))
        .route("/api/sources/{id}/deletion", get(deletion_preview))
        .route("/api/sources/{id}", axum::routing::delete(delete_source))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}
async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("../static/app.js"),
    )
        .into_response()
}
async fn style_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/style.css"),
    )
        .into_response()
}

async fn get_snapshot(State(st): State<AppState>) -> Json<serde_json::Value> {
    let mut db = st.engine.db.lock().unwrap();
    let snap = db.conn.transaction().ok().map(|tx| snapshot::build_snapshot(&tx));
    match snap {
        Some(s) => Json(json!(s)),
        None => Json(json!({"error": "snapshot failed"})),
    }
}

async fn get_candidate(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut db = st.engine.db.lock().unwrap();
    let tx = db.conn.transaction().map_err(internal)?;
    match snapshot::candidate_detail(&tx, id) {
        Some(d) => Ok(Json(json!(d))),
        None => Err((StatusCode::NOT_FOUND, format!("candidate {} not found", id))),
    }
}

#[derive(Deserialize)]
struct BudgetQuery {
    max_depth: Option<u32>,
    total_bytes: Option<u64>,
    ratio_millis: Option<u64>,
    pinned_source: Option<i64>,
}

fn budget_of(q: &Option<BudgetQuery>) -> (Option<Budget>, Option<i64>) {
    match q {
        Some(b) => {
            let def = Budget::default();
            (
                Some(Budget::new(
                    b.max_depth.unwrap_or(def.max_depth),
                    b.total_bytes.unwrap_or(def.total_bytes),
                    b.ratio_millis.unwrap_or(def.ratio_millis),
                )),
                b.pinned_source,
            )
        }
        None => (None, None),
    }
}

async fn analyze(
    State(st): State<AppState>,
    Query(q): Query<BudgetQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (budget, pin) = budget_of(&Some(q));
    let stats = st.engine.analyze(budget, pin).map_err(internal)?;
    Ok(Json(json!({ "stats": stats })))
}

async fn resume(
    State(st): State<AppState>,
    Query(q): Query<BudgetQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let (budget, pin) = budget_of(&Some(q));
    let stats = st.engine.resume(budget, pin).map_err(internal)?;
    Ok(Json(json!({ "stats": stats })))
}

async fn import_files(
    State(st): State<AppState>,
    mut mp: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut imported = Vec::new();
    let mut warnings = Vec::new();
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let filename = field.file_name().unwrap_or("unnamed").to_string();
        let data = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        // loose 文件可能以 objects/xx/yyy 路径上传，尝试从路径提取 oid 提示
        let oid_hint = extract_loose_oid_hint(&filename);
        let outcome = st
            .engine
            .import_bytes(&filename, &data, oid_hint.as_deref())
            .map_err(internal)?;
        imported.push(json!({
            "filename": filename,
            "source_id": outcome.report.source_id,
            "kind": outcome.report.kind,
            "candidates": outcome.report.candidates,
            "fatal": outcome.report.fatal,
        }));
        warnings.extend(outcome.warnings);
    }
    // 导入后自动跑一轮默认预算的全量分析（页面刷新即可看到结果）
    let auto = st.engine.analyze(None, None).ok();
    Ok(Json(json!({ "imported": imported, "warnings": warnings, "auto_run": auto })))
}

fn extract_loose_oid_hint(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    if parts.len() >= 2 {
        let n = parts.len();
        let dir = parts[n - 2];
        let file = parts[n - 1];
        if dir.len() == 2 && file.len() >= 38 {
            let oid = format!("{}{}", dir, file);
            if oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(oid);
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct BranchReq {
    name: String,
    ref_oid: String,
    pinned_source_id: Option<i64>,
    pinned_cand_id: Option<i64>,
}

async fn create_branch(
    State(st): State<AppState>,
    Json(req): Json<BranchReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let db = st.engine.db.lock().unwrap();
    db.conn
        .execute(
            "INSERT INTO branches(name, pinned_source_id, pinned_cand_id, ref_oid)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(name) DO UPDATE SET
                pinned_source_id=excluded.pinned_source_id,
                pinned_cand_id=excluded.pinned_cand_id,
                ref_oid=excluded.ref_oid",
            params![req.name, req.pinned_source_id, req.pinned_cand_id, req.ref_oid],
        )
        .map_err(internal)?;
    Ok(Json(json!({"ok": true})))
}

async fn deletion_preview(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut db = st.engine.db.lock().unwrap();
    let tx = db.conn.transaction().map_err(internal)?;
    let filename: String = tx
        .query_row(
            "SELECT filename FROM sources WHERE id=?1",
            params![id],
            |r| r.get(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, format!("source {} not found", id)))?;
    // 仍依赖该源的对象：本源候选 + 通过 edge 反向依赖这些候选的其它候选
    let own: Vec<i64> = tx
        .prepare("SELECT id FROM candidates WHERE source_id=?1 ORDER BY id")
        .unwrap()
        .query_map(params![id], |r| r.get::<_, i64>(0))
        .unwrap()
        .flatten()
        .collect();
    let mut dependent: Vec<i64> = Vec::new();
    {
        let mut stmt = tx
            .prepare("SELECT from_cand, to_cand FROM edges")
            .map_err(internal)?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
        });
        if let Ok(rows) = rows {
            for (from, to) in rows.flatten() {
                if let Some(t) = to {
                    if own.contains(&t) && !own.contains(&from) {
                        dependent.push(from);
                    }
                }
            }
        }
    }
    dependent.sort_unstable();
    dependent.dedup();
    Ok(Json(json!({
        "source_id": id,
        "filename": filename,
        "own_candidates": own,
        "external_dependents": dependent,
        "blocked": !own.is_empty() || !dependent.is_empty(),
        "message": if own.is_empty() && dependent.is_empty() {
            "没有对象依赖该源，可安全删除".to_string()
        } else {
            format!("删除将移除 {} 个对象，且 {} 个其它对象仍依赖它们", own.len(), dependent.len())
        }
    })))
}

async fn delete_source(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<DeleteQ>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !q.force.unwrap_or(false) {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            "请先查看 /api/sources/{id}/deletion 并显式 force=true".to_string(),
        ));
    }
    let mut db = st.engine.db.lock().unwrap();
    let dir = db.data_dir.clone();
    let tx = db.conn.transaction().map_err(internal)?;
    let stored: String = tx
        .query_row(
            "SELECT stored_path FROM sources WHERE id=?1",
            params![id],
            |r| r.get(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, format!("source {} not found", id)))?;

    // 级联删除该源候选及其 delta_steps / edges
    let cand_ids: Vec<i64> = tx
        .prepare("SELECT id FROM candidates WHERE source_id=?1")
        .unwrap()
        .query_map(params![id], |r| r.get::<_, i64>(0))
        .unwrap()
        .flatten()
        .collect();
    for cid in &cand_ids {
        tx.execute("DELETE FROM delta_steps WHERE cand_id=?1", params![cid]).ok();
        tx.execute("DELETE FROM edges WHERE from_cand=?1 OR to_cand=?1", params![cid, cid]).ok();
    }
    tx.execute("DELETE FROM candidates WHERE source_id=?1", params![id]).ok();
    tx.execute("DELETE FROM fanout WHERE source_id=?1", params![id]).ok();
    // 解除其它 index 对该 pack 的附着
    tx.execute(
        "UPDATE sources SET attached_pack_id=NULL, status=CASE WHEN kind='index' THEN 'mismatch' ELSE status END
         WHERE attached_pack_id=?1",
        params![id],
    )
    .ok();
    tx.execute("DELETE FROM sources WHERE id=?1", params![id]).ok();
    let path = dir.join("files").join(&stored);
    let _ = std::fs::remove_file(path);
    tx.commit().map_err(internal)?;
    Ok(Json(json!({"ok": true, "removed_candidates": cand_ids.len()})))
}

#[derive(Deserialize)]
struct DeleteQ {
    force: Option<bool>,
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
