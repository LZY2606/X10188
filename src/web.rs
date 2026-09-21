//! Axum HTTP surface.

use crate::engine::Engine;
use crate::error::AppError;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
}

pub fn app(engine: Engine) -> Router {
    let state = AppState {
        engine: Arc::new(engine),
    };
    Router::new()
        .route("/", get(index))
        .route("/api/import", post(import_files))
        .route("/api/state", get(state_view))
        .route("/api/sources", get(sources_view))
        .route("/api/objects", get(objects_view))
        .route("/api/object/:oid", get(object_view))
        .route("/api/dag", get(dag_view))
        .route("/api/blockers", get(blockers_view))
        .route("/api/pack/:id", get(pack_view))
        .route("/api/branch", post(create_branch))
        .route("/api/pin", post(pin_candidate))
        .route("/api/unpin", post(unpin_candidate))
        .route("/api/resume", post(resume))
        .route("/api/rerun", post(rerun))
        .route("/api/sources/:id/dependents", get(dependents))
        .route("/api/sources/:id", post(delete_source))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
}

#[derive(Deserialize)]
struct BranchQuery {
    branch: Option<String>,
}

fn br(q: &Option<BranchQuery>) -> String {
    q.as_ref().and_then(|q| q.branch.clone()).unwrap_or_else(|| "default".to_string())
}

async fn state_view(
    State(s): State<AppState>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(crate::queries::state(&s.engine, &br(&Some(q))).await?))
}

async fn sources_view(State(s): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(crate::queries::sources(&s.engine).await?))
}

async fn objects_view(
    State(s): State<AppState>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(crate::queries::objects(&s.engine, &br(&Some(q))).await?))
}

async fn object_view(
    State(s): State<AppState>,
    Path(oid): Path<String>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(
        crate::queries::object_detail(&s.engine, &br(&Some(q)), &oid).await?,
    ))
}

async fn dag_view(
    State(s): State<AppState>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(crate::queries::dag(&s.engine, &br(&Some(q))).await?))
}

async fn blockers_view(
    State(s): State<AppState>,
    Query(q): Query<BranchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(
        crate::queries::blockers(&s.engine, &br(&Some(q))).await?,
    ))
}

async fn pack_view(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(crate::queries::pack_layout(&s.engine, id).await?))
}

async fn import_files(
    State(s): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut imported = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Http(e.to_string()))?
    {
        let name = field.file_name().unwrap_or("uploaded").to_string();
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::Http(e.to_string()))?;
        let info = s.engine.import(&name, data.to_vec()).await?;
        imported.push(serde_json::json!({ "file": name, "result": info }));
    }
    Ok(Json(serde_json::json!({ "imported": imported })))
}

#[derive(Deserialize)]
struct BranchReq {
    name: String,
}

async fn create_branch(
    State(s): State<AppState>,
    Json(req): Json<BranchReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = s.engine.create_branch(&req.name).await?;
    Ok(Json(serde_json::json!({ "id": id, "name": req.name })))
}

#[derive(Deserialize)]
struct PinReq {
    branch: Option<String>,
    oid: String,
    candidate_id: i64,
}

async fn pin_candidate(
    State(s): State<AppState>,
    Json(req): Json<PinReq>,
) -> Result<impl IntoResponse, AppError> {
    s.engine
        .pin(&br(&Some(BranchQuery { branch: req.branch })), &req.oid, req.candidate_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unpin_candidate(
    State(s): State<AppState>,
    Json(req): Json<PinReq>,
) -> Result<impl IntoResponse, AppError> {
    s.engine
        .unpin(&br(&Some(BranchQuery { branch: req.branch })), &req.oid)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ResumeReq {
    branch: Option<String>,
    add_bytes: Option<i64>,
    add_depth: Option<i64>,
    add_ratio_mib: Option<i64>,
}

async fn resume(
    State(s): State<AppState>,
    Json(req): Json<ResumeReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let r = s
        .engine
        .resume(
            &br(&Some(BranchQuery { branch: req.branch })),
            req.add_bytes.unwrap_or(8 * 1024 * 1024),
            req.add_depth.unwrap_or(8),
            req.add_ratio_mib.unwrap_or(16),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "run_seq": r.run_seq,
        "complete": r.complete,
        "blocked": r.blocked,
        "paused": r.paused,
        "bad": r.bad,
        "pause_reason": r.pause_reason,
    })))
}

async fn rerun(
    State(s): State<AppState>,
    Json(req): Json<ResumeReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let r = s
        .engine
        .rerun_all(&br(&Some(BranchQuery { branch: req.branch })))
        .await?;
    Ok(Json(serde_json::json!({
        "run_seq": r.run_seq,
        "complete": r.complete,
        "blocked": r.blocked,
        "paused": r.paused,
        "bad": r.bad,
    })))
}

async fn dependents(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(s.engine.deletion_dependents(id).await?))
}

#[derive(Deserialize)]
struct DeleteReq {
    force: Option<bool>,
}

#[axum::debug_handler]
async fn delete_source(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<DeleteReq>,
) -> axum::response::Response {
    async fn run(
        s: AppState,
        id: i64,
        q: DeleteReq,
    ) -> Result<Json<serde_json::Value>, AppError> {
        let force = q.force.unwrap_or(false);
        if !force {
            let dep = s.engine.deletion_dependents(id).await?;
            return Ok(Json(serde_json::json!({
                "refused": true,
                "dependents": dep,
            })));
        }
        Ok(Json(s.engine.delete_source(id, true).await?))
    }
    match run(s, id, q).await {
        Ok(v) => v.into_response(),
        Err(e) => e.into_response(),
    }
}

#[allow(dead_code)]
fn params_map(_: &HashMap<String, String>) {}
