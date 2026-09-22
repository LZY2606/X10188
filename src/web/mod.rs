use crate::db::Db;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub data_dir: String,
    pub lock: Arc<AsyncMutex<()>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/snapshot", get(snapshot))
        .route("/api/import", post(import))
        .route("/api/resume", post(resume))
        .route("/api/budget", post(budget))
        .route("/api/pin", post(pin))
        .route("/api/unpin", post(unpin))
        .route("/api/sources/:id/delete-check", get(delete_check))
        .route("/api/sources/:id", axum::routing::delete(delete_source))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn snapshot(State(st): State<AppState>) -> Json<serde_json::Value> {
    let s = crate::engine::inspect::snapshot(&st.db);
    Json(serde_json::to_value(s).unwrap())
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<i64>,
    total_bytes: Option<i64>,
    single_ratio: Option<i64>,
    reset_used: Option<bool>,
}

async fn budget(
    State(st): State<AppState>,
    Json(body): Json<BudgetBody>,
) -> Json<serde_json::Value> {
    let _g = st.lock.lock().await;
    crate::engine::resolve::set_budgets(
        &st.db,
        body.max_depth,
        body.total_bytes,
        body.single_ratio,
    );
    if body.reset_used.unwrap_or(false) {
        crate::engine::resolve::reset_used(&st.db);
    }
    let r = crate::engine::resolve::resume(&st.db);
    Json(serde_json::to_value(r).unwrap())
}

async fn resume(State(st): State<AppState>) -> Json<crate::engine::resolve::RecomputeReport> {
    let _g = st.lock.lock().await;
    Json(crate::engine::resolve::resume(&st.db))
}

#[derive(Deserialize)]
struct PinBody {
    node_id: i64,
}

async fn pin(
    State(st): State<AppState>,
    Json(body): Json<PinBody>,
) -> Json<crate::engine::inspect::PinReport> {
    let _g = st.lock.lock().await;
    let r = crate::engine::inspect::pin_candidate(&st.db, body.node_id);
    crate::engine::resolve::incremental(&st.db);
    Json(r)
}

#[derive(Deserialize)]
struct UnpinBody {
    oid: String,
}

async fn unpin(State(st): State<AppState>, Json(body): Json<UnpinBody>) -> StatusCode {
    let _g = st.lock.lock().await;
    crate::engine::inspect::unpin_oid(&st.db, &body.oid);
    crate::engine::resolve::incremental(&st.db);
    StatusCode::OK
}

async fn delete_check(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Json<crate::engine::inspect::DeleteCheck> {
    Json(crate::engine::inspect::delete_source_check(&st.db, id))
}

#[derive(Deserialize)]
struct ForceQuery {
    force: Option<bool>,
}

async fn delete_source(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<ForceQuery>,
) -> impl IntoResponse {
    let _g = st.lock.lock().await;
    let r = crate::engine::inspect::delete_source(&st.db, id, q.force.unwrap_or(false));
    if r.deleted_source == 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"source still has dependent objects",
                "check": crate::engine::inspect::delete_source_check(&st.db, id)})),
        ).into_response();
    }
    crate::engine::resolve::incremental(&st.db);
    Json(serde_json::to_value(r).unwrap()).into_response()
}

async fn import(
    State(st): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<Vec<crate::engine::import::ImportReport>>, (StatusCode, String)> {
    let _g = st.lock.lock().await;
    let mut reports = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let filename = field.file_name().unwrap_or("upload").to_string();
        let data = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let report = crate::engine::import::import_bytes(
            &st.db,
            &st.data_dir,
            &filename,
            &data,
        );
        reports.push(report);
    }
    Ok(Json(reports))
}
