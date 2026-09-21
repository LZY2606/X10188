//! Axum HTTP layer: import endpoints, analysis control, read APIs and the
//! single-page 包链显微镜 UI.

use axum::{
    extract::{Multipart, Path as AxPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::db::Db;
use crate::engine::AnalyzeReport;
use crate::ingest::IngestReport;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Db>>,
}

pub fn router(db: Db) -> Router {
    let state = AppState { db: Arc::new(Mutex::new(db)) };
    Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/import", post(import_files))
        .route("/api/sources", get(list_sources))
        .route("/api/sources/{id}/dependents", get(source_dependents))
        .route("/api/sources/{id}", axum::routing::delete(delete_source))
        .route("/api/branches", get(list_branches).post(create_branch))
        .route("/api/branches/{id}/analyze", post(analyze))
        .route("/api/branches/{id}/resume", post(resume))
        .route("/api/branches/{id}/objects", get(objects))
        .route("/api/branches/{id}/dag", get(dag))
        .route("/api/branches/{id}/conflicts", get(conflicts))
        .route("/api/branches/{id}/objects/{eid}", get(object_detail))
        .route("/api/branches/{id}/pin", post(pin))
        .route("/api/branches/{id}/unpin", post(unpin))
        .route("/api/budget", get(get_budget).post(set_budget))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(crate::ui::INDEX_HTML)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "name": "包链显微镜"}))
}

#[derive(Deserialize)]
struct BranchQ { branch: Option<i64> }

async fn import_files(State(st): State<AppState>, mut mp: Multipart)
    -> Result<Json<Vec<IngestReport>>, AppError>
{
    let mut reports = Vec::new();
    while let Some(field) = mp.next_field().await.map_err(|e| AppError::msg(e.to_string()))? {
        let name = field.file_name().unwrap_or("upload.bin").to_string();
        let data = field.bytes().await.map_err(|e| AppError::msg(e.to_string()))?;
        let db = st.db.lock().await;
        let r = db.ingest_file(&name, &data).map_err(AppError::from)?;
        reports.push(r);
    }
    let db = st.db.lock().await;
    db.analyze_branch(1).map_err(AppError::from)?;
    Ok(Json(reports))
}

async fn list_sources(State(st): State<AppState>) -> impl IntoResponse {
    let db = st.db.lock().await;
    Json(db.list_sources())
}

async fn source_dependents(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> impl IntoResponse
{
    let db = st.db.lock().await;
    Json(serde_json::json!({"source_id": id, "dependents": db.source_dependents(id)}))
}

async fn delete_source(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> Result<Json<serde_json::Value>, AppError>
{
    let db = st.db.lock().await;
    let n = db.delete_source(id)?;
    Ok(Json(serde_json::json!({"deleted": id, "affected": n})))
}

async fn list_branches(State(st): State<AppState>) -> impl IntoResponse {
    let db = st.db.lock().await;
    let conn = db.conn.lock().unwrap();
    let rows: Vec<(i64, String, String)> = conn
        .prepare("SELECT id,name,note FROM branches ORDER BY id").unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        .filter_map(|r| r.ok()).collect();
    Json(rows)
}

#[derive(Deserialize)]
struct NewBranch { name: String, note: Option<String> }

async fn create_branch(State(st): State<AppState>, Json(body): Json<NewBranch>)
    -> Result<Json<serde_json::Value>, AppError>
{
    let db = st.db.lock().await;
    let id = {
        let mut conn = db.conn.lock().unwrap();
        let seq = crate::db::next_seq(&conn)?;
        conn.execute("INSERT INTO branches(name,note,created_seq) VALUES(?1,?2,?3)",
            rusqlite::params![body.name, body.note.clone().unwrap_or_default(), seq])?;
        conn.last_insert_rowid()
    };
    db.analyze_branch(id)?;
    Ok(Json(serde_json::json!({"branch_id": id})))
}

async fn analyze(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> Result<Json<AnalyzeReport>, AppError>
{
    let db = st.db.lock().await;
    Ok(Json(db.analyze_branch(id)?))
}

async fn resume(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> Result<Json<AnalyzeReport>, AppError>
{
    let db = st.db.lock().await;
    Ok(Json(db.resume_branch(id)?))
}

async fn objects(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> impl IntoResponse
{
    let db = st.db.lock().await;
    Json(db.list_objects(id))
}

async fn dag(State(st): State<AppState>, AxPath(id): AxPath<i64>) -> impl IntoResponse {
    let db = st.db.lock().await;
    Json(db.dag(id))
}

async fn conflicts(State(st): State<AppState>, AxPath(id): AxPath<i64>)
    -> impl IntoResponse
{
    let db = st.db.lock().await;
    Json(db.conflicts(id))
}

async fn object_detail(State(st): State<AppState>, AxPath((bid, eid)): AxPath<(i64, i64)>)
    -> Result<Json<serde_json::Value>, StatusCode>
{
    let db = st.db.lock().await;
    let detail = db.object_detail(bid, eid).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::to_value(detail).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?))
}

#[derive(Deserialize)]
struct PinBody { oid: String, source_id: i64 }

async fn pin(State(st): State<AppState>, AxPath(id): AxPath<i64>, Json(body): Json<PinBody>)
    -> Result<Json<serde_json::Value>, AppError>
{
    let db = st.db.lock().await;
    let affected = db.pin_source(id, &body.oid, body.source_id)?;
    Ok(Json(serde_json::json!({"pinned": true, "recomputed_entries": affected.len()})))
}

async fn unpin(State(st): State<AppState>, AxPath(id): AxPath<i64>, Json(body): Json<PinBody>)
    -> Result<Json<serde_json::Value>, AppError>
{
    let db = st.db.lock().await;
    let affected = db.unpin_source(id, &body.oid)?;
    Ok(Json(serde_json::json!({"unpinned": true, "recomputed_entries": affected.len()})))
}

async fn get_budget(State(st): State<AppState>) -> Json<serde_json::Value> {
    let db = st.db.lock().await;
    let cfg = db.budget_cfg().unwrap_or(crate::engine::BudgetCfg {
        max_depth: 0, max_expand_bytes: 0, max_single_bytes: 0,
    });
    Json(serde_json::json!({
        "max_depth": cfg.max_depth,
        "max_expand_bytes": cfg.max_expand_bytes,
        "max_single_bytes": cfg.max_single_bytes,
    }))
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<usize>,
    max_expand_bytes: Option<u64>,
    max_single_ratio: Option<f64>,
}

async fn set_budget(State(st): State<AppState>, Json(body): Json<BudgetBody>)
    -> Result<Json<serde_json::Value>, AppError>
{
    let db = st.db.lock().await;
    if let Some(v) = body.max_depth { db.set_setting("budget_depth", &v.to_string())?; }
    if let Some(v) = body.max_expand_bytes { db.set_setting("budget_expand", &v.to_string())?; }
    if let Some(v) = body.max_single_ratio { db.set_setting("budget_single_ratio", &v.to_string())?; }
    db.invalidate_branches();
    db.analyze_branch(1)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

struct AppError { msg: String, code: StatusCode }
impl AppError {
    fn msg(m: String) -> Self { AppError { msg: m, code: StatusCode::BAD_REQUEST } }
}
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self { AppError { msg: e.to_string(), code: StatusCode::INTERNAL_SERVER_ERROR } }
}
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self { AppError { msg: e.to_string(), code: StatusCode::INTERNAL_SERVER_ERROR } }
}
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.code, Json(serde_json::json!({"error": self.msg}))).into_response()
    }
}

#[allow(dead_code)]
fn _use(_q: Query<BranchQ>) {}
