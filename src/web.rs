use crate::service::{Budget, Service};
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState { pub service: Arc<Service> }

pub fn app(service: Service) -> Router {
    let state = AppState { service: Arc::new(service) };
    Router::new()
        .route("/", get(index))
        .route("/api/dashboard", get(dashboard))
        .route("/api/import", post(import))
        .route("/api/sources/{id}/delete", post(delete_source))
        .route("/api/candidates/{id}/pin", post(pin))
        .route("/api/resolve", post(resolve))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn dashboard(State(state): State<AppState>) -> Result<Json<crate::service::Dashboard>, AppError> {
    Ok(Json(state.service.dashboard()?))
}

#[derive(Deserialize)]
struct ResolveForm { max_delta_depth: Option<usize>, max_total_expanded: Option<u64>, max_object_ratio: Option<f64> }

async fn resolve(State(state): State<AppState>, Json(form): Json<ResolveForm>) -> Result<Json<crate::service::RunSummary>, AppError> {
    let mut budget = Budget::default();
    if let Some(v) = form.max_delta_depth { budget.max_delta_depth = v; }
    if let Some(v) = form.max_total_expanded { budget.max_total_expanded = v; }
    if let Some(v) = form.max_object_ratio { budget.max_object_ratio = v; }
    Ok(Json(state.service.resolve(1, budget)?))
}

async fn import(State(state): State<AppState>, mut multipart: Multipart) -> Result<Json<crate::service::ImportResult>, AppError> {
    while let Some(field) = multipart.next_field().await.map_err(|e| e.to_string())? {
        let name = field.file_name().unwrap_or("loose-object").to_string();
        let bytes = field.bytes().await.map_err(|e| e.to_string())?;
        return Ok(Json(state.service.import_bytes(&name, &bytes)?));
    }
    Err(AppError("missing file".into()))
}

#[derive(Deserialize)]
struct DeleteQuery { force: Option<bool> }
async fn delete_source(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<DeleteQuery>) -> Result<Json<crate::service::DeleteResult>, AppError> {
    Ok(Json(state.service.delete_source(id, q.force.unwrap_or(false))?))
}

async fn pin(State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<crate::service::RunSummary>, AppError> {
    Ok(Json(state.service.pin_candidate(1, id, Budget::default())?))
}

struct AppError(String);
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": self.0}))).into_response()
    }
}
impl From<String> for AppError { fn from(value: String) -> Self { Self(value) } }
