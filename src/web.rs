pub mod api;
pub mod graph;
pub mod home;
pub mod obj;
pub mod part;

use std::sync::Arc;
use axum::routing::get;
use axum::Router;

use crate::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(home::dashboard))
        .route("/sources", get(part::sources_page))
        .route("/sources/{id}", get(part::source_detail))
        .route("/sources/{id}/dependents", get(part::source_dependents))
        .route("/sources/{id}/delete", axum::routing::post(part::delete_source))
        .route("/objects", get(obj::objects_page))
        .route("/objects/{id}", get(obj::object_detail))
        .route("/graph", get(graph::graph_page))
        .route("/branches", get(graph::branches_page))
        .route("/import", axum::routing::post(graph::import_form))
        .route("/retry", axum::routing::post(graph::retry_form))
        .route("/budget", axum::routing::post(graph::set_budget_form))
        .route("/pin", axum::routing::post(graph::pin_form))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .merge(api::routes())
        .with_state(state)
}
