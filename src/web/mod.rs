pub mod api;
pub mod page;

use std::sync::Arc;
use axum::{routing::{get, post}, Router};

use crate::Engine;

pub fn app(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/", get(page::index))
        .route("/api/state", get(api::state))
        .route("/api/import", post(api::import))
        .route("/api/resume", post(api::resume))
        .route("/api/branches", post(api::create_branch))
        .route("/api/sources/{id}/delete", post(api::delete_source))
        .route("/api/budget", post(api::set_budget))
        .with_state(engine)
}
