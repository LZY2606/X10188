use crate::engine::Engine;
use axum::{Router, routing::get};
use std::sync::Arc;

pub fn build_router(_engine: Arc<Engine>) -> Router {
    Router::new().route("/", get(|| async { "包链显微镜" }))
}
