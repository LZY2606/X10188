use std::sync::Arc;
use axum::{extract::State, Json};

use crate::Engine;

pub async fn state(State(_e): State<Arc<Engine>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

pub async fn import(State(_e): State<Arc<Engine>>, _body: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

pub async fn resume(State(e): State<Arc<Engine>>) -> Json<serde_json::Value> {
    let s = e.full_resolve();
    Json(serde_json::to_value(s).unwrap())
}

pub async fn create_branch(State(_e): State<Arc<Engine>>, _body: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

pub async fn delete_source(State(_e): State<Arc<Engine>>, _body: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

pub async fn set_budget(State(_e): State<Arc<Engine>>, _body: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}
