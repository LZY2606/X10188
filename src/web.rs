//! Axum Web 层：页面 + JSON API。所有接口在 `spawn_blocking` 中访问 SQLite。

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::importer::{dependents_before_delete, ImportReport, Importer};
use crate::resolver;
use crate::store::{SourceKind, Store, CB_FRESH};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/api/state", get(api_state))
        .route("/api/import", post(api_import))
        .route("/api/sources/{id}", get(api_source).delete(api_delete_source))
        .route("/api/sources/{id}/dependents", get(api_dependents))
        .route("/api/objects/{id}", get(api_object))
        .route("/api/branches", get(api_branches).post(api_create_branch))
        .route("/api/branches/{name}/pin", post(api_pin))
        .route("/api/branches/{name}/resolve", post(api_resolve_branch))
        .route("/api/budget", get(api_budget).post(api_set_budget))
        .route("/api/retry", post(api_retry))
        .with_state(AppState { store })
}

async fn index_page() -> Html<&'static str> {
    Html(crate::web_html::HTML)
}

fn err500(msg: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg.to_string() })))
}

async fn api_state(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || build_state_json(&store))
        .await
        .map(Json)
        .map_err(err500)
}

fn build_state_json(store: &Store) -> Value {
    let branch_name = crate::store::DEFAULT_BRANCH;
    let branch = store.branch_by_name(branch_name).expect("default branch");

    let sources: Vec<Value> = store
        .sources()
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "kind": s.kind,
                "filename": s.filename,
                "size_bytes": s.size_bytes,
                "sha1": s.sha1,
                "pack_checksum": s.pack_checksum,
                "idx_pack_checksum": s.idx_pack_checksum,
                "parse_state": s.parse_state,
                "evidence": serde_json::from_str::<Value>(&s.evidence_json).unwrap_or(json!([])),
            })
        })
        .collect();

    let cbs = store.cb_rows_for_branch(branch.id);
    let cb_map: std::collections::HashMap<i64, _> = cbs.into_iter().map(|r| (r.candidate_id, r)).collect();

    let candidates: Vec<Value> = store
        .all_candidates()
        .into_iter()
        .map(|c| {
            let cb = cb_map.get(&c.id);
            let conflicts = if let Some(oid) = &c.oid {
                if !c.delta {
                    store.candidates_for_oid(oid).len()
                } else {
                    0
                }
            } else {
                0
            };
            json!({
                "id": c.id,
                "source_id": c.source_id,
                "kind": c.kind,
                "pack_offset": c.pack_offset,
                "stype": c.stype,
                "final_type": cb.and_then(|r| r.final_type.clone()).or(c.final_type),
                "oid": cb.and_then(|r| r.oid.clone()).or(c.oid),
                "declared_size": c.declared_size,
                "inflated_size": c.inflated_size,
                "body_len": cb.and_then(|r| r.body_len).or(c.body_len),
                "delta": c.delta,
                "base_offset": c.base_offset,
                "base_oid": c.base_oid,
                "parse_state": c.parse_state,
                "evidence": serde_json::from_str::<Value>(&c.evidence_json).unwrap_or(json!([])),
                "rank_score": c.rank_score,
                "content_sig": c.content_sig,
                "status": cb.map(|r| r.status.clone()).unwrap_or_else(|| CB_FRESH.into()),
                "blocked_chain": cb.map(|r| serde_json::from_str::<Value>(&r.blocked_chain_json).unwrap_or(json!([]))).unwrap_or(json!([])),
                "pause": cb.map(|r| serde_json::from_str::<Value>(&r.pause_json).unwrap_or(json!({}))).unwrap_or(json!({})),
                "generation": cb.map(|r| r.generation).unwrap_or(0),
                "same_oid_candidates": conflicts,
            })
        })
        .collect();

    let edges: Vec<Value> = store
        .edges(branch.id)
        .into_iter()
        .map(|e| json!({ "from": e.from_candidate, "to": e.to_candidate, "ref_kind": e.ref_kind }))
        .collect();

    let branches: Vec<Value> = store
        .branches()
        .into_iter()
        .map(|b| json!({ "id": b.id, "name": b.name, "note": b.note, "pinned": serde_json::from_str::<Value>(&b.pinned_json).unwrap_or(json!({})) }))
        .collect();

    let cfg = resolver::load_budget(store);
    json!({
        "title": "包链显微镜",
        "branch": branch.name,
        "pinned": serde_json::from_str::<Value>(&branch.pinned_json).unwrap_or(json!({})),
        "sources": sources,
        "objects": candidates,
        "edges": edges,
        "branches": branches,
        "budget": {
            "max_depth": cfg.max_depth,
            "max_total_bytes": cfg.max_total_bytes,
            "max_obj_ratio": cfg.max_obj_ratio,
            "max_obj_bytes": cfg.max_obj_bytes,
            "used_total_bytes": store.total_used_bytes(branch.id),
        },
        "counts": status_counts(&candidates),
    })
}

fn status_counts(objects: &[Value]) -> Value {
    let mut m = serde_json::Map::new();
    for o in objects {
        let key = o.get("status").and_then(|v| v.as_str()).unwrap_or("fresh");
        let v = m.entry(key.to_string()).or_insert(json!(0));
        *v = json!(v.as_i64().unwrap_or(0) + 1);
    }
    Value::Object(m)
}

/* ---------------- 导入 / 删除 / 依赖 ---------------- */

async fn api_import(State(st): State<AppState>, mut multipart: axum::extract::Multipart) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let name = field.file_name().unwrap_or("upload.bin").to_string();
                let bytes = field.bytes().await.map_err(err500)?.to_vec();
                files.push((name, bytes));
            }
            Ok(None) => break,
            Err(e) => return Err(err500(e)),
        }
    }
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let importer = Importer::new(&store);
        let reports: Vec<ImportReport> = files.iter().map(|(name, data)| importer.import_bytes(name, data)).collect();
        Json(json!({ "imported": reports }))
    })
    .await
    .map_err(|e| err500(e))
}

async fn api_source(State(st): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || match store.source_by_id(id) {
        Some(s) => Ok(Json(json!({
            "id": s.id,
            "kind": s.kind,
            "filename": s.filename,
            "stored_path": s.stored_path,
            "size_bytes": s.size_bytes,
            "sha1": s.sha1,
            "pack_checksum": s.pack_checksum,
            "idx_pack_checksum": s.idx_pack_checksum,
            "parse_state": s.parse_state,
            "evidence": serde_json::from_str::<Value>(&s.evidence_json).unwrap_or(json!([])),
        }))),
        None => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "source not found" })))),
    })
    .await
    .map_err(err500)
}

async fn api_dependents(State(st): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let deps = dependents_before_delete(&store, id);
        let objects: Vec<Value> = deps
            .into_iter()
            .filter_map(|cid| store.candidate_meta(cid))
            .map(|c| {
                json!({
                    "candidate_id": c.id,
                    "source_id": c.source_id,
                    "stype": c.stype,
                    "oid": c.oid,
                    "pack_offset": c.pack_offset,
                    "base_oid": c.base_oid,
                    "base_offset": c.base_offset,
                })
            })
            .collect();
        Json(json!({ "source_id": id, "dependents": objects, "can_delete": objects.is_empty() }))
    })
    .await
    .map_err(err500)
}

async fn api_delete_source(State(st): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let deps = dependents_before_delete(&store, id);
        if !deps.is_empty() {
            return Ok((StatusCode::CONFLICT, Json(json!({
                "error": "仍有对象依赖该源文件",
                "dependents": deps,
            }))));
        }
        if let Some(src) = store.source_by_id(id) {
            let abs = format!("{}/{}", store.data_dir, src.stored_path);
            std::fs::remove_file(abs).ok();
            store.delete_source_cascade(id);
            let summary = resolver::resolve_branch(&store, crate::store::DEFAULT_BRANCH);
            Ok((StatusCode::OK, Json(json!({ "deleted": id, "resolve": summary }))))
        } else {
            Err((StatusCode::NOT_FOUND, Json(json!({ "error": "source not found" }))))
        }
    })
    .await
    .map_err(err500)
}

/* ---------------- 对象详情（内容预览 + delta 步骤证据） ---------------- */

async fn api_object(State(st): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let c = match store.candidate_meta(id) {
            Some(c) => c,
            None => return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "object not found" })))),
        };
        let branch = match store.branch_by_name(crate::store::DEFAULT_BRANCH) {
            Some(b) => b,
            None => return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "branch missing" })))),
        };
        let (body, delta_payload) = store.candidate_payload(id).unwrap_or_default();
        let cb = store.cb_row(branch.id, id);
        let steps = store.delta_steps(branch.id, id);
        let preview = preview_body(&body, 4096);
        Ok(Json(json!({
            "id": c.id,
            "source_id": c.source_id,
            "stype": c.stype,
            "final_type": cb.as_ref().and_then(|r| r.final_type.clone()).or(c.final_type),
            "oid": cb.as_ref().and_then(|r| r.oid.clone()).or(c.oid),
            "status": cb.as_ref().map(|r| r.status.clone()).unwrap_or_else(|| CB_FRESH.into()),
            "declared_size": c.declared_size,
            "inflated_size": c.inflated_size,
            "body_len": body.len(),
            "body_preview": preview,
            "body_sha1": crate::hash::sha1_hex(&body),
            "delta_len": delta_payload.len(),
            "delta_sha1": crate::hash::sha1_hex(&delta_payload),
            "delta_preview_hex": hex_preview(&delta_payload, 512),
            "pack_offset": c.pack_offset,
            "base_offset": c.base_offset,
            "base_oid": c.base_oid,
            "evidence": serde_json::from_str::<Value>(&c.evidence_json).unwrap_or(json!([])),
            "blocked_chain": cb.as_ref().map(|r| serde_json::from_str::<Value>(&r.blocked_chain_json).unwrap_or(json!([]))).unwrap_or(json!([])),
            "pause": cb.as_ref().map(|r| serde_json::from_str::<Value>(&r.pause_json).unwrap_or(json!({}))).unwrap_or(json!({})),
            "steps": steps,
        })))
    })
    .await
    .map_err(err500)
}

fn preview_body(body: &[u8], max: usize) -> Value {
    let slice = &body[..body.len().min(max)];
    let truncated = body.len() > slice.len();
    let is_text = slice.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80);
    json!({
        "text": if is_text { json!(String::from_utf8_lossy(slice).to_string()) } else { Value::Null },
        "hex": hex_preview(slice, max),
        "is_text": is_text,
        "truncated": truncated,
        "shown_bytes": slice.len(),
    })
}

fn hex_preview(data: &[u8], max: usize) -> String {
    let n = data.len().min(max);
    hex::encode(&data[..n])
}

/* ---------------- 分支 / pin / resolve / 预算 / 重试 ---------------- */

async fn api_branches(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let branches: Vec<Value> = store
            .branches()
            .into_iter()
            .map(|b| json!({ "id": b.id, "name": b.name, "note": b.note, "pinned": serde_json::from_str::<Value>(&b.pinned_json).unwrap_or(json!({})) }))
            .collect();
        Json(json!({ "branches": branches }))
    })
    .await
    .map_err(err500)
}

#[derive(Deserialize)]
struct CreateBranchReq {
    name: String,
    note: Option<String>,
    /// 从哪个分支克隆；缺省 default。
    from: Option<String>,
    pinned: Option<Value>,
}

async fn api_create_branch(State(st): State<AppState>, Json(req): Json<CreateBranchReq>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let pinned = req.pinned.map(|v| v.to_string()).unwrap_or_else(|| "{}".into());
        let from = req.from.clone().unwrap_or_else(|| crate::store::DEFAULT_BRANCH.into());
        if store.branch_by_name(&req.name).is_some() {
            return Err((StatusCode::CONFLICT, Json(json!({ "error": "分支已存在" }))));
        }
        if let Err(e) = store.clone_branch(&from, &req.name, req.note.as_deref().unwrap_or(""), &pinned) {
            return Err(err500(e));
        }
        Ok(Json(json!({ "created": req.name })))
    })
    .await
    .map_err(err500)
}

#[derive(Deserialize)]
struct PinReq {
    oid: String,
    /// 固定使用的候选 id；null 表示取消 pin。
    candidate_id: Option<i64>,
}

async fn api_pin(State(st): State<AppState>, Path(name): Path<String>, Json(req): Json<PinReq>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let branch = match store.branch_by_name(&name) {
            Some(b) => b,
            None => return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "branch not found" })))),
        };
        let mut pinned: Value = serde_json::from_str(&branch.pinned_json).unwrap_or_else(|_| json!({}));
        let obj = pinned.as_object_mut().expect("pinned is object");
        match req.candidate_id {
            Some(cid) => {
                obj.insert(req.oid.to_lowercase(), json!(cid));
            }
            None => {
                obj.remove(&req.oid.to_lowercase());
            }
        }
        {
            let c = store.lock();
            c.execute("UPDATE branches SET pinned_json=?1 WHERE id=?2", rusqlite::params![pinned.to_string(), branch.id])
                .unwrap();
        }
        // pin 改变来源选择 -> 对 default 全量重算该分支。
        let summary = resolver::resolve_branch_named(&store, &name);
        Ok(Json(json!({ "pinned": pinned, "resolve": summary })))
    })
    .await
    .map_err(err500)
}

async fn api_resolve_branch(State(st): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || Json(json!(resolver::resolve_branch_named(&store, &name))))
        .await
        .map_err(err500)
}

#[derive(Deserialize)]
struct BudgetReq {
    max_depth: Option<u32>,
    max_total_bytes: Option<u64>,
    max_obj_ratio: Option<f64>,
    max_obj_bytes: Option<u64>,
}

async fn api_budget(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let cfg = resolver::load_budget(&store);
        Json(json!(cfg))
    })
    .await
    .map_err(err500)
}

async fn api_set_budget(State(st): State<AppState>, Json(req): Json<BudgetReq>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || {
        let mut cfg = resolver::load_budget(&store);
        if let Some(v) = req.max_depth {
            cfg.max_depth = v;
        }
        if let Some(v) = req.max_total_bytes {
            cfg.max_total_bytes = v;
        }
        if let Some(v) = req.max_obj_ratio {
            cfg.max_obj_ratio = v.clamp(0.0, 1.0);
        }
        if let Some(v) = req.max_obj_bytes {
            cfg.max_obj_bytes = v;
        }
        resolver::save_budget(&store, &cfg);
        // 预算放宽后重试：重新解析，之前 paused 的对象有机会完成。
        let summary = resolver::resolve_branch(&store, crate::store::DEFAULT_BRANCH);
        Json(json!({ "budget": cfg, "resolve": summary }))
    })
    .await
    .map_err(err500)
}

async fn api_retry(State(st): State<AppState>) -> impl IntoResponse {
    let store = st.store.clone();
    tokio::task::spawn_blocking(move || Json(json!(resolver::resolve_branch(&store, crate::store::DEFAULT_BRANCH))))
        .await
        .map_err(err500)
}

/// 允许服务器以 `?data=...` 或默认 ./data 启动由 main 负责；这里保留 SourceKind 引用。
#[allow(dead_code)]
fn kind_ref(_k: SourceKind) {}
