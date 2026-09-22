use crate::engine::{Budget, Engine, RunOutcome};
use crate::oid;
use crate::store::Store;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type Shared = Arc<Mutex<Engine>>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/import", post(import_bytes))
        .route("/api/import_path", post(import_path))
        .route("/api/engine/run", post(run_engine))
        .route("/api/engine/status", get(engine_status))
        .route("/api/sources", get(list_sources))
        .route("/api/sources/{id}/dependents", get(source_dependents))
        .route("/api/sources/{id}", axum::routing::delete(delete_source))
        .route("/api/packs", get(list_packs))
        .route("/api/objects", get(list_objects))
        .route("/api/objects/{oid}", get(object_detail))
        .route("/api/dag", get(dag))
        .route("/api/errors", get(list_errors))
        .route("/api/blocked", get(list_blocked))
        .route("/api/candidates/{oid}", get(candidates_of))
        .route("/api/branches", get(list_branches))
        .route("/api/branches", post(create_branch))
        .with_state(state)
}

pub async fn serve(addr: &str, data_dir: PathBuf, budget: Budget) -> Result<(), String> {
    let engine = Engine::open(&data_dir, budget)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    println!("包链显微镜 listening on http://{addr}");
    axum::serve(listener, router(Arc::new(Mutex::new(engine))))
        .await
        .map_err(|e| e.to_string())
}

async fn page() -> Html<&'static str> {
    Html(PAGE_HTML)
}

async fn import_bytes(
    State(state): State<Shared>,
    Query(q): Query<ImportQuery>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = q.name.unwrap_or_else(|| "uploaded".to_string());
    let mut engine = state.lock().unwrap();
    let summary = engine
        .import_and_run(&name, &body)
        .map_err(ApiError::from_string)?;
    Ok(Json(json!({
        "source_id": summary.source_id,
        "kind": summary.kind,
        "state": summary.state,
    })))
}

async fn import_path(
    State(state): State<Shared>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = req
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad("missing path"))?;
    let bytes = std::fs::read(path).map_err(|e| ApiError::bad(&format!("read: {e}")))?;
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("loose")
        .to_string();
    let mut engine = state.lock().unwrap();
    let summary = engine
        .import_and_run(&name, &bytes)
        .map_err(ApiError::from_string)?;
    Ok(Json(json!({
        "source_id": summary.source_id,
        "kind": summary.kind,
        "state": summary.state,
    })))
}

async fn run_engine(
    State(state): State<Shared>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut engine = state.lock().unwrap();
    if let Some(b) = req.get("budget").and_then(|v| v.as_object()) {
        if let Some(v) = b.get("max_depth").and_then(|v| v.as_u64()) {
            engine.budget.max_depth = v as u32;
        }
        if let Some(v) = b.get("max_total_bytes").and_then(|v| v.as_u64()) {
            engine.budget.max_total_bytes = v;
        }
        if let Some(v) = b.get("max_object_ratio").and_then(|v| v.as_f64()) {
            engine.budget.max_object_ratio = v;
        }
    }
    let state_name = match engine.run().map_err(ApiError::from_string)? {
        RunOutcome::Complete => "complete",
        RunOutcome::Paused(reason) => {
            return Ok(Json(json!({"state": "paused", "reason": reason})))
        }
    };
    Ok(Json(json!({"state": state_name})))
}

async fn engine_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let (status, message, expanded, run_count) = engine.store.engine_state();
    Json(json!({
        "status": status,
        "message": message,
        "expanded_bytes": expanded,
        "run_count": run_count,
        "budget": {
            "max_depth": engine.budget.max_depth,
            "max_total_bytes": engine.budget.max_total_bytes,
            "max_object_ratio": engine.budget.max_object_ratio,
        }
    }))
}

#[derive(serde::Deserialize)]
struct ImportQuery {
    name: Option<String>,
}

struct ApiError {
    status: StatusCode,
    message: String,
    payload: Option<serde_json::Value>,
}

impl ApiError {
    fn bad(msg: &str) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            message: msg.to_string(),
            payload: None,
        }
    }
    fn from_string(msg: String) -> Self {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            message: msg,
            payload: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let mut body = json!({"error": self.message});
        if let Some(p) = self.payload {
            body["dependents"] = p;
        }
        (self.status, Json(body)).into_response()
    }
}

fn candidate_unit(store: &Store, c: &crate::store::CandidateRow) -> serde_json::Value {
    let (loc, source_id) = match c.unit_kind.as_str() {
        "entry" => store
            .entry_by_id(c.unit_id)
            .map(|e| (format!("pack entry @{}", e.offset), e.source_id))
            .unwrap_or_default(),
        _ => store
            .loose_by_id(c.unit_id)
            .map(|l| ("loose object".to_string(), l.source_id))
            .unwrap_or_default(),
    };
    json!({
        "location": loc,
        "source_id": source_id,
        "source_name": store.source_name(source_id),
    })
}

async fn list_sources(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let sources: Vec<serde_json::Value> = engine
        .store
        .list_sources()
        .into_iter()
        .map(|s| {
            let dependents = engine.store.dependents_of_source(s.id).len();
            json!({
                "id": s.id,
                "name": s.name,
                "kind": s.kind,
                "size": s.size,
                "digest": s.digest,
                "dependents": dependents,
            })
        })
        .collect();
    Json(json!({"sources": sources}))
}

async fn source_dependents(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let deps: Vec<serde_json::Value> = engine
        .store
        .dependents_of_source(id)
        .into_iter()
        .map(|c| {
            json!({
                "candidate_id": c.id,
                "oid": c.oid,
                "kind": c.kind,
                "status": c.status,
                "unit": candidate_unit(&engine.store, &c),
            })
        })
        .collect();
    Json(json!({"dependents": deps}))
}

async fn delete_source(
    State(state): State<Shared>,
    Path(id): Path<i64>,
    Query(q): Query<ForceQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut engine = state.lock().unwrap();
    let deps = engine.store.dependents_of_source(id);
    if !q.force.unwrap_or(false) && !deps.is_empty() {
        let list: Vec<serde_json::Value> = deps
            .iter()
            .map(|c| {
                json!({"candidate_id": c.id, "oid": c.oid, "kind": c.kind, "status": c.status})
            })
            .collect();
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            message: format!("{} objects still depend on this source", list.len()),
            payload: Some(json!(list)),
        });
    }
    let external = engine.store.delete_source(id);
    let outcome = engine.run().map_err(ApiError::from_string)?;
    Ok(Json(json!({
        "deleted": id,
        "recomputed": external.len(),
        "state": match outcome { RunOutcome::Complete => "complete", RunOutcome::Paused(_) => "paused" },
    })))
}

#[derive(serde::Deserialize)]
struct ForceQuery {
    force: Option<bool>,
}


async fn list_packs(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let packs: Vec<serde_json::Value> = engine
        .store
        .packs()
        .into_iter()
        .map(|p| {
            let source = engine
                .store
                .list_sources()
                .into_iter()
                .find(|s| s.id == p.source_id);
            let entries: Vec<serde_json::Value> = engine
                .store
                .pack_entries(p.id)
                .into_iter()
                .map(|e| {
                    let candidate = engine.store.candidate("entry", e.id);
                    json!({
                        "idx": e.idx,
                        "offset": e.offset,
                        "kind": e.kind,
                        "declared_size": e.declared_size,
                        "header_len": e.header_len,
                        "data_start": e.data_start,
                        "data_len": e.data_len,
                        "end_offset": e.end_offset,
                        "base_offset": e.base_offset,
                        "base_oid": e.base_oid,
                        "size_ok": e.size_ok,
                        "crc32": format!("{:#010x}", e.crc32 as u32),
                        "candidate_id": candidate.as_ref().map(|c| c.id),
                        "status": candidate.as_ref().map(|c| c.status.clone()),
                    })
                })
                .collect();
            json!({
                "id": p.id,
                "source_name": source.as_ref().map(|s| s.name.clone()),
                "digest": source.as_ref().map(|s| s.digest.clone()),
                "version": p.version,
                "count": p.count,
                "trailer_ok": p.trailer_ok,
                "parse_error": p.parse_error,
                "entries": entries,
            })
        })
        .collect();
    let indexes: Vec<serde_json::Value> = {
        let mut stmt = engine
            .store
            .conn
            .prepare(
                "SELECT im.id, s.name, im.version, im.count, im.fanout
                 FROM indexes_meta im JOIN sources s ON s.id=im.source_id ORDER BY im.id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .map(|(id, name, version, count, fanout)| {
            json!({"id": id, "source_name": name, "version": version, "count": count, "fanout": fanout})
        })
        .collect()
    };
    Json(json!({"packs": packs, "indexes": indexes}))
}

async fn list_objects(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let mut groups: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for c in engine.store.all_candidates() {
        if c.status != "ok" {
            continue;
        }
        let oid_hex = c.oid.clone().unwrap_or_default();
        let entry = json!({
            "candidate_id": c.id,
            "kind": c.kind,
            "size": c.content.as_ref().map(|x| x.len()),
            "depth": c.depth,
            "unit": candidate_unit(&engine.store, &c),
        });
        groups
            .entry(oid_hex)
            .and_modify(|v| {
                v["sources"].as_array_mut().unwrap().push(entry.clone());
            })
            .or_insert_with(|| {
                json!({
                    "oid": oid_hex,
                    "kind": c.kind,
                    "size": c.content.as_ref().map(|x| x.len()),
                    "sources": vec![entry],
                })
            });
    }
    let objects: Vec<serde_json::Value> = groups.into_values().collect();
    Json(json!({"objects": objects}))
}

fn hex_preview(data: &[u8], limit: usize) -> String {
    let take = &data[..data.len().min(limit)];
    take.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn object_detail(
    State(state): State<Shared>,
    Path(oid_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state.lock().unwrap();
    let candidates = engine.store.candidates_by_oid(&oid_hex);
    if candidates.is_empty() {
        return Err(ApiError::bad("no candidates for oid"));
    }
    let primary = candidates
        .iter()
        .find(|c| c.status == "ok")
        .or_else(|| candidates.first())
        .unwrap()
        .clone();
    let content = primary.content.clone().unwrap_or_default();
    let cand_json: Vec<serde_json::Value> = candidates
        .iter()
        .map(|c| {
            json!({
                "candidate_id": c.id,
                "status": c.status,
                "error": c.error,
                "depth": c.depth,
                "generation": c.generation,
                "unit": candidate_unit(&engine.store, c),
            })
        })
        .collect();
    let steps: Vec<serde_json::Value> = engine
        .store
        .steps_of(primary.id)
        .into_iter()
        .map(|s| {
            json!({
                "step_no": s.step_no,
                "base_kind": s.base_kind,
                "base_desc": s.base_desc,
                "base_candidate_id": s.base_candidate_id,
                "input_len": s.input_len,
                "output_len": s.output_len,
                "verified": s.verified,
                "instructions": serde_json::from_str::<serde_json::Value>(&s.instr_json)
                    .unwrap_or(json!([])),
            })
        })
        .collect();
    let branches: Vec<_> = engine
        .store
        .branches()
        .into_iter()
        .filter(|(_, _, o, _)| o == &oid_hex)
        .collect();
    Ok(Json(json!({
        "oid": oid_hex,
        "kind": primary.kind,
        "status": primary.status,
        "size": content.len(),
        "hex": hex_preview(&content, 256),
        "text": String::from_utf8_lossy(&content[..content.len().min(4096)]).to_string(),
        "candidates": cand_json,
        "delta_steps": steps,
        "branches": branches.iter().map(|(id, name, _, cid)| {
            json!({"id": id, "name": name, "candidate_id": cid})
        }).collect::<Vec<_>>(),
    })))
}

async fn dag(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let nodes: Vec<serde_json::Value> = engine
        .store
        .all_candidates()
        .iter()
        .map(|c| {
            let depth = engine.store.steps_of(c.id).len();
            json!({
                "id": c.id,
                "oid": c.oid,
                "kind": c.kind,
                "status": c.status,
                "delta_steps": depth,
                "chain_depth": c.depth,
                "unit_kind": c.unit_kind,
                "unit_id": c.unit_id,
                "label": c.oid.clone().map(|o| o[..8].to_string())
                    .unwrap_or_else(|| format!("#{}", c.id)),
            })
        })
        .collect();
    let edges: Vec<serde_json::Value> = engine
        .store
        .all_steps()
        .into_iter()
        .filter_map(|s| {
            s.base_candidate_id.map(|b| {
                json!({
                    "from": b,
                    "to": s.candidate_id,
                    "base_kind": s.base_kind,
                    "base_desc": s.base_desc,
                    "input_len": s.input_len,
                    "output_len": s.output_len,
                    "verified": s.verified,
                })
            })
        })
        .collect();
    Json(json!({"nodes": nodes, "edges": edges}))
}

async fn list_errors(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let errors: Vec<serde_json::Value> = engine
        .store
        .errors()
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id,
                "scope": e.scope,
                "ref_id": e.ref_id,
                "kind": e.kind,
                "message": e.message,
                "evidence": e.evidence,
            })
        })
        .collect();
    Json(json!({"errors": errors}))
}

async fn list_blocked(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let blocked: Vec<serde_json::Value> = engine
        .store
        .all_blocks()
        .into_iter()
        .iter()
        .map(|(cid, by, reason)| {
            let candidate = engine.store.candidate_by_id(*cid);
            json!({
                "candidate_id": cid,
                "oid": candidate.as_ref().and_then(|c| c.oid.clone()),
                "status": candidate.as_ref().map(|c| c.status.clone()),
                "error": candidate.as_ref().and_then(|c| c.error.clone()),
                "blocked_by": by,
                "reason": reason,
                "unit": candidate.as_ref().map(|c| candidate_unit(&engine.store, c)),
            })
        })
        .collect();
    Json(json!({"blocked": blocked}))
}

async fn candidates_of(
    State(state): State<Shared>,
    Path(oid_hex): Path<String>,
) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let candidates: Vec<serde_json::Value> = engine
        .store
        .candidates_by_oid(&oid_hex)
        .into_iter()
        .iter()
        .map(|c| {
            json!({
                "candidate_id": c.id,
                "status": c.status,
                "error": c.error,
                "unit": candidate_unit(&engine.store, c),
            })
        })
        .collect();
    Json(json!({"oid": oid_hex, "candidates": candidates}))
}

async fn list_branches(State(state): State<Shared>) -> Json<serde_json::Value> {
    let engine = state.lock().unwrap();
    let branches: Vec<serde_json::Value> = engine
        .store
        .branches()
        .into_iter()
        .iter()
        .map(|(id, name, oid, cid)| {
            json!({"id": id, "name": name, "oid": oid, "candidate_id": cid})
        })
        .collect();
    Json(json!({"branches": branches}))
}

async fn create_branch(
    State(state): State<Shared>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad("missing name"))?;
    let oid_hex = req
        .get("oid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad("missing oid"))?;
    let candidate_id = req
        .get("candidate_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ApiError::bad("missing candidate_id"))?;
    let engine = state.lock().unwrap();
    engine
        .store
        .add_branch(name, oid_hex, candidate_id)
        .map_err(ApiError::from_string)?;
    Ok(Json(json!({"ok": true})))
}

fn _ensure_oid_used(_: oid::Oid) {}

pub const PAGE_HTML: &str = include_str!("page.html");
