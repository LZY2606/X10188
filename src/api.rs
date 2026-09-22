//! Axum HTTP layer: JSON APIs, multipart import, analysis branches and the
//! single-page UI.

use crate::db::Db;
use crate::importer;
use crate::model::Budgets;
use crate::resolver;
use axum::{
    extract::{Multipart, Path as AxPath, Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub struct AppState {
    pub db: Db,
    pub data_dir: std::path::PathBuf,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/static/app.js", get(app_js))
        .route("/static/app.css", get(app_css))
        .route("/api/sources", get(list_sources).post(upload))
        .route("/api/sources/{id}", post(delete_source))
        .route("/api/sources/{id}/dependents", get(source_dependents))
        .route("/api/packs", get(list_packs))
        .route("/api/nodes", get(list_nodes))
        .route("/api/nodes/{id}/{branch_id}", get(node_detail))
        .route("/api/nodes/{id}/", get(node_detail_root))
        .route("/api/branches", get(list_branches).post(create_branch))
        .route("/api/branches/{id}", get(branch_detail))
        .route("/api/branches/{id}/pin", post(pin_branch))
        .route("/api/resume", post(resume))
        .route("/api/budgets", get(get_budgets).post(set_budgets))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}
async fn app_js() -> (StatusCode, &'static str) {
    (StatusCode::OK, include_str!("static/app.js"))
}
async fn app_css() -> (StatusCode, &'static str) {
    (StatusCode::OK, include_str!("static/app.css"))
}

async fn list_sources(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows = {
        let c = st.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT id,filename,kind,size,linked_pack_source_id,idx_checksum_ok,
                        pack_checksum_matches,parse_errors FROM sources ORDER BY id",
            )
            .unwrap();
        s.query_map([], |r| {
            let errs: String = r.get(7)?;
            Ok(serde_json::json!({
                "id": r.get::<_,i64>(0)?,
                "filename": r.get::<_,String>(1)?,
                "kind": r.get::<_,String>(2)?,
                "size": r.get::<_,i64>(3)?,
                "linked_pack": r.get::<_,Option<i64>>(4)?,
                "idx_checksum_ok": r.get::<_,Option<i64>>(5)?.map(|v| v!=0),
                "pack_checksum_matches": r.get::<_,Option<i64>>(6)?.map(|v| v!=0),
                "parse_errors": serde_json::from_str::<Vec<String>>(&errs).unwrap_or_default(),
            }))
        })
        .unwrap()
        .flatten()
        .collect::<Vec<_>>()
    };
    Json(json!({ "sources": rows }))
}

async fn upload(
    State(st): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut imported = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let name = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "object".into());
        let data = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let data = data.to_vec();
        let st2 = Arc::clone(&st);
        let name2 = name.clone();
        let report = tokio::task::spawn_blocking(move || {
            importer::import_bytes(&st2.db, &st2.data_dir, &name2, &data)
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        imported.push(json!({
            "source_id": report.source_id,
            "kind": report.kind,
            "filename": name,
            "nodes_added": report.nodes_added,
            "candidates_added": report.candidates_added,
            "errors": report.errors,
        }));
    }
    // Re-run resolution after import (incremental-aware).
    let budgets = read_budgets(&st.db);
    let st2 = Arc::clone(&st);
    let summary = tokio::task::spawn_blocking(move || {
        resolver::recompute_after_import(&st2.db, budgets)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "imported": imported, "summary": summary_json(&summary) })))
}

fn read_budgets(db: &Db) -> Budgets {
    let mut b = Budgets::defaults();
    let c = db.0.lock().unwrap();
    if let Ok(v) = c.query_row(
        "SELECT value FROM kv WHERE key='max_depth'",
        [],
        |r| r.get::<_, String>(0),
    ) {
        b.max_depth = v.parse().unwrap_or(b.max_depth);
    }
    if let Ok(v) = c.query_row(
        "SELECT value FROM kv WHERE key='total_bytes'",
        [],
        |r| r.get::<_, String>(0),
    ) {
        b.total_bytes = v.parse().unwrap_or(b.total_bytes);
    }
    if let Ok(v) = c.query_row(
        "SELECT value FROM kv WHERE key='single_ratio'",
        [],
        |r| r.get::<_, String>(0),
    ) {
        b.single_ratio = v.parse().unwrap_or(b.single_ratio);
    }
    b
}

fn write_budgets(db: &Db, b: &Budgets) {
    let c = db.0.lock().unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);",
    )
    .unwrap();
    for (k, v) in [
        ("max_depth", b.max_depth.to_string()),
        ("total_bytes", b.total_bytes.to_string()),
        ("single_ratio", b.single_ratio.to_string()),
    ] {
        c.execute(
            "INSERT INTO kv(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2",
            params![k, v],
        )
        .unwrap();
    }
}

fn summary_json(s: &resolver::ResolveSummary) -> serde_json::Value {
    json!({
        "resolved": s.resolved,
        "missing_base": s.missing_base,
        "cycle": s.cycle,
        "bad_object": s.bad_object,
        "budget_paused": s.budget_paused,
        "too_large": s.too_large,
        "too_deep": s.too_deep,
        "parse_error": s.parse_error,
        "bytes_used": s.bytes_used,
        "paused": s.paused,
    })
}

async fn get_budgets(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let b = read_budgets(&st.db);
    Json(json!({
        "max_depth": b.max_depth,
        "total_bytes": b.total_bytes,
        "single_ratio": b.single_ratio,
        "single_cap": b.single_cap()
    }))
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<usize>,
    total_bytes: Option<u64>,
    single_ratio: Option<f64>,
}

async fn set_budgets(
    State(st): State<Arc<AppState>>,
    Json(body): Json<BudgetBody>,
) -> Json<serde_json::Value> {
    let mut b = read_budgets(&st.db);
    if let Some(v) = body.max_depth {
        b.max_depth = v;
    }
    if let Some(v) = body.total_bytes {
        b.total_bytes = v;
    }
    if let Some(v) = body.single_ratio {
        b.single_ratio = v.clamp(0.0, 1.0);
    }
    write_budgets(&st.db, &b);
    Json(json!({ "ok": true, "single_cap": b.single_cap() }))
}

#[derive(Deserialize)]
struct ResumeBody {
    branch_id: Option<i64>,
    total_bytes: Option<u64>,
}

async fn resume(
    State(st): State<Arc<AppState>>,
    body: Option<Json<ResumeBody>>,
) -> Json<serde_json::Value> {
    let branch_id = body.as_ref().and_then(|b| b.branch_id).unwrap_or(1);
    let mut budgets = read_budgets(&st.db);
    if let Some(Json(b)) = &body {
        if let Some(v) = b.total_bytes {
            budgets.total_bytes = v;
        }
    }
    let db_ref = &st.db;
    let summary = resolver::resolve_all(
        db_ref,
        resolver::ResolveOptions {
            branch_id,
            budgets,
            only_nodes: None,
            pin_node: None,
            resume: true,
        },
    );
    Json(summary_json(&summary))
}

async fn list_packs(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let packs_base: Vec<serde_json::Value> = {
        let c = st.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT ps.source_id,s.filename,ps.version,ps.object_count,ps.raw_len,ps.trailer_sha,
                        ps.trailer_ok,ps.scan_errors
                 FROM pack_scan ps JOIN sources s ON s.id=ps.source_id ORDER BY ps.source_id",
            )
            .unwrap();
        s.query_map([], |r| {
            let errs: String = r.get(7)?;
            Ok(json!({
                "source_id": r.get::<_,i64>(0)?,
                "filename": r.get::<_,String>(1)?,
                "version": r.get::<_,i64>(2)?,
                "object_count": r.get::<_,i64>(3)?,
                "raw_len": r.get::<_,i64>(4)?,
                "trailer_sha": r.get::<_,String>(5)?,
                "trailer_ok": r.get::<_,i64>(6)? != 0,
                "scan_errors": serde_json::from_str::<Vec<String>>(&errs).unwrap_or_default(),
            }))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    let mut out = Vec::new();
    for mut pack in packs_base {
        let sid = pack["source_id"].as_i64().unwrap();
        let entries = {
            let c = st.db.0.lock().unwrap();
            let mut q = c
                .prepare(
                    "SELECT id,pack_offset,kind,object_type,declared_size,inflated_size,
                            header_len,compressed_len,record_crc,expected_crc,crc_ok,base_ofs,base_ref_oid,parse_errors
                     FROM nodes WHERE source_id=?1 ORDER BY pack_offset",
                )
                .unwrap();
            q.query_map(params![sid], |r| {
                let errs: String = r.get(13)?;
                Ok(json!({
                    "node_id": r.get::<_,i64>(0)?,
                    "offset": r.get::<_,i64>(1)?,
                    "kind": r.get::<_,String>(2)?,
                    "object_type": r.get::<_,Option<i64>>(3)?,
                    "declared_size": r.get::<_,i64>(4)?,
                    "inflated_size": r.get::<_,i64>(5)?,
                    "header_len": r.get::<_,i64>(6)?,
                    "compressed_len": r.get::<_,i64>(7)?,
                    "record_crc": r.get::<_,Option<i64>>(8)?.map(|v| format!("{v:#010x}")),
                    "expected_crc": r.get::<_,Option<i64>>(9)?.map(|v| format!("{v:#010x}")),
                    "crc_ok": r.get::<_,Option<i64>>(10)?.map(|v| v!=0),
                    "base_ofs": r.get::<_,Option<i64>>(11)?,
                    "base_ref_oid": r.get::<_,Option<String>>(12)?,
                    "parse_errors": serde_json::from_str::<Vec<String>>(&errs).unwrap_or_default(),
                }))
            })
            .unwrap()
            .flatten()
            .collect::<Vec<_>>()
        };
        pack["entries"] = json!(entries);
        out.push(pack);
    }
    Json(json!({ "packs": out }))
}

#[derive(Deserialize)]
struct NodesQuery {
    branch_id: Option<i64>,
}

async fn list_nodes(
    State(st): State<Arc<AppState>>,
    Query(q): Query<NodesQuery>,
) -> Json<serde_json::Value> {
    let branch_id = q.branch_id.unwrap_or(1);
    let c = st.db.0.lock().unwrap();
    let mut s = c
        .prepare(
            "SELECT n.id,n.source_id,n.pack_offset,n.kind,n.object_type,n.declared_size,n.inflated_size,
                    n.base_ofs,n.base_ref_oid,n.parse_errors,
                    r.status,r.resolved_oid,r.object_type,length(r.content),r.chain_depth,r.error,r.blocked_chain
             FROM nodes n
             LEFT JOIN resolutions r ON r.node_id=n.id AND r.branch_id=?1
             ORDER BY n.source_id,n.pack_offset",
        )
        .unwrap();
    let rows: Vec<serde_json::Value> = s
        .query_map(params![branch_id], |r| {
            let errs: String = r.get(9).unwrap_or_default();
            let chain: Option<String> = r.get(16).ok();
            Ok(json!({
                "id": r.get::<_,i64>(0)?,
                "source_id": r.get::<_,i64>(1)?,
                "offset": r.get::<_,i64>(2)?,
                "kind": r.get::<_,String>(3)?,
                "object_type": r.get::<_,Option<i64>>(4)?,
                "declared_size": r.get::<_,i64>(5)?,
                "inflated_size": r.get::<_,i64>(6)?,
                "base_ofs": r.get::<_,Option<i64>>(7)?,
                "base_ref_oid": r.get::<_,Option<String>>(8)?,
                "parse_errors": serde_json::from_str::<Vec<String>>(&errs).unwrap_or_default(),
                "status": r.get::<_,Option<String>>(10)?,
                "resolved_oid": r.get::<_,Option<String>>(11)?,
                "resolved_type": r.get::<_,Option<i64>>(12)?,
                "content_len": r.get::<_,Option<i64>>(13)?,
                "chain_depth": r.get::<_,Option<i64>>(14)?,
                "error": r.get::<_,Option<String>>(15)?,
                "blocked_chain": chain.and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok()),
            }))
        })
        .unwrap()
        .flatten()
        .collect();
    Json(json!({ "nodes": rows }))
}

async fn node_detail(
    State(st): State<Arc<AppState>>,
    AxPath((id, branch_id)): AxPath<(i64, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let branch_id = branch_id;
    let value = {
        let c = st.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT n.id,n.source_id,n.pack_offset,n.kind,n.object_type,n.declared_size,n.inflated_size,
                        n.header_len,n.compressed_len,n.record_crc,n.expected_crc,n.crc_ok,
                        n.base_ofs,n.base_ref_oid,n.payload,n.parse_errors,
                        r.status,r.resolved_oid,r.object_type,r.content,r.chain_depth,r.error,r.blocked_chain
                 FROM nodes n
                 LEFT JOIN resolutions r ON r.node_id=n.id AND r.branch_id=?2
                 WHERE n.id=?1",
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        s.query_row(params![id, branch_id], |r| {
            let errs: String = r.get(15).unwrap_or_default();
            let payload: Vec<u8> = r.get(14).unwrap_or_default();
            let content: Vec<u8> = r.get(19).unwrap_or_default();
            let chain: Option<String> = r.get(22).ok();
            Ok(json!({
                "id": r.get::<_,i64>(0)?,
                "source_id": r.get::<_,i64>(1)?,
                "offset": r.get::<_,i64>(2)?,
                "kind": r.get::<_,String>(3)?,
                "object_type": r.get::<_,Option<i64>>(4)?,
                "declared_size": r.get::<_,i64>(5)?,
                "inflated_size": r.get::<_,i64>(6)?,
                "header_len": r.get::<_,i64>(7)?,
                "compressed_len": r.get::<_,i64>(8)?,
                "record_crc": r.get::<_,Option<i64>>(9)?.map(|v| format!("{v:#010x}")),
                "expected_crc": r.get::<_,Option<i64>>(10)?.map(|v| format!("{v:#010x}")),
                "crc_ok": r.get::<_,Option<i64>>(11)?.map(|v| v!=0),
                "base_ofs": r.get::<_,Option<i64>>(12)?,
                "base_ref_oid": r.get::<_,Option<String>>(13)?,
                "parse_errors": serde_json::from_str::<Vec<String>>(&errs).unwrap_or_default(),
                "payload_preview": preview_bytes(&payload, 4096),
                "status": r.get::<_,Option<String>>(16)?,
                "resolved_oid": r.get::<_,Option<String>>(17)?,
                "resolved_type": r.get::<_,Option<i64>>(18)?,
                "content_preview": preview_bytes(&content, 4096),
                "content_len": content.len(),
                "chain_depth": r.get::<_,Option<i64>>(15 + 5)?,
                "error": r.get::<_,Option<String>>(21)?,
                "blocked_chain": chain.and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok()),
            }))
        })
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?
    };
    // candidates + delta steps
    let candidates: Vec<serde_json::Value> = {
        let c = st.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT id,oid,origin,source_label,hash_match,confidence,sort_key
                 FROM candidates WHERE node_id=?1 ORDER BY sort_key DESC, confidence DESC, id",
            )
            .unwrap();
        s.query_map(params![id], |r| {
            Ok(json!({
                "id": r.get::<_,i64>(0)?,
                "oid": r.get::<_,String>(1)?,
                "origin": r.get::<_,String>(2)?,
                "source_label": r.get::<_,String>(3)?,
                "hash_match": r.get::<_,i64>(4)? != 0,
                "confidence": r.get::<_,i64>(5)?,
            }))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    let steps: Vec<serde_json::Value> = {
        let c = st.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT step_index,base_node_id,kind,delta_start,delta_end,copy_offset,size,
                        input_pos,output_len_after,check_ok,check_error
                 FROM delta_steps WHERE branch_id=?1 AND node_id=?2
                 ORDER BY id",
            )
            .unwrap();
        s.query_map(params![branch_id, id], |r| {
            Ok(json!({
                "step_index": r.get::<_,i64>(0)?,
                "base_node_id": r.get::<_,Option<i64>>(1)?,
                "kind": r.get::<_,String>(2)?,
                "delta_start": r.get::<_,i64>(3)?,
                "delta_end": r.get::<_,i64>(4)?,
                "copy_offset": r.get::<_,Option<i64>>(5)?,
                "size": r.get::<_,i64>(6)?,
                "input_pos": r.get::<_,i64>(7)?,
                "output_len_after": r.get::<_,i64>(8)?,
                "check_ok": r.get::<_,i64>(9)? != 0,
                "check_error": r.get::<_,Option<String>>(10)?,
            }))
        })
        .unwrap()
        .flatten()
        .collect()
    };
    let mut v = value;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("candidates".into(), json!(candidates));
        obj.insert("delta_steps".into(), json!(steps));
    }
    Ok(Json(v))
}

fn preview_bytes(data: &[u8], limit: usize) -> serde_json::Value {
    let truncated = data.len() > limit;
    let head = &data[..data.len().min(limit)];
    let is_text = head
        .iter()
        .take(2048)
        .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b));
    json!({
        "hex": hex_encode(head),
        "ascii": if is_text {
            Some(String::from_utf8_lossy(head).to_string())
        } else {
            None
        },
        "is_text": is_text,
        "truncated": truncated,
        "shown": head.len(),
        "total": data.len(),
    })
}

fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

async fn list_branches(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let c = st.db.0.lock().unwrap();
    let mut s = c
        .prepare(
            "SELECT b.id,b.name,b.is_trunk,b.pinned_node_id,b.pinned_oid,
                    (SELECT COUNT(*) FROM resolutions r WHERE r.branch_id=b.id AND r.status='resolved'),
                    (SELECT COUNT(*) FROM resolutions r WHERE r.branch_id=b.id AND r.status<>'resolved')
             FROM branches b ORDER BY b.id",
        )
        .unwrap();
    let rows: Vec<serde_json::Value> = s
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_,i64>(0)?,
                "name": r.get::<_,String>(1)?,
                "is_trunk": r.get::<_,i64>(2)? != 0,
                "pinned_node_id": r.get::<_,Option<i64>>(3)?,
                "pinned_oid": r.get::<_,Option<String>>(4)?,
                "resolved": r.get::<_,i64>(5)?,
                "unresolved": r.get::<_,i64>(6)?,
            }))
        })
        .unwrap()
        .flatten()
        .collect();
    Json(json!({ "branches": rows }))
}

#[derive(Deserialize)]
struct BranchBody {
    name: String,
}

async fn create_branch(
    State(st): State<Arc<AppState>>,
    Json(body): Json<BranchBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let id = {
        let c = st.db.0.lock().unwrap();
        c.execute(
            "INSERT INTO branches(name,is_trunk) VALUES(?1,0)",
            params![body.name],
        )
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
        c.last_insert_rowid()
    };
    // Seed branch from trunk resolutions, then it can diverge via a pin.
    {
        let c = st.db.0.lock().unwrap();
        c.execute(
            "INSERT INTO resolutions(branch_id,node_id,status,object_type,resolved_oid,content,chain_depth,bytes_charged)
             SELECT ?1,node_id,status,object_type,resolved_oid,content,chain_depth,0 FROM resolutions WHERE branch_id=1",
            params![id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

async fn node_detail_root(
    State(st): State<Arc<AppState>>,
    AxPath(id): AxPath<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    node_detail(State(st), AxPath((id, 1i64))).await
}

async fn branch_detail(
    State(st): State<Arc<AppState>>,
    AxPath(id): AxPath<i64>,
) -> Json<serde_json::Value> {
    let c = st.db.0.lock().unwrap();
    let info: Option<serde_json::Value> = c
        .query_row(
            "SELECT id,name,is_trunk,pinned_node_id,pinned_oid FROM branches WHERE id=?1",
            params![id],
            |r| {
                Ok(json!({
                    "id": r.get::<_,i64>(0)?,
                    "name": r.get::<_,String>(1)?,
                    "is_trunk": r.get::<_,i64>(2)? != 0,
                    "pinned_node_id": r.get::<_,Option<i64>>(3)?,
                    "pinned_oid": r.get::<_,Option<String>>(4)?,
                }))
            },
        )
        .ok();
    Json(json!({ "branch": info }))
}

#[derive(Deserialize)]
struct PinBody {
    node_id: i64,
    oid: String,
}

/// Fix a conflicting OID source for this branch, then recompute only the
/// affected dependency subgraph using that pinned candidate.
async fn pin_branch(
    State(st): State<Arc<AppState>>,
    AxPath(branch_id): AxPath<i64>,
    Json(body): Json<PinBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if branch_id == 1 {
        return Err((
            StatusCode::CONFLICT,
            "trunk cannot be pinned; create an analysis branch".into(),
        ));
    }
    {
        let c = st.db.0.lock().unwrap();
        let exists: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM candidates WHERE node_id=?1 AND oid=?2",
                params![body.node_id, body.oid],
                |r| r.get(0),
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if exists == 0 {
            return Err((StatusCode::BAD_REQUEST, "candidate not found".into()));
        }
    }
    // Affected subgraph: everything depending on the pinned node plus itself.
    let affected = crate::resolver::affected_subgraph(&st.db, &[body.node_id]);
    {
        let c = st.db.0.lock().unwrap();
        c.execute(
            "UPDATE branches SET pinned_node_id=?1,pinned_oid=?2 WHERE id=?3",
            params![body.node_id, body.oid, branch_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Force a "pinned" candidate at high confidence scoped via origin label.
        c.execute(
            "UPDATE candidates SET confidence=CASE WHEN node_id=?1 AND oid=?2 THEN 1000 ELSE confidence END",
            params![body.node_id, body.oid],
        )
        .unwrap();
        // Reset branch resolutions for the affected subgraph so they recompute.
        for nid in &affected {
            c.execute(
                "DELETE FROM resolutions WHERE branch_id=?1 AND node_id=?2",
                params![branch_id, nid],
            )
            .unwrap();
            c.execute(
                "DELETE FROM delta_steps WHERE branch_id=?1 AND node_id=?2",
                params![branch_id, nid],
            )
            .unwrap();
        }
    }
    let budgets = read_budgets(&st.db);
    let opts = crate::resolver::ResolveOptions {
        branch_id,
        budgets,
        only_nodes: Some(affected),
        pin_node: Some(body.node_id),
        resume: true,
    };
    let summary = crate::resolver::resolve_all(&st.db, opts);
    Ok(Json(json!({ "ok": true, "summary": summary_json(&summary) })))
}

async fn source_dependents(
    State(st): State<Arc<AppState>>,
    AxPath(id): AxPath<i64>,
) -> Json<serde_json::Value> {
    let deps = compute_source_dependents(&st.db, id);
    Json(json!({ "source_id": id, "dependents": deps }))
}

fn compute_source_dependents(db: &Db, source_id: i64) -> Vec<serde_json::Value> {
    // Nodes belonging to this source and every node whose chain depends on
    // them, restricted to currently resolved/unresolved objects.
    let own: Vec<i64> = {
        let c = db.0.lock().unwrap();
        let mut s = c
            .prepare("SELECT id FROM nodes WHERE source_id=?1")
            .unwrap();
        s.query_map(params![source_id], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    let closure = crate::resolver::affected_subgraph(db, &own);
    let c = db.0.lock().unwrap();
    let mut s = c
        .prepare(
            "SELECT n.id,n.source_id,n.pack_offset,n.kind,r.status,r.resolved_oid
             FROM nodes n LEFT JOIN resolutions r ON r.node_id=n.id AND r.branch_id=1
             WHERE n.id IN (SELECT value FROM json_each(?1))",
        )
        .unwrap();
    // json_each needs a JSON array string.
    let arr = serde_json::to_string(
        &closure
            .iter()
            .map(|v| *v)
            .collect::<std::collections::BTreeSet<_>>(),
    )
    .unwrap();
    s.query_map(params![arr], |r| {
        Ok(json!({
            "node_id": r.get::<_,i64>(0)?,
            "source_id": r.get::<_,i64>(1)?,
            "offset": r.get::<_,i64>(2)?,
            "kind": r.get::<_,String>(3)?,
            "status": r.get::<_,Option<String>>(4)?,
            "resolved_oid": r.get::<_,Option<String>>(5)?,
        }))
    })
    .unwrap()
    .flatten()
    .collect()
}

/// Delete a source only when no object still depends on it; otherwise the
/// caller receives the full dependency list so the UI can confirm.
#[derive(Deserialize)]
struct DeleteBody {
    confirm: Option<bool>,
}

async fn delete_source(
    State(st): State<Arc<AppState>>,
    AxPath(id): AxPath<i64>,
    body: Option<Json<DeleteBody>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let deps = compute_source_dependents(&st.db, id);
    // We consider nodes owned by other sources that depend on nodes of this
    // source as the blocking set; the source's own nodes are removed with it.
    let external: Vec<_> = deps
        .iter()
        .filter(|d| d["source_id"].as_i64() != Some(id))
        .collect();
    if !external.is_empty() && body.and_then(|b| b.0.confirm) != Some(true) {
        return Err((
            StatusCode::CONFLICT,
            serde_json::to_string(&json!({
                "error": "source still required by objects from other sources",
                "dependents": external
            }))
            .unwrap(),
        ));
    }
    let path: String = {
        let c = st.db.0.lock().unwrap();
        c.query_row(
            "SELECT stored_path FROM sources WHERE id=?1",
            params![id],
            |r| r.get::<_, String>(0),
        )
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?
    };
    {
        let mut c = st.db.0.lock().unwrap();
        let tx = c.transaction().unwrap();
        let node_ids: Vec<i64> = {
            let mut s = tx.prepare("SELECT id FROM nodes WHERE source_id=?1").unwrap();
            s.query_map(params![id], |r| r.get::<_, i64>(0))
                .unwrap()
                .flatten()
                .collect()
        };
        for nid in node_ids {
            tx.execute("DELETE FROM delta_steps WHERE node_id=?1", params![nid])
                .unwrap();
            tx.execute("DELETE FROM resolutions WHERE node_id=?1", params![nid])
                .unwrap();
            tx.execute("DELETE FROM candidates WHERE node_id=?1", params![nid])
                .unwrap();
        }
        tx.execute("DELETE FROM nodes WHERE source_id=?1", params![id])
            .unwrap();
        tx.execute("DELETE FROM pack_scan WHERE source_id=?1", params![id])
            .unwrap();
        tx.execute("DELETE FROM sources WHERE id=?1", params![id])
            .unwrap();
        tx.commit().unwrap();
    }
    let _ = std::fs::remove_file(&path);
    Ok(Json(json!({ "deleted": id })))
}
