//! Axum HTTP layer: JSON API plus the single-page microscope UI.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::analyze::engine::analyze_branch;
use crate::store::{Budget, Store, DEFAULT_BRANCH};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(state))
        .route("/api/sources", get(list_sources).post(import_multipart))
        .route("/api/sources/import-path", post(import_path))
        .route("/api/sources/:id/dependents", get(source_dependents))
        .route("/api/sources/:id", axum::routing::delete(delete_source))
        .route("/api/analyze", post(run_analyze))
        .route("/api/runs", get(list_runs))
        .route("/api/runs/:id", get(run_detail))
        .route("/api/branches", get(list_branches).post(create_branch))
        .route("/api/branches/:name/pins", post(set_pin))
        .route("/api/branches/:name/pins/:oid", axum::routing::delete(clear_pin))
        .route("/api/objects", get(list_objects))
        .route("/api/objects/:oid", get(object_detail))
        .route("/api/packs", get(pack_layouts))
        .with_state(AppState { store })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

type ApiResult = Result<Json<serde_json::Value>, ApiError>;

struct ApiError(anyhow::Error);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}
impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

#[derive(Deserialize)]
struct BranchQuery {
    branch: Option<String>,
}

fn branch_of(q: &Option<BranchQuery>) -> String {
    q.as_ref()
        .and_then(|b| b.branch.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_BRANCH.to_string())
}

async fn state(
    State(st): State<AppState>,
    Query(q): Query<BranchQuery>,
) -> ApiResult {
    let branch = q.branch.clone().unwrap_or_else(|| DEFAULT_BRANCH.into());
    let conn = st.store.db.lock().unwrap();
    let sources: Vec<serde_json::Value> = {
        let mut stmt = conn.prepare(
            "SELECT id, kind, filename, size, checksum, paired_source_id,
                    parse_summary, parse_errors, imported_at
             FROM sources ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "kind": r.get::<_, String>(1)?,
                "filename": r.get::<_, String>(2)?,
                "size": r.get::<_, i64>(3)?,
                "checksum": r.get::<_, Option<String>>(4)?,
                "paired_source_id": r.get::<_, Option<i64>>(5)?,
                "parse_summary": r.get::<_, String>(6)?,
                "parse_errors": serde_json::from_str::<Vec<String>>(
                    &r.get::<_, String>(7)?).unwrap_or_default(),
                "imported_at": r.get::<_, String>(8)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let branches: Vec<String> = {
        let mut stmt = conn.prepare("SELECT name FROM branches ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let last_run: Option<serde_json::Value> = conn
        .query_row(
            "SELECT id, status, summary, depth_used, bytes_used FROM runs
             WHERE branch=?1 ORDER BY id DESC LIMIT 1",
            params![branch],
            |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "status": r.get::<_, String>(1)?,
                    "summary": r.get::<_, String>(2)?,
                    "depth_used": r.get::<_, i64>(3)?,
                    "bytes_used": r.get::<_, i64>(4)?,
                }))
            },
        )
        .optional()?;
    Ok(Json(json!({
        "branch": branch,
        "branches": branches,
        "sources": sources,
        "last_run": last_run,
    })))
}

use axum::extract::multipart::Multipart;
use rusqlite::OptionalExtension;

async fn list_sources(State(st): State<AppState>) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, kind, filename, size, checksum, paired_source_id,
                parse_summary, parse_errors FROM sources ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "filename": r.get::<_, String>(2)?,
            "size": r.get::<_, i64>(3)?,
            "checksum": r.get::<_, Option<String>>(4)?,
            "paired_source_id": r.get::<_, Option<i64>>(5)?,
            "parse_summary": r.get::<_, String>(6)?,
            "parse_errors": serde_json::from_str::<Vec<String>>(
                &r.get::<_, String>(7)?).unwrap_or_default(),
        }))
    })?;
    Ok(Json(json!({ "sources": rows.collect::<rusqlite::Result<Vec<_>>>()? })))
}

async fn import_multipart(
    State(st): State<AppState>,
    mut mp: Multipart,
) -> ApiResult {
    let mut reports = Vec::new();
    while let Some(field) = mp.next_field().await.map_err(anyhow::Error::from)? {
        let filename = field.file_name().unwrap_or("object").to_string();
        let bytes = field.bytes().await.map_err(anyhow::Error::from)?.to_vec();
        let report = st.store.import_bytes(&filename, &bytes)?;
        reports.push(json!({
            "source_id": report.source_id,
            "kind": report.kind,
            "filename": filename,
            "candidate_count": report.candidate_count,
            "paired_id": report.paired_id,
            "parse_errors": report.parse_errors,
        }));
    }
    Ok(Json(json!({ "imported": reports })))
}

#[derive(Deserialize)]
struct ImportPath {
    path: String,
}

async fn import_path(
    State(st): State<AppState>,
    Form(form): Form<ImportPath>,
) -> ApiResult {
    let filename = form
        .path
        .split('/')
        .next_back()
        .filter(|s| !s.is_empty())
        .unwrap_or("object")
        .to_string();
    let bytes = tokio::fs::read(&form.path)
        .await
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", form.path))?;
    let report = st.store.import_bytes(&filename, &bytes)?;
    Ok(Json(json!({
        "source_id": report.source_id,
        "kind": report.kind,
        "candidate_count": report.candidate_count,
        "parse_errors": report.parse_errors,
    })))
}

/// Objects whose current reconstruction depends on a source: resolved objects
/// whose chosen candidate chain touches the source. Shown before deletion.
async fn source_dependents(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<BranchQuery>,
) -> ApiResult {
    let branch = branch_of(&Some(q));
    let conn = st.store.db.lock().unwrap();
    // Latest complete run for the branch.
    let run_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM runs WHERE branch=?1 AND status='complete'
             ORDER BY id DESC LIMIT 1",
            params![branch],
            |r| r.get(0),
        )
        .optional()?;
    let mut dependents = Vec::new();
    let mut candidates_in_source = 0i64;
    if let Some(run_id) = run_id {
        let mut stmt = conn.prepare(
            "SELECT r.oid, r.kind_name, r.content_len, r.candidate_id
             FROM resolved r
             WHERE r.run_id=?1 AND (
                r.candidate_id IN (SELECT id FROM objects WHERE source_id=?2)
                OR r.oid IN (
                    SELECT o.oid FROM objects o WHERE o.source_id=?2
                )
             )
             ORDER BY r.oid",
        )?;
        let rows = stmt.query_map(params![run_id, id], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "kind": r.get::<_, String>(1)?,
                "content_len": r.get::<_, i64>(2)?,
                "candidate_id": r.get::<_, i64>(3)?,
            }))
        })?;
        dependents = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    }
    candidates_in_source = conn.query_row(
        "SELECT COUNT(*) FROM objects WHERE source_id=?1",
        params![id],
        |r| r.get(0),
    )?;
    let (filename, kind): (String, String) = conn.query_row(
        "SELECT filename, kind FROM sources WHERE id=?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Json(json!({
        "source_id": id,
        "filename": filename,
        "kind": kind,
        "candidate_rows": candidates_in_source,
        "dependents": dependents,
        "safe_to_delete": dependents.is_empty(),
        "note": if dependents.is_empty() {
            "no reconstructed object depends on this source"
        } else {
            "these objects still depend on this source; delete invalidates them"
        }
    })))
}

async fn delete_source(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<DeleteQuery>,
) -> ApiResult {
    if !q.confirm.unwrap_or(false) {
        return Err(anyhow::anyhow!(
            "refusing to delete without confirm=true; inspect /api/sources/{id}/dependents first"
        )
        .into());
    }
    let mut conn = st.store.db.lock().unwrap();
    let path: String = conn.query_row(
        "SELECT stored_path FROM sources WHERE id=?1",
        params![id],
        |r| r.get(0),
    )?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM sources WHERE id=?1", params![id])?;
    tx.commit()?;
    drop(conn);
    let _ = std::fs::remove_file(st.store.data_dir().join(path));
    Ok(Json(json!({ "deleted": id })))
}

#[derive(Deserialize)]
struct DeleteQuery {
    confirm: Option<bool>,
}

#[derive(Deserialize)]
struct AnalyzeBody {
    branch: Option<String>,
    max_depth: Option<u32>,
    max_expand_bytes: Option<u64>,
    max_single_bytes: Option<u64>,
    resume_run_id: Option<i64>,
}

async fn run_analyze(
    State(st): State<AppState>,
    Json(body): Json<AnalyzeBody>,
) -> ApiResult {
    let branch = body.branch.unwrap_or_else(|| DEFAULT_BRANCH.into());
    let default = Budget::default();
    let budget = Budget {
        max_depth: body.max_depth.unwrap_or(default.max_depth),
        max_expand_bytes: body
            .max_expand_bytes
            .unwrap_or(default.max_expand_bytes),
        max_single_bytes: body
            .max_single_bytes
            .unwrap_or(default.max_single_bytes),
    };
    let summary = analyze_branch(&st.store, &branch, budget, body.resume_run_id)?;
    Ok(Json(json!(summary)))
}

async fn list_runs(State(st): State<AppState>) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, branch, status, budget, depth_used, bytes_used, summary, created_at
         FROM runs ORDER BY id DESC LIMIT 50",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "branch": r.get::<_, String>(1)?,
            "status": r.get::<_, String>(2)?,
            "budget": serde_json::from_str::<serde_json::Value>(
                &r.get::<_, String>(3)?).unwrap_or(json!({})),
            "depth_used": r.get::<_, i64>(4)?,
            "bytes_used": r.get::<_, i64>(5)?,
            "summary": r.get::<_, String>(6)?,
            "created_at": r.get::<_, String>(7)?,
        }))
    })?;
    Ok(Json(json!({ "runs": rows.collect::<rusqlite::Result<Vec<_>>>()? })))
}

async fn run_detail(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    let run = conn.query_row(
        "SELECT branch, status, budget, depth_used, bytes_used, summary
         FROM runs WHERE id=?1",
        params![id],
        |r| {
            Ok(json!({
                "id": id,
                "branch": r.get::<_, String>(0)?,
                "status": r.get::<_, String>(1)?,
                "budget": serde_json::from_str::<serde_json::Value>(
                    &r.get::<_, String>(2)?).unwrap_or(json!({})),
                "depth_used": r.get::<_, i64>(3)?,
                "bytes_used": r.get::<_, i64>(4)?,
                "summary": r.get::<_, String>(5)?,
            }))
        },
    )?;
    let mut stmt = conn.prepare(
        "SELECT oid, level, message FROM evidence WHERE run_id=?1 ORDER BY id",
    )?;
    let evidence = stmt
        .query_map(params![id], |r| {
            Ok(json!({
                "oid": r.get::<_, Option<String>>(0)?,
                "level": r.get::<_, String>(1)?,
                "message": r.get::<_, String>(2)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = conn.prepare(
        "SELECT oid, kind_name, depth, content_len, oid_ok, candidate_id
         FROM resolved WHERE run_id=?1 ORDER BY oid",
    )?;
    let resolved = stmt
        .query_map(params![id], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "kind": r.get::<_, String>(1)?,
                "depth": r.get::<_, i64>(2)?,
                "content_len": r.get::<_, i64>(3)?,
                "oid_ok": r.get::<_, i64>(4)? != 0,
                "candidate_id": r.get::<_, i64>(5)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = conn.prepare(
        "SELECT oid, step, child_candidate_id, base_candidate_id, base_oid,
                cmd_start, cmd_end, cmd_count, input_len, output_len, verify
         FROM delta_steps WHERE run_id=?1 ORDER BY oid, step",
    )?;
    let steps = stmt
        .query_map(params![id], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "step": r.get::<_, i64>(1)?,
                "child_candidate_id": r.get::<_, i64>(2)?,
                "base_candidate_id": r.get::<_, Option<i64>>(3)?,
                "base_oid": r.get::<_, Option<String>>(4)?,
                "cmd_start": r.get::<_, i64>(5)?,
                "cmd_end": r.get::<_, i64>(6)?,
                "cmd_count": r.get::<_, i64>(7)?,
                "input_len": r.get::<_, i64>(8)?,
                "output_len": r.get::<_, i64>(9)?,
                "verify": r.get::<_, String>(10)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = conn.prepare(
        "SELECT oid, step, seq, kind, cmd_start, cmd_end, src_offset, src_len,
                out_offset, out_len
         FROM delta_commands WHERE run_id=?1 ORDER BY oid, step, seq",
    )?;
    let commands = stmt
        .query_map(params![id], |r| {
            Ok(json!({
                "oid": r.get::<_, String>(0)?,
                "step": r.get::<_, i64>(1)?,
                "seq": r.get::<_, i64>(2)?,
                "kind": r.get::<_, String>(3)?,
                "start": r.get::<_, i64>(4)?,
                "end": r.get::<_, i64>(5)?,
                "src_offset": r.get::<_, i64>(6)?,
                "src_len": r.get::<_, i64>(7)?,
                "out_offset": r.get::<_, i64>(8)?,
                "out_len": r.get::<_, i64>(9)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(json!({
        "run": run,
        "evidence": evidence,
        "resolved": resolved,
        "delta_steps": steps,
        "delta_commands": commands,
    })))
}

async fn list_branches(State(st): State<AppState>) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT b.name, (SELECT COUNT(*) FROM pins p WHERE p.branch=b.name)
         FROM branches b ORDER BY b.name",
    )?;
    let mapped = stmt.query_map([], |r| {
        Ok(json!({
            "name": r.get::<_, String>(0)?,
            "pins": r.get::<_, i64>(1)?,
        }))
    })?;
    let rows = mapped.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(json!({ "branches": rows })))
}

#[derive(Deserialize)]
struct BranchBody {
    name: String,
}

async fn create_branch(
    State(st): State<AppState>,
    Json(body): Json<BranchBody>,
) -> ApiResult {
    let name = normalize_branch(&body.name)?;
    {
        let conn = st.store.db.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO branches(name, created_at) VALUES (?1, datetime())",
            params![name],
        )?;
    }
    Ok(Json(json!({ "branch": name })))
}

#[derive(Deserialize)]
struct PinBody {
    oid: String,
    candidate_id: i64,
}

async fn set_pin(
    State(st): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<PinBody>,
) -> ApiResult {
    let name = normalize_branch(&name)?;
    let oid = body.oid.to_ascii_lowercase();
    {
        let conn = st.store.db.lock().unwrap();
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM objects WHERE id=?1 AND oid=?2",
            params![body.candidate_id, oid],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Err(anyhow::anyhow!(
                "candidate {} does not provide oid {oid}",
                body.candidate_id
            )
            .into());
        }
        conn.execute(
            "INSERT INTO branches(name, created_at) VALUES (?1, datetime())
             ON CONFLICT(name) DO NOTHING",
            params![name],
        )?;
        conn.execute(
            "INSERT INTO pins(branch, oid, candidate_id, created_at)
             VALUES (?1,?2,?3, datetime())
             ON CONFLICT(branch, oid) DO UPDATE SET candidate_id=excluded.candidate_id",
            params![name, oid, body.candidate_id],
        )?;
    }
    // Only the subgraph depending on this oid needs recomputation; the next
    // run naturally re-resolves it because pinned choice changed.
    Ok(Json(json!({ "branch": name, "oid": oid, "pinned": body.candidate_id })))
}

async fn clear_pin(
    State(st): State<AppState>,
    Path((name, oid)): Path<(String, String)>,
) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    conn.execute(
        "DELETE FROM pins WHERE branch=?1 AND oid=?2",
        params![name, oid.to_ascii_lowercase()],
    )?;
    Ok(Json(json!({ "cleared": oid })))
}

fn normalize_branch(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 64
        || name
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.'))
    {
        return Err(anyhow::anyhow!("invalid branch name {name:?}").into());
    }
    Ok(name.to_string())
}

#[derive(Deserialize)]
struct ObjectsQuery {
    branch: Option<String>,
}

async fn list_objects(
    State(st): State<AppState>,
    Query(q): Query<ObjectsQuery>,
) -> ApiResult {
    let branch = q.branch.unwrap_or_else(|| DEFAULT_BRANCH.into());
    let conn = st.store.db.lock().unwrap();
    let run_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM runs WHERE branch=?1 ORDER BY id DESC LIMIT 1",
            params![branch],
            |r| r.get(0),
        )
        .optional()?;
    let mut stmt = conn.prepare(
        "SELECT o.oid, o.kind_name, COUNT(*) AS n,
                MIN(o.source_id), MIN(o.\"offset\"),
                SUM(CASE WHEN o.parse_error IS NOT NULL THEN 1 ELSE 0 END),
                GROUP_CONCAT(DISTINCT o.source_id)
         FROM objects o
         WHERE o.oid <> ''
         GROUP BY o.oid
         ORDER BY o.oid",
    )?;
    let mut objects: Vec<serde_json::Value> = Vec::new();
    let tuples = stmt
        .query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    })?;
    let tuples = tuples.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    for (oid, kind, n, src_min, off_min, bad, sources) in tuples {
        let candidates = {
            let mut cs = conn.prepare(
                "SELECT o.id, o.source_id, o.locator, s.filename, o.crc_ok,
                        o.parse_error, o.\"offset\", o.inflate_size, o.kind_name
                 FROM objects o JOIN sources s ON s.id=o.source_id
                 WHERE o.oid=?1 ORDER BY o.source_id, o.\"offset\", o.id",
            )?;
            let list = cs
                .query_map(params![oid], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "source_id": r.get::<_, i64>(1)?,
                        "locator": r.get::<_, String>(2)?,
                        "filename": r.get::<_, String>(3)?,
                        "crc_ok": r.get::<_, Option<i64>>(4)?.map(|v| v != 0),
                        "parse_error": r.get::<_, Option<String>>(5)?,
                        "offset": r.get::<_, i64>(6)?,
                        "inflate_size": r.get::<_, i64>(7)?,
                        "kind": r.get::<_, String>(8)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            list
        };
        let pinned = conn
            .query_row(
                "SELECT candidate_id FROM pins WHERE branch=?1 AND oid=?2",
                params![branch, oid],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        let status = if let Some(rid) = run_id {
            conn.query_row(
                "SELECT oid_ok, content_len, kind_name, depth FROM resolved
                 WHERE run_id=?1 AND oid=?2",
                params![rid, oid],
                |r| {
                    Ok(json!({
                        "state": "resolved",
                        "oid_ok": r.get::<_, i64>(0)? != 0,
                        "content_len": r.get::<_, i64>(1)?,
                        "kind": r.get::<_, String>(2)?,
                        "depth": r.get::<_, i64>(3)?,
                    }))
                },
            )
            .optional()?
            .unwrap_or_else(|| json!({ "state": if bad > 0 { "error" } else { "unresolved" } }))
        } else {
            json!({ "state": if bad > 0 { "error" } else { "unresolved" } })
        };
        objects.push(json!({
            "oid": oid,
            "kind": kind,
            "candidate_count": n,
            "conflict": n > 1,
            "first_source": src_min,
            "first_offset": off_min,
            "error_candidates": bad,
            "sources": sources,
            "pinned_candidate_id": pinned,
            "status": status,
            "candidates": candidates,
        }));
    }
    Ok(Json(json!({ "branch": branch, "objects": objects })))
}

async fn object_detail(
    State(st): State<AppState>,
    Path(oid): Path<String>,
    Query(q): Query<ObjectsQuery>,
) -> ApiResult {
    let branch = q.branch.unwrap_or_else(|| DEFAULT_BRANCH.into());
    let oid = oid.to_ascii_lowercase();
    let conn = st.store.db.lock().unwrap();

    let run_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM runs WHERE branch=?1 ORDER BY id DESC LIMIT 1",
            params![branch],
            |r| r.get(0),
        )
        .optional()?;

    let mut resolved = None;
    let mut steps = Vec::new();
    let mut commands = Vec::new();
    let mut evidence = Vec::new();
    if let Some(rid) = run_id {
        resolved = conn
            .query_row(
                "SELECT kind_name, depth, content_len, oid_ok,
                        hex(content), content
                 FROM resolved WHERE run_id=?1 AND oid=?2",
                params![rid, oid],
                |r| {
                    let content: Vec<u8> = r.get(5)?;
                    Ok(json!({
                        "kind": r.get::<_, String>(0)?,
                        "depth": r.get::<_, i64>(1)?,
                        "content_len": r.get::<_, i64>(2)?,
                        "oid_ok": r.get::<_, i64>(3)? != 0,
                        "preview_hex": r.get::<_, String>(4)?
                            .chars().take(8192).collect::<String>(),
                        "preview_text": String::from_utf8_lossy(&content[..content.len().min(4096)])
                            .replace('\0', "␀"),
                    }))
                },
            )
            .optional()?;
        let mut stmt = conn.prepare(
            "SELECT step, child_candidate_id, base_candidate_id, base_oid,
                    cmd_start, cmd_end, cmd_count, input_len, output_len, verify
             FROM delta_steps WHERE run_id=?1 AND oid=?2 ORDER BY step",
        )?;
        steps = stmt
            .query_map(params![rid, oid], |r| {
                Ok(json!({
                    "step": r.get::<_, i64>(0)?,
                    "child": r.get::<_, i64>(1)?,
                    "base": r.get::<_, Option<i64>>(2)?,
                    "base_oid": r.get::<_, Option<String>>(3)?,
                    "cmd_start": r.get::<_, i64>(4)?,
                    "cmd_end": r.get::<_, i64>(5)?,
                    "cmd_count": r.get::<_, i64>(6)?,
                    "input_len": r.get::<_, i64>(7)?,
                    "output_len": r.get::<_, i64>(8)?,
                    "verify": r.get::<_, String>(9)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = conn.prepare(
            "SELECT step, seq, kind, cmd_start, cmd_end, src_offset, src_len,
                    out_offset, out_len
             FROM delta_commands WHERE run_id=?1 AND oid=?2 ORDER BY step, seq",
        )?;
        commands = stmt
            .query_map(params![rid, oid], |r| {
                Ok(json!({
                    "step": r.get::<_, i64>(0)?,
                    "seq": r.get::<_, i64>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "start": r.get::<_, i64>(3)?,
                    "end": r.get::<_, i64>(4)?,
                    "src_offset": r.get::<_, i64>(5)?,
                    "src_len": r.get::<_, i64>(6)?,
                    "out_offset": r.get::<_, i64>(7)?,
                    "out_len": r.get::<_, i64>(8)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = conn.prepare(
            "SELECT level, message FROM evidence WHERE run_id=?1 AND oid=?2",
        )?;
        evidence = stmt
            .query_map(params![rid, oid], |r| {
                Ok(json!({
                    "level": r.get::<_, String>(0)?,
                    "message": r.get::<_, String>(1)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }

    let mut stmt = conn.prepare(
        "SELECT o.id, o.source_id, s.filename, o.locator, o.kind_name,
                o.\"offset\", o.raw_size, o.inflate_size, o.crc_ok,
                o.parse_error, o.base_ref, o.base_offset
         FROM objects o JOIN sources s ON s.id=o.source_id
         WHERE o.oid=?1 ORDER BY o.source_id, o.\"offset\", o.id",
    )?;
    let candidates = stmt
        .query_map(params![oid], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "source_id": r.get::<_, i64>(1)?,
                "filename": r.get::<_, String>(2)?,
                "locator": r.get::<_, String>(3)?,
                "kind": r.get::<_, String>(4)?,
                "offset": r.get::<_, i64>(5)?,
                "raw_size": r.get::<_, i64>(6)?,
                "inflate_size": r.get::<_, i64>(7)?,
                "crc_ok": r.get::<_, Option<i64>>(8)?.map(|v| v != 0),
                "parse_error": r.get::<_, Option<String>>(9)?,
                "base_ref": r.get::<_, Option<String>>(10)?,
                "base_offset": r.get::<_, Option<i64>>(11)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let pinned = conn
        .query_row(
            "SELECT candidate_id FROM pins WHERE branch=?1 AND oid=?2",
            params![branch, oid],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;

    Ok(Json(json!({
        "branch": branch,
        "oid": oid,
        "pinned_candidate_id": pinned,
        "candidates": candidates,
        "resolved": resolved,
        "delta_steps": steps,
        "delta_commands": commands,
        "evidence": evidence,
    })))
}

async fn pack_layouts(State(st): State<AppState>) -> ApiResult {
    let conn = st.store.db.lock().unwrap();
    let mut packs = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, filename, size, checksum, paired_source_id,
                parse_summary, parse_errors
         FROM sources WHERE kind='pack' ORDER BY id",
    )?;
    let pack_rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, String>(5)?,
                serde_json::from_str::<Vec<String>>(&r.get::<_, String>(6)?)
                    .unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for (id, filename, size, checksum, pair, summary, errors) in pack_rows {
        let mut es = conn.prepare(
            "SELECT o.oid, o.locator, o.kind_name, o.\"offset\", o.raw_size,
                    o.inflate_size, o.crc_ok, o.parse_error, o.base_ref,
                    o.base_offset
             FROM objects o WHERE o.source_id=?1
                AND o.locator LIKE 'pack:%'
             ORDER BY o.\"offset\"",
        )?;
        let entries = es
            .query_map(params![id], |r| {
                Ok(json!({
                    "oid": r.get::<_, String>(0)?,
                    "locator": r.get::<_, String>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "offset": r.get::<_, i64>(3)?,
                    "raw_size": r.get::<_, i64>(4)?,
                    "inflate_size": r.get::<_, i64>(5)?,
                    "crc_ok": r.get::<_, Option<i64>>(6)?.map(|v| v != 0),
                    "parse_error": r.get::<_, Option<String>>(7)?,
                    "base_ref": r.get::<_, Option<String>>(8)?,
                    "base_offset": r.get::<_, Option<i64>>(9)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let fanout: Option<Vec<u32>> = None;
        let _ = fanout;
        packs.push(json!({
            "source_id": id,
            "filename": filename,
            "size": size,
            "checksum": checksum,
            "paired_idx": pair,
            "summary": summary,
            "errors": errors,
            "entries": entries,
        }));
    }
    Ok(Json(json!({ "packs": packs })))
}
