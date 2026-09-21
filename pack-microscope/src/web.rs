use crate::engine::{recompute_affected, rerun_all_branches, run_branch};
use crate::state::build_state;
use crate::store::{
    branch_id, create_branch, delete_preview, delete_source, get_budget, import_file,
    reset_used_bytes, set_budget, Budget,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::Connection;
use serde::Deserialize;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub conn: Mutex<Connection>,
    pub data_dir: std::path::PathBuf,
}

type ApiResult = Result<Response, AppError>;

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

fn db_err(e: rusqlite::Error) -> AppError {
    if e.to_string().contains("no rows") {
        AppError(StatusCode::NOT_FOUND, e.to_string())
    } else {
        AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn json_body<T: serde::Serialize>(t: &T) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        serde_json::to_string(t).unwrap_or_else(|_| "{}".into()),
    )
        .into_response()
}

pub fn app() -> Router {
    app_with_dir(default_data_dir())
}

pub fn default_data_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("PAIM_DATA_DIR") {
        return std::path::PathBuf::from(d);
    }
    std::path::PathBuf::from("data")
}

pub fn app_with_dir(dir: std::path::PathBuf) -> Router {
    std::fs::create_dir_all(&dir).ok();
    let conn = crate::store::open(&dir.join("microscope.db")).expect("open db");
    let state = Arc::new(AppState {
        conn: Mutex::new(conn),
        data_dir: dir,
    });
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/import", post(api_import))
        .route("/api/run", post(api_run))
        .route("/api/branches", post(api_branch))
        .route("/api/branches/{name}/pins", post(api_pin))
        .route("/api/branches/{name}/budget", post(api_budget))
        .route("/api/sources/{id}/preview", get(api_delete_preview))
        .route("/api/sources/{id}", axum::routing::delete(api_delete))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[derive(Deserialize)]
struct BranchQuery {
    branch: Option<String>,
}

async fn api_state(
    State(st): State<Arc<AppState>>,
    Query(q): Query<BranchQuery>,
) -> ApiResult {
    let name = q.branch.unwrap_or_else(|| "main".to_string());
    let conn = st.conn.lock().unwrap();
    let state = build_state(&conn, &name).map_err(db_err)?;
    Ok(json_body(&state))
}

async fn api_import(
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> ApiResult {
    let filename = format!("upload-{}.bin", crate::store::now_ms());
    let res = {
        let conn = st.conn.lock().unwrap();
        import_file(&conn, &st.data_dir, &filename, &body).map_err(db_err)?
    };
    let reports = {
        let conn = st.conn.lock().unwrap();
        rerun_all_branches(&conn, Some(&res.affected_ck)).map_err(db_err)?
    };
    let payload = serde_json::json!({
        "source_id": res.source_id,
        "kind": res.kind,
        "duplicate": res.duplicate,
        "affected": res.affected_ck,
        "reports": reports.iter().map(|(n, r)| serde_json::json!({
            "branch": n,
            "evaluated": r.evaluated,
            "resolved": r.resolved,
            "errors": r.errors,
            "blocked": r.blocked,
            "suspended": r.suspended,
            "used_bytes": r.used_bytes,
        })).collect::<Vec<_>>(),
    });
    Ok(json_body(&payload))
}

#[derive(Deserialize)]
struct RunBody {
    branch: Option<String>,
    reset_budget: Option<bool>,
}

async fn api_run(State(st): State<Arc<AppState>>, Json(body): Json<RunBody>) -> ApiResult {
    let name = body.branch.unwrap_or_else(|| "main".into());
    let conn = st.conn.lock().unwrap();
    if body.reset_budget.unwrap_or(false) {
        let id = branch_id(&conn, &name).map_err(db_err)?;
        reset_used_bytes(&conn, id).map_err(db_err)?;
    }
    let report = run_branch(&conn, &name, None).map_err(db_err)?;
    Ok(json_body(&serde_json::json!({
        "branch": name,
        "evaluated": report.evaluated,
        "resolved": report.resolved,
        "errors": report.errors,
        "blocked": report.blocked,
        "suspended": report.suspended,
        "used_bytes": report.used_bytes,
    })))
}

#[derive(Deserialize)]
struct BranchBody {
    name: String,
}

async fn api_branch(
    State(st): State<Arc<AppState>>,
    Json(body): Json<BranchBody>,
) -> ApiResult {
    let clean: String = body
        .name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    if clean.is_empty() {
        return Err(AppError(StatusCode::BAD_REQUEST, "分支名非法".into()));
    }
    let conn = st.conn.lock().unwrap();
    let id = create_branch(&conn, &clean).map_err(db_err)?;
    run_branch(&conn, &clean, None).map_err(db_err)?;
    Ok(json_body(&serde_json::json!({"id": id, "name": clean})))
}

#[derive(Deserialize)]
struct PinBody {
    oid: String,
    ckey: Option<String>,
}

async fn api_pin(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<PinBody>,
) -> ApiResult {
    let id = {
        let conn = st.conn.lock().unwrap();
        branch_id(&conn, &name).map_err(db_err)?
    };
    {
        let conn = st.conn.lock().unwrap();
        match &body.ckey {
            Some(ckey) if !ckey.is_empty() => conn.execute(
                "INSERT INTO pins(branch_id, oid, ckey) VALUES(?1,?2,?3)
                 ON CONFLICT(branch_id, oid) DO UPDATE SET ckey=excluded.ckey",
                rusqlite::params![id, body.oid, ckey],
            ),
            _ => conn.execute(
                "DELETE FROM pins WHERE branch_id=? AND oid=?",
                rusqlite::params![id, body.oid],
            ),
        }
        .map_err(db_err)?;
    }
    let conn = st.conn.lock().unwrap();
    let seeds: Vec<String> = {
        conn.prepare("SELECT ckey FROM candidates WHERE oid=?")
            .and_then(|mut stmt| {
                stmt.query_map(rusqlite::params![body.oid], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(db_err)?
    };
    let report = recompute_affected(&conn, &name, &seeds).map_err(db_err)?;
    Ok(json_body(&serde_json::json!({
        "evaluated": report.evaluated, "resolved": report.resolved,
        "errors": report.errors, "blocked": report.blocked, "suspended": report.suspended,
    })))
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<i64>,
    total_bytes: Option<i64>,
    single_ratio: Option<f64>,
    reset_used: Option<bool>,
}

async fn api_budget(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<BudgetBody>,
) -> ApiResult {
    let conn = st.conn.lock().unwrap();
    let id = branch_id(&conn, &name).map_err(db_err)?;
    let mut budget: Budget = get_budget(&conn, id).map_err(db_err)?;
    if let Some(v) = body.max_depth {
        budget.max_depth = v.max(1);
    }
    if let Some(v) = body.total_bytes {
        budget.total_bytes = v.max(1);
    }
    if let Some(v) = body.single_ratio {
        budget.single_ratio = v.clamp(0.01, 1.0);
    }
    set_budget(&conn, id, &budget).map_err(db_err)?;
    if body.reset_used.unwrap_or(true) {
        reset_used_bytes(&conn, id).map_err(db_err)?;
    }
    let report = run_branch(&conn, &name, None).map_err(db_err)?;
    Ok(json_body(&serde_json::json!({
        "budget": budget,
        "evaluated": report.evaluated, "resolved": report.resolved,
        "errors": report.errors, "blocked": report.blocked, "suspended": report.suspended,
        "used_bytes": report.used_bytes,
    })))
}

async fn api_delete_preview(
    State(st): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult {
    let conn = st.conn.lock().unwrap();
    match delete_preview(&conn, id).map_err(db_err)? {
        Some(p) => Ok(json_body(&p)),
        None => Err(AppError(StatusCode::NOT_FOUND, "源不存在".into())),
    }
}

#[derive(Deserialize)]
struct DeleteQuery {
    confirm: Option<bool>,
}

async fn api_delete(
    State(st): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<DeleteQuery>,
) -> ApiResult {
    if !q.confirm.unwrap_or(false) {
        let conn = st.conn.lock().unwrap();
        return match delete_preview(&conn, id).map_err(db_err)? {
            Some(p) => Ok((
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
                serde_json::to_string(&p).unwrap(),
            )
                .into_response()),
            None => Err(AppError(StatusCode::NOT_FOUND, "源不存在".into())),
        };
    }
    {
        let conn = st.conn.lock().unwrap();
        delete_source(&conn, id, false, &st.data_dir).map_err(db_err)?;
    }
    {
        let conn = st.conn.lock().unwrap();
        for (_, name) in crate::store::list_branches(&conn).map_err(db_err)? {
            run_branch(&conn, &name, None).map_err(db_err)?;
        }
    }
    Ok(json_body(&serde_json::json!({"deleted": id})))
}
