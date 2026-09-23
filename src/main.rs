use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pack_microscope::{Budgets, Engine, ScopeMode};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

struct AppState {
    engine: Engine,
    analyze_lock: AsyncMutex<()>,
}

type Shared = Arc<AppState>;

#[tokio::main]
async fn main() {
    let mut addr = "127.0.0.1:5248".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--addr" {
            if let Some(v) = args.next() {
                addr = v;
            }
        } else if let Some(v) = a.strip_prefix("--addr=") {
            addr = v.to_string();
        }
    }

    let data_dir = std::env::var("MICROSCOPE_DATA").unwrap_or_else(|_| "data".to_string());
    let engine = Engine::new(&data_dir).expect("open data dir + sqlite");
    let state = Arc::new(AppState { engine, analyze_lock: AsyncMutex::new(()) });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(state_json))
        .route("/api/import", post(import))
        .route("/api/analyze", post(analyze))
        .route("/api/resume", post(resume))
        .route("/api/pins", post(set_pin).delete(delete_pin))
        .route("/api/sources/{id}", axum::routing::delete(delete_source))
        .route("/api/sources/{id}/dependents", get(dependents))
        .route("/api/objects/{oid}", get(object_content))
        .layer(DefaultBodyLimit::max(300 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("包链显微镜 listening on http://{addr} (data dir: {data_dir})");
    axum::serve(listener, app).await.expect("server");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn state_json(State(st): State<Shared>) -> Json<serde_json::Value> {
    let body = tokio::task::spawn_blocking(move || st.engine.state_json())
        .await
        .unwrap_or(serde_json::json!({}));
    Json(body)
}

async fn import(
    State(st): State<Shared>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut imported = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let name = field.file_name().unwrap_or("uploaded").to_string();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let data = bytes.to_vec();
        let engine = st.engine.clone_ref();
        let res = tokio::task::spawn_blocking(move || engine.import_bytes(&name, &data))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        match res {
            Ok((id, kind, path)) => imported.push(serde_json::json!({
                "id": id, "kind": kind, "name": name, "path": path, "duplicate": false
            })),
            Err(e) => {
                return Err((StatusCode::BAD_REQUEST, format!("{name}: {e}")));
            }
        }
    }
    Ok(Json(serde_json::json!({"imported": imported})))
}

#[derive(Deserialize, Default)]
struct AnalyzeBody {
    #[serde(default)]
    max_depth: Option<u32>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    max_share: Option<f64>,
}

fn budgets_from(b: &AnalyzeBody) -> Budgets {
    let d = Budgets::default();
    Budgets {
        max_depth: b.max_depth.unwrap_or(d.max_depth),
        max_bytes: b.max_bytes.unwrap_or(d.max_bytes),
        max_share: b.max_share.unwrap_or(d.max_share),
    }
}

async fn analyze(
    State(st): State<Shared>,
    Json(body): Json<AnalyzeBody>,
) -> Json<serde_json::Value> {
    let _guard = st.analyze_lock.lock().await;
    let budgets = budgets_from(&body);
    let engine = st.engine.clone_ref();
    let report = tokio::task::spawn_blocking(move || engine.analyze(ScopeMode::Add, Some(budgets), false))
        .await
        .unwrap();
    Json(serde_json::to_value(report).unwrap())
}

async fn resume(
    State(st): State<Shared>,
    Json(body): Json<AnalyzeBody>,
) -> Json<serde_json::Value> {
    let _guard = st.analyze_lock.lock().await;
    let budgets = budgets_from(&body);
    let engine = st.engine.clone_ref();
    let report = tokio::task::spawn_blocking(move || engine.analyze(ScopeMode::Add, Some(budgets), true))
        .await
        .unwrap();
    Json(serde_json::to_value(report).unwrap())
}

#[derive(Deserialize)]
struct PinBody {
    oid: String,
    source_id: i64,
    locator: String,
    #[serde(default)]
    note: String,
}

async fn set_pin(
    State(st): State<Shared>,
    Json(body): Json<PinBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let oid = pack_microscope::Oid::parse_hex(&body.oid)
        .ok_or((StatusCode::BAD_REQUEST, "bad oid".to_string()))?;
    st.engine
        .set_pin(oid, body.source_id, &body.locator, &body.note)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _guard = st.analyze_lock.lock().await;
    let engine = st.engine.clone_ref();
    let report = tokio::task::spawn_blocking(move || engine.analyze(ScopeMode::Full, None, false))
        .await
        .unwrap();
    Ok(Json(serde_json::json!({"ok": true, "report": report})))
}

#[derive(Deserialize)]
struct UnpinBody {
    oid: String,
}

async fn delete_pin(
    State(st): State<Shared>,
    Json(body): Json<UnpinBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let oid = pack_microscope::Oid::parse_hex(&body.oid)
        .ok_or((StatusCode::BAD_REQUEST, "bad oid".to_string()))?;
    st.engine.unpin(&oid).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _guard = st.analyze_lock.lock().await;
    let engine = st.engine.clone_ref();
    let report = tokio::task::spawn_blocking(move || engine.analyze(ScopeMode::Full, None, false))
        .await
        .unwrap();
    Ok(Json(serde_json::json!({"ok": true, "report": report})))
}

async fn delete_source(
    State(st): State<Shared>,
    Path(id): Path<i64>,
) -> Json<serde_json::Value> {
    let engine = st.engine.clone_ref();
    let res = tokio::task::spawn_blocking(move || engine.delete_source(id, true))
        .await
        .unwrap();
    match res {
        Ok(v) => Json(v),
        Err(e) => Json(serde_json::json!({"error": e})),
    }
}

async fn dependents(State(st): State<Shared>, Path(id): Path<i64>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"dependents": st.engine.source_dependents(id)}))
}

async fn object_content(
    State(st): State<Shared>,
    Path(oid): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (typ, data) = st
        .engine
        .object_content(&oid)
        .ok_or((StatusCode::NOT_FOUND, "object not found".to_string()))?;
    let ctype = match typ.as_str() {
        "blob" => "application/octet-stream",
        _ => "text/plain; charset=utf-8",
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{oid}.{typ}\""),
            ),
        ],
        data,
    )
        .into_response())
}
