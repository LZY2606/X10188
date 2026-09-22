use crate::engine::{Analyzer, Budget};
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Redirect},
    routing::{get, post},
    Router,
};
use rusqlite::params;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub analyzer: Arc<Mutex<Analyzer>>,
}

#[derive(Serialize)]
pub struct SourceJson {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub status: String,
    pub error: Option<String>,
    pub paired_with: Option<i64>,
    pub objects: i64,
    pub dependents: i64,
}

#[derive(Serialize)]
pub struct ObjectJson {
    pub raw_id: i64,
    pub source_id: i64,
    pub source: String,
    pub offset: Option<i64>,
    pub declared_type: String,
    pub declared_size: i64,
    pub inflated_size: i64,
    pub compressed_size: i64,
    pub zlib_start: Option<i64>,
    pub zlib_end: Option<i64>,
    pub state: String,
    pub oid: Option<String>,
    pub resolved_type: Option<String>,
    pub depth: i64,
    pub expanded_bytes: i64,
    pub preview: String,
    pub error: Option<String>,
    pub blocked_chain: Vec<i64>,
}

#[derive(Serialize)]
pub struct EdgeJson {
    pub child: i64,
    pub kind: String,
    pub base_oid: Option<String>,
    pub base_offset: Option<i64>,
    pub base_raw: Option<i64>,
    pub state: String,
}

#[derive(Serialize)]
pub struct StepJson {
    pub seq: i64,
    pub base_raw_id: Option<i64>,
    pub base_oid: Option<String>,
    pub op_start: Option<i64>,
    pub op_end: Option<i64>,
    pub op_kind: Option<String>,
    pub input_len: i64,
    pub output_len: i64,
    pub check_kind: String,
    pub check_ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct CandidateJson {
    pub oid: String,
    pub raw_id: i64,
    pub source_id: i64,
    pub source: String,
    pub valid: bool,
    pub mismatch: Option<String>,
}

#[derive(Serialize)]
pub struct Dashboard {
    pub paused: bool,
    pub sources: Vec<SourceJson>,
    pub objects: Vec<ObjectJson>,
    pub edges: Vec<EdgeJson>,
    pub candidates: Vec<CandidateJson>,
}

pub async fn serve(addr: SocketAddr, analyzer: Analyzer) -> Result<(), std::io::Error> {
    let state = AppState { analyzer: Arc::new(Mutex::new(analyzer)) };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(state_json))
        .route("/api/import", post(import))
        .route("/api/analyze", post(run_analysis))
        .route("/api/pin", post(pin))
        .route("/api/sources/:id/dependents", get(dependents))
        .route("/api/sources/:id", post(delete_source))
        .route("/api/objects/:id", get(object_detail))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

fn json_error(status: StatusCode, message: impl Into<String>) -> impl IntoResponse {
    (status, Json(serde_json::json!({"error": message.into()})))
}

async fn state_json(State(state): State<AppState>) -> Json<Dashboard> {
    Json(state.analyzer.lock().unwrap().dashboard())
}

async fn import(State(state): State<AppState>, mut multipart: Multipart) -> Result<Redirect, (StatusCode, String)> {
    let mut imported = Vec::new();
    while let Some(field) = multipart.next_field().await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))? {
        let name = field.file_name().unwrap_or("object").to_string();
        let bytes = field.bytes().await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?.to_vec();
        let analyzer = state.analyzer.lock().unwrap();
        let source_id = analyzer.import(&name, bytes).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let raw_ids = analyzer.raw_ids_for_source(source_id);
        drop(analyzer);
        let analyzer = state.analyzer.lock().unwrap();
        analyzer.recompute_affected(&raw_ids, Budget::default(), "default").map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        imported.push(source_id);
    }
    let _ = imported;
    Ok(Redirect::to("/"))
}

async fn run_analysis(State(state): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let report = state.analyzer.lock().unwrap().analyze(Budget::default(), "default").map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({ "paused": report.paused, "used_bytes": report.used_bytes })))
}

async fn pin(State(state): State<AppState>, Json(request): Json<PinRequest>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let analyzer = state.analyzer.lock().unwrap();
    analyzer.pin_source(&request.oid, &request.branch, request.source_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let report = analyzer.analyze(Budget::default(), &request.branch).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({ "paused": report.paused })))
}

#[derive(serde::Deserialize)]
struct PinRequest {
    pub oid: String,
    pub branch: String,
    pub source_id: i64,
}

async fn dependents(State(state): State<AppState>, Path(source_id): Path<i64>) -> Json<serde_json::Value> {
    Json(state.analyzer.lock().unwrap().delete_preview(source_id))
}

async fn delete_source(State(state): State<AppState>, Path(source_id): Path<i64>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let analyzer = state.analyzer.lock().unwrap();
    analyzer.delete_source(source_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    analyzer.analyze(Budget::default(), "default").map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({"deleted": source_id})))
}

async fn object_detail(State(state): State<AppState>, Path(raw_id): Path<i64>) -> Json<serde_json::Value> {
    Json(state.analyzer.lock().unwrap().object_detail(raw_id))
}


impl Analyzer {
    pub fn dashboard(&self) -> Dashboard {
        Dashboard {
            paused: self.db.conn.query_row("SELECT EXISTS(SELECT 1 FROM resolved WHERE state='paused')", [], |r| r.get::<_, i64>(0)).unwrap_or(0) != 0,
            sources: self.sources_json(),
            objects: self.objects_json(),
            edges: self.edges_json(),
            candidates: self.candidates_json(),
        }
    }

    fn sources_json(&self) -> Vec<SourceJson> {
        let mut stmt = self.db.conn.prepare(
            "SELECT s.id,s.kind,s.original_name,s.parse_status,s.parse_error,s.paired_source_id,
                    (SELECT COUNT(*) FROM raw_objects r WHERE r.source_id=s.id),
                    (SELECT COUNT(DISTINCT child.id) FROM raw_objects child
                       JOIN edges e ON e.child_raw_id=child.id
                       JOIN raw_objects base ON base.id=COALESCE(e.base_raw_id,-1)
                      WHERE base.source_id=s.id AND child.source_id<>s.id)
             FROM sources s ORDER BY s.imported_at,s.id").unwrap();
        stmt.query_map([], |row| Ok(SourceJson {
            id: row.get(0)?, kind: row.get(1)?, name: row.get(2)?, status: row.get(3)?,
            error: row.get(4)?, paired_with: row.get(5)?, objects: row.get::<_, i64>(6)?,
            dependents: row.get::<_, i64>(7)?,
        })).unwrap().flatten().collect()
    }

    fn objects_json(&self) -> Vec<ObjectJson> {
        let mut stmt = self.db.conn.prepare(
            "SELECT r.id,r.source_id,s.original_name,r.pack_offset,r.type_name,r.declared_size,
                    r.inflated_size,r.compressed_size,r.header_offset,r.zlib_end,
                    COALESCE(x.state,'unanalyzed'),x.oid,x.type_name,COALESCE(x.depth,0),
                    COALESCE(x.expanded_bytes,0),COALESCE(x.content,r.content),x.error_message,x.blocked_chain
             FROM raw_objects r JOIN sources s ON s.id=r.source_id
             LEFT JOIN resolved x ON x.raw_id=r.id
             ORDER BY r.source_id, COALESCE(r.pack_offset,-1), r.id").unwrap();
        stmt.query_map([], |row| {
            let content: Vec<u8> = row.get(16)?;
            let chain_text: Option<String> = row.get(18)?;
            Ok(ObjectJson {
                raw_id: row.get(0)?, source_id: row.get(1)?, source: row.get(2)?,
                offset: row.get(3)?, declared_type: row.get(4)?, declared_size: row.get(5)?,
                inflated_size: row.get(6)?, compressed_size: row.get(7)?, zlib_start: row.get(8)?,
                zlib_end: row.get(9)?, state: row.get(10)?, oid: row.get(11)?,
                resolved_type: row.get(12)?, depth: row.get(13)?, expanded_bytes: row.get(14)?,
                preview: preview_bytes(&content), error: row.get(17)?,
                blocked_chain: serde_json::from_str(&chain_text.unwrap_or_else(|| "[]".to_string())).unwrap_or_default(),
            })
        }).unwrap().flatten().collect()
    }

    fn edges_json(&self) -> Vec<EdgeJson> {
        let mut stmt = self.db.conn.prepare(
            "SELECT e.child_raw_id,e.ref_kind,e.base_oid,e.base_offset,e.base_raw_id,
                    COALESCE(x.state,'unanalyzed')
             FROM edges e LEFT JOIN resolved x ON x.raw_id=e.child_raw_id ORDER BY e.child_raw_id").unwrap();
        stmt.query_map([], |row| Ok(EdgeJson {
            child: row.get(0)?, kind: row.get(1)?, base_oid: row.get(2)?,
            base_offset: row.get(3)?, base_raw: row.get(4)?, state: row.get(5)?,
        })).unwrap().flatten().collect()
    }

    fn candidates_json(&self) -> Vec<CandidateJson> {
        let mut stmt = self.db.conn.prepare(
            "SELECT c.oid,c.raw_id,c.source_id,s.original_name,c.valid,c.mismatch_reason
             FROM candidates c JOIN sources s ON s.id=c.source_id
             ORDER BY c.oid,c.valid DESC,c.origin_rank,c.source_id,c.raw_id").unwrap();
        stmt.query_map([], |row| Ok(CandidateJson {
            oid: row.get(0)?, raw_id: row.get(1)?, source_id: row.get(2)?, source: row.get(3)?,
            valid: row.get::<_, i64>(4)? != 0, mismatch: row.get(5)?,
        })).unwrap().flatten().collect()
    }

    pub fn raw_ids_for_source(&self, source_id: i64) -> Vec<i64> {
        let mut stmt = self.db.conn.prepare("SELECT id FROM raw_objects WHERE source_id=?1").unwrap();
        stmt.query_map(params![source_id], |row| row.get(0)).unwrap().flatten().collect()
    }

    pub fn pin_source(&self, oid: &str, branch: &str, source_id: i64) -> Result<(), String> {
        self.db.conn.execute("INSERT OR REPLACE INTO branch_pins(oid,branch,source_id) VALUES (?1,?2,?3)", params![oid, branch, source_id]).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn delete_preview(&self, source_id: i64) -> serde_json::Value {
        let name: String = self.db.conn.query_row("SELECT original_name FROM sources WHERE id=?1", params![source_id], |r| r.get(0)).unwrap_or_default();
        let objects = self.dependent_objects(source_id);
        serde_json::json!({"source_id": source_id, "source": name, "still_dependent_objects": objects, "confirm_required": !objects.is_empty()})
    }

    fn dependent_objects(&self, source_id: i64) -> Vec<serde_json::Value> {
        let mut stmt = self.db.conn.prepare(
            "WITH RECURSIVE reach(id) AS (
                SELECT id FROM raw_objects WHERE source_id=?1
                UNION
                SELECT e.child_raw_id FROM edges e JOIN reach ON reach.id=COALESCE(e.base_raw_id,-1)
             )
             SELECT r.id,s.original_name,r.pack_offset,COALESCE(x.state,'unanalyzed'),COALESCE(x.oid,'')
             FROM reach r JOIN sources s ON s.id=r.source_id
             LEFT JOIN resolved x ON x.raw_id=r.id ORDER BY r.id").unwrap();
        stmt.query_map(params![source_id], |row| Ok(serde_json::json!({
            "raw_id": row.get::<_, i64>(0)?, "source": row.get::<_, String>(1)?,
            "offset": row.get::<_, Option<i64>>(2)?, "state": row.get::<_, String>(3)?,
            "oid": row.get::<_, String>(4)?,
        }))).unwrap().flatten().collect()
    }

    pub fn delete_source(&self, source_id: i64) -> Result<(), String> {
        let path: Option<String> = self.db.conn.query_row("SELECT stored_path FROM sources WHERE id=?1", params![source_id], |r| r.get(0)).ok();
        self.db.conn.execute("DELETE FROM sources WHERE id=?1", params![source_id]).map_err(|e| e.to_string())?;
        if let Some(path) = path { std::fs::remove_file(path).ok(); }
        Ok(())
    }

    pub fn object_detail(&self, raw_id: i64) -> serde_json::Value {
        let object = self.db.conn.query_row(
            "SELECT r.id,s.original_name,r.pack_offset,r.type_name,r.declared_size,r.inflated_size,
                    r.compressed_size,r.header_offset,r.zlib_end,r.base_ref_oid,r.base_offset,r.parse_error,
                    COALESCE(x.state,'unanalyzed'),COALESCE(x.oid,''),COALESCE(x.error_message,''),
                    COALESCE(x.blocked_chain,'[]'),COALESCE(x.content,r.content)
             FROM raw_objects r JOIN sources s ON s.id=r.source_id
             LEFT JOIN resolved x ON x.raw_id=r.id WHERE r.id=?1",
            params![raw_id],
            |row| Ok(serde_json::json!({
                "raw_id": row.get::<_, i64>(0)?, "source": row.get::<_, String>(1)?,
                "offset": row.get::<_, Option<i64>>(2)?, "type": row.get::<_, String>(3)?,
                "declared_size": row.get::<_, i64>(4)?, "inflated_size": row.get::<_, i64>(5)?,
                "compressed_size": row.get::<_, i64>(6)?, "zlib_start": row.get::<_, Option<i64>>(7)?,
                "zlib_end": row.get::<_, Option<i64>>(8)?, "base_ref_oid": row.get::<_, Option<String>>(9)?,
                "base_offset": row.get::<_, Option<i64>>(10)?, "parse_error": row.get::<_, Option<String>>(11)?,
                "state": row.get::<_, String>(12)?, "oid": row.get::<_, String>(13)?,
                "error": row.get::<_, String>(14)?, "blocked_chain": row.get::<_, String>(15)?,
                "preview": preview_bytes(&row.get::<_, Vec<u8>>(16).unwrap_or_default()),
            })),
        ).unwrap_or_else(|_| serde_json::json!({"error":"object not found"}));
        let mut stmt = self.db.conn.prepare(
            "SELECT seq,base_raw_id,base_oid,op_start,op_end,op_kind,input_len,output_len,check_kind,check_ok,detail
             FROM resolution_steps WHERE raw_id=?1 ORDER BY seq").unwrap();
        let steps = stmt.query_map(params![raw_id], |row| Ok(StepJson {
            seq: row.get(0)?, base_raw_id: row.get(1)?, base_oid: row.get(2)?, op_start: row.get(3)?,
            op_end: row.get(4)?, op_kind: row.get(5)?, input_len: row.get(6)?, output_len: row.get(7)?,
            check_kind: row.get(8)?, check_ok: row.get::<_, i64>(9)? != 0, detail: row.get(10)?,
        })).unwrap().flatten().collect::<Vec<_>>();
        serde_json::json!({ "object": object, "steps": steps })
    }
}

fn preview_bytes(bytes: &[u8]) -> String {
    let limit = bytes.len().min(512);
    String::from_utf8_lossy(&bytes[..limit]).replace('\0', "␀").chars().filter(|ch| !ch.is_control()).collect()
}
