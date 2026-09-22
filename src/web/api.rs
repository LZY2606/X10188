//! JSON API consumed by automated tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::Router;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::Budget;
use crate::web::home::{BranchQ, St};

pub fn routes() -> Router<St> {
    Router::new()
        .route("/api/sources", axum::routing::get(sources))
        .route("/api/objects", axum::routing::get(objects))
        .route("/api/objects/{id}", axum::routing::get(object))
        .route("/api/layout/{sid}", axum::routing::get(layout))
        .route("/api/graph", axum::routing::get(graph))
        .route("/api/import", axum::routing::post(import_one))
        .route("/api/retry", axum::routing::post(retry_now))
        .route("/api/budget", axum::routing::post(budget))
        .route("/api/pin", axum::routing::post(pin))
        .route("/api/sources/{id}/dependents", axum::routing::get(dependents))
        .route("/api/sources/{id}", axum::routing::delete(del_source))
}

async fn sources(State(st): State<St>) -> Response {
    Json(json!(st.list_sources().unwrap_or_default())).into_response()
}

#[derive(Deserialize)]
struct ObjQ {
    branch: Option<String>,
    status: Option<String>,
    oid: Option<String>,
}

async fn objects(State(st): State<St>, Query(q): Query<ObjQ>) -> Response {
    let branch = q.branch.clone().unwrap_or_else(|| "default".into());
    let store = st.store.lock().unwrap();
    let mut sql = String::from(
        "SELECT e.id,e.source_id,s.kind,s.name,e.offset,COALESCE(e.type_name,''),e.delta,
                e.claimed_oid,COALESCE(r.status,'unresolved'),r.actual_oid,r.oid_ok,r.error,r.blockers,
                r.content_len,r.depth
         FROM entries e JOIN sources s ON s.id=e.source_id
         LEFT JOIN resolutions r ON r.entry_id=e.id AND r.branch=?1",
    );
    let mut wherec = Vec::new();
    if q.status.is_some() {
        wherec.push("r.status=?2");
    }
    if q.oid.is_some() {
        wherec.push("(r.actual_oid=?3 OR e.claimed_oid=?3)");
    }
    if !wherec.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wherec.join(" AND "));
    }
    sql.push_str(" ORDER BY s.kind,s.name,e.offset IS NULL,e.offset,e.id");
    let mut s = match store.db.prepare(&sql) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::new();
    let params = rusqlite::types::Value::from(q.status.clone().unwrap_or_default());
    let params3 = rusqlite::types::Value::from(q.oid.clone().unwrap_or_default());
    let rows = s.query_map(rusqlite::params![branch, params, params3], |r| {
        Ok(json!({
            "entry_id": r.get::<_,i64>(0)?,
            "source_id": r.get::<_,i64>(1)?,
            "source_kind": r.get::<_,String>(2)?,
            "source_name": r.get::<_,String>(3)?,
            "offset": r.get::<_,Option<i64>>(4)?,
            "kind": r.get::<_,String>(5)?,
            "delta": r.get::<_,Option<String>>(6)?,
            "claimed_oid": r.get::<_,Option<String>>(7)?,
            "status": r.get::<_,String>(8)?,
            "actual_oid": r.get::<_,Option<String>>(9)?,
            "oid_ok": r.get::<_,Option<i64>>(10)?,
            "error": parse_json(r.get::<_,Option<String>>(11).ok().flatten()),
            "blockers": parse_json(r.get::<_,Option<String>>(12).ok().flatten()),
            "content_len": r.get::<_,Option<i64>>(13)?,
            "depth": r.get::<_,Option<i64>>(14)?,
        }))
    });
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            out.push(r);
        }
    }
    Json(Value::Array(out)).into_response()
}

fn parse_json(s: Option<String>) -> Value {
    s.and_then(|x| serde_json::from_str(&x).ok()).unwrap_or(Value::Null)
}

async fn object(
    State(st): State<St>,
    Path(id): Path<i64>,
    Query(q): Query<BranchQ>,
) -> Response {
    let branch = q.branch.clone().unwrap_or_else(|| "default".into());
    let store = st.store.lock().unwrap();
    let row = store.db.query_row(
        "SELECT e.id,e.source_id,e.offset,e.type_name,e.delta,e.base_entry_id,e.base_oid,
                e.base_offset,e.declared_size,e.inflated_size,e.z_off,e.z_len,e.claimed_oid,
                e.parse_err,
                r.status,r.kind,r.actual_oid,r.oid_ok,r.depth,r.error,r.blockers,r.steps,
                r.content_len
         FROM entries e
         LEFT JOIN resolutions r ON r.entry_id=e.id AND r.branch=?2
         WHERE e.id=?1",
        params![id, branch],
        |r| {
            Ok(json!({
                "entry_id": r.get::<_,i64>(0)?,
                "source_id": r.get::<_,i64>(1)?,
                "offset": r.get::<_,Option<i64>>(2)?,
                "kind": r.get::<_,Option<String>>(3)?,
                "delta": r.get::<_,Option<String>>(4)?,
                "base_entry_id": r.get::<_,Option<i64>>(5)?,
                "base_oid": r.get::<_,Option<String>>(6)?,
                "base_offset": r.get::<_,Option<i64>>(7)?,
                "declared_size": r.get::<_,Option<i64>>(8)?,
                "inflated_size": r.get::<_,Option<i64>>(9)?,
                "z_off": r.get::<_,Option<i64>>(10)?,
                "z_len": r.get::<_,Option<i64>>(11)?,
                "claimed_oid": r.get::<_,Option<String>>(12)?,
                "parse_err": parse_json(r.get::<_,Option<String>>(13).ok().flatten()),
                "status": r.get::<_,Option<String>>(14)?,
                "resolved_kind": r.get::<_,Option<String>>(15)?,
                "actual_oid": r.get::<_,Option<String>>(16)?,
                "oid_ok": r.get::<_,Option<i64>>(17)?,
                "depth": r.get::<_,Option<i64>>(18)?,
                "error": parse_json(r.get::<_,Option<String>>(19).ok().flatten()),
                "blockers": parse_json(r.get::<_,Option<String>>(20).ok().flatten()),
                "steps": parse_json(r.get::<_,Option<String>>(21).ok().flatten()),
                "content_len": r.get::<_,Option<i64>>(22)?,
            }))
        },
    );
    match row {
        Ok(v) => Json(v).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn layout(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    let store = st.store.lock().unwrap();
    let mut s = match store.db.prepare(
        "SELECT id,offset,COALESCE(type_name,delta,'?'),declared_size,z_off,z_len
         FROM entries WHERE source_id=?1 ORDER BY offset",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let rows = s.query_map(params![sid], |r| {
        Ok(json!({
            "entry_id": r.get::<_,i64>(0)?,
            "offset": r.get::<_,i64>(1)?,
            "kind": r.get::<_,String>(2)?,
            "declared_size": r.get::<_,Option<i64>>(3)?,
            "z_off": r.get::<_,Option<i64>>(4)?,
            "z_len": r.get::<_,Option<i64>>(5)?,
        }))
    });
    let fan: Vec<Value> = store
        .db
        .prepare("SELECT bucket,cumulative FROM fanout WHERE source_id=?1 ORDER BY bucket")
        .unwrap()
        .query_map(params![sid], |r| Ok(json!({"bucket": r.get::<_,i64>(0)?, "cumulative": r.get::<_,i64>(1)?})))
        .unwrap()
        .flatten()
        .collect();
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            out.push(r);
        }
    }
    Json(json!({"entries": out, "fanout": fan})).into_response()
}

async fn graph(State(st): State<St>, Query(q): Query<BranchQ>) -> Response {
    let branch = q.branch.clone().unwrap_or_else(|| "default".into());
    let store = st.store.lock().unwrap();
    let mut s = store
        .db
        .prepare(
            "SELECT e.id,COALESCE(r.actual_oid,e.claimed_oid),e.delta,e.base_entry_id,e.base_oid,
                    COALESCE(r.status,'unresolved')
             FROM entries e LEFT JOIN resolutions r ON r.entry_id=e.id AND r.branch=?1
             ORDER BY e.id",
        )
        .unwrap();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for r in s.query_map(params![branch], |r| {
        Ok((
            r.get::<_,i64>(0)?,
            r.get::<_,Option<String>>(1)?,
            r.get::<_,Option<String>>(2)?,
            r.get::<_,Option<i64>>(3)?,
            r.get::<_,Option<String>>(4)?,
            r.get::<_,String>(5)?,
        ))
    }).unwrap().flatten() {
        let (id, oid, delta, base_entry, base_oid, status) = r;
        nodes.push(json!({"entry_id": id, "oid": oid, "delta": delta, "status": status}));
        edges.push(json!({"from": id, "to": base_entry, "base_oid": base_oid, "via": delta}));
    }
    Json(json!({"branch": branch, "nodes": nodes, "edges": edges})).into_response()
}

async fn import_one(State(st): State<St>, mut mp: Multipart) -> Response {
    let field = match mp.next_field().await {
        Ok(Some(f)) => f,
        _ => return (StatusCode::BAD_REQUEST, "expected multipart 'file'").into_response(),
    };
    let name = field.file_name().unwrap_or("file").to_string();
    let data = match field.bytes().await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match st.import_file(&name, &data) {
        Ok(rep) => Json(json!({
            "ok": true,
            "source_id": rep.source_id,
            "kind": rep.kind,
            "run": {"ok": rep.run.ok, "paused": rep.run.paused, "error": rep.run.error,
                    "total_bytes": rep.run.total_bytes, "reused": rep.run.reused}
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": e}))).into_response(),
    }
}

async fn retry_now(State(st): State<St>) -> Response {
    match st.retry() {
        Ok(r) => Json(json!({"ok": r.ok, "paused": r.paused, "error": r.error, "total_bytes": r.total_bytes})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

#[derive(Deserialize)]
struct BudgetBody {
    max_depth: Option<u32>,
    total_bytes: Option<u64>,
    per_object_bytes: Option<u64>,
}

async fn budget(State(st): State<St>, Json(b): Json<BudgetBody>) -> Response {
    let mut cur = st.budget();
    if let Some(v) = b.max_depth { cur.max_depth = v; }
    if let Some(v) = b.total_bytes { cur.total_bytes = v; }
    if let Some(v) = b.per_object_bytes { cur.per_object_bytes = v; }
    st.set_budget(cur);
    Json(json!(cur)).into_response()
}

#[derive(Deserialize)]
struct PinBody {
    oid: String,
    entry_id: i64,
    branch: Option<String>,
}

async fn pin(State(st): State<St>, Json(b): Json<PinBody>) -> Response {
    let branch = b.branch.clone().unwrap_or_else(|| format!("fork-{}", b.entry_id));
    match st.pin_branch(&branch, &b.oid, b.entry_id) {
        Ok(()) => Json(json!({"ok": true, "branch": branch})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn dependents(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    Json(json!(st.dependents_of_source(sid).unwrap_or_default())).into_response()
}

async fn del_source(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    match st.delete_source(sid) {
        Ok(n) => Json(json!({"ok": true, "recomputed": n})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}
