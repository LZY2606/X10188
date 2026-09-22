//! Delta DAG visualisation, branches page, form actions and JSON API.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::Form;
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::model::Budget;
use crate::web::home::{branch_of, esc, layout, status_badge, BranchQ, St};

pub async fn graph_page(State(st): State<St>, qb: Option<Query<BranchQ>>) -> Response {
    let branch = branch_of(&qb.map(|q| q.0));
    let store = st.store.lock().unwrap();
    let mut nodes: Vec<(i64, String, Option<String>, Option<i64>, String, Option<String>)> = Vec::new();
    {
        let mut s = store
            .db
            .prepare(
                "SELECT e.id,COALESCE(r.kind,e.type_name,'?'),e.delta,e.base_entry_id,
                        COALESCE(r.status,'unresolved'),COALESCE(r.actual_oid,e.claimed_oid,'')
                 FROM entries e LEFT JOIN resolutions r
                   ON r.entry_id=e.id AND r.branch=?1
                 ORDER BY e.id",
            )
            .unwrap();
        let rows = s.query_map(params![branch], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        }).unwrap();
        for r in rows.flatten() {
            nodes.push(r);
        }
    }
    // deterministic positions: simple layered SVG
    let n = nodes.len();
    let w = 1100;
    let col_w = 150;
    let per_col = ((n as f64) / (w / col_w) as f64).ceil().max(1.0) as usize;
    let h = (per_col * 70 + 80).max(200);
    let mut pos: BTreeMap<i64, (f64, f64)> = BTreeMap::new();
    for (i, (id, _, _, _, status, _)) in nodes.iter().enumerate() {
        let col = i / per_col;
        let row = i % per_col;
        pos.insert(*id, (60.0 + col as f64 * col_w as f64, 40.0 + row as f64 * 64.0));
    }
    let mut edges_svg = String::new();
    for (id, _, _, base, _, _) in &nodes {
        if let Some(b) = base {
            if let (Some(&(x1, y1)), Some(&(x2, y2))) = (pos.get(b), pos.get(id)) {
                edges_svg.push_str(&format!(
                    r#"<path d='M {x1} {y1} C {xm} {y1}, {xm} {y2}, {x2} {y2}' stroke='#c084fc' stroke-width='1.4' fill='none' marker-end='url(#a)'/>"#,
                    xm = (x1 + x2) / 2.0
                ));
            }
        }
    }
    let mut nodes_svg = String::new();
    for (id, kind, delta, _, status, oid) in &nodes {
        let (x, y) = pos.get(id).copied().unwrap_or((0.0, 0.0));
        let color = match status.as_str() {
            "ok" => "#4ade80",
            "paused" => "#fbbf24",
            "error" => "#f87171",
            _ => "#64748b",
        };
        let shape = if delta.is_some() { "◇" } else { "●" };
        nodes_svg.push_str(&format!(
            r#"<g><a href='/objects/{id}'><circle cx='{x}' cy='{y}' r='9' fill='{color}' opacity='0.85'/>
            <text x='{x}' y='{yv}' font-size='11' fill='#e6ecf7'>{shape} {id}·{kind}</text>
            <text x='{x}' y='{yv2}' font-size='9' fill='#93a0b8'>{oid}</text></a></g>"#,
            yv = y - 13.0,
            yv2 = y + 22.0,
            kind = esc(kind),
            oid = esc(&oid.clone().unwrap_or_default().chars().take(8).collect::<String>())
        ));
    }
    drop(store);
    let body = format!(
        r#"<h2>Delta DAG（分支：{branch}）</h2>
        <p class="small">● 普通对象　◇ delta 对象；紫箭头指向 base；
        绿=已还原　黄=预算暂停（可重试）　红=隔离坏对象　灰=未解析。</p>
        <svg width='100%' viewBox='0 0 {w} {h}' style='background:#0c111c;border:1px solid #26314a;border-radius:10px'>
        <defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
        <path d='M0,0 L7,3 L0,6 Z' fill='#c084fc'/></marker></defs>
        {edges_svg}{nodes_svg}</svg>"#
    );
    layout("Delta DAG", body).into_response()
}

pub async fn branches_page(State(st): State<St>) -> Response {
    let branches = st.branches().unwrap_or_default();
    let store = st.store.lock().unwrap();
    let mut pins: Vec<(String, String, i64)> = Vec::new();
    {
        let mut s = store
            .db
            .prepare(
                "SELECT b.name,p.oid,p.entry_id FROM branch_pins p
                 JOIN branches b ON b.id=p.branch_id ORDER BY b.id",
            )
            .unwrap();
        for r in s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().flatten() {
            pins.push(r);
        }
    }
    drop(store);
    let mut rows = String::new();
    for (bid, name) in &branches {
        let p = pins.iter().filter(|(b, _, _)| b == name)
            .map(|(_, o, e)| format!("<code>{}→#{}</code>", esc(&o.chars().take(10).collect::<String>()), e))
            .collect::<Vec<_>>()
            .join("，");
        rows.push_str(&format!(
            "<tr><td>{bid}</td><td><a href='/graph?branch={n}'>{n}</a></td><td>{p}</td></tr>",
            n = esc(name),
            p = if p.is_empty() { "<span class='mut'>无固定（默认排序）</span>".into() } else { p }
        ));
    }
    let body = format!(
        r#"<h2>分析分支（固定冲突来源）</h2>
        <table><thead><tr><th>id</th><th>分支</th><th>固定的候选来源</th></tr></thead><tbody>{rows}</tbody></table>
        <p class="small">在对象页对重复 oid 选择“固定此来源形成分析分支”，只重算受影响依赖子图。</p>"#
    );
    layout("分支", body).into_response()
}

#[derive(Deserialize)]
pub struct BudgetForm {
    pub max_depth: Option<u32>,
    pub total_bytes: Option<u64>,
    pub per_object_bytes: Option<u64>,
}

pub async fn set_budget_form(State(st): State<St>, Form(f): Form<BudgetForm>) -> Response {
    let mut b = st.budget();
    if let Some(v) = f.max_depth { b.max_depth = v; }
    if let Some(v) = f.total_bytes { b.total_bytes = v; }
    if let Some(v) = f.per_object_bytes { b.per_object_bytes = v; }
    st.set_budget(b);
    Redirect::to("/").into_response()
}

pub async fn retry_form(State(st): State<St>) -> Response {
    match st.retry() {
        Ok(_) => Redirect::to("/objects?status=paused").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, esc(&e)).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PinForm {
    pub oid: String,
    pub entry_id: i64,
    pub branch: String,
}

pub async fn pin_form(State(st): State<St>, Form(f): Form<PinForm>) -> Response {
    let branch = f.branch.trim().to_string();
    match st.pin_branch(&branch, &f.oid, f.entry_id) {
        Ok(()) => Redirect::to(&format!("/objects/{}?branch={}", f.entry_id, urlencode(&branch))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, esc(&e)).into_response(),
    }
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_string() } else { format!("%{:02X}", c as u32) })
        .collect()
}

pub async fn import_form(State(st): State<St>, mut mp: Multipart) -> Response {
    let mut msgs = Vec::new();
    while let Some(field) = mp.next_field().await.unwrap_or(None) {
        let name = field.file_name().unwrap_or("upload").to_string();
        let data = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };
        if data.is_empty() {
            continue;
        }
        match st.import_file(&name, &data) {
            Ok(rep) => msgs.push(format!("已导入 {}（source #{}, 本轮 ok={} paused={} err={}）", esc(&name), rep.source_id, rep.run.ok, rep.run.paused, rep.run.error)),
            Err(e) => msgs.push(format!("<span class='bad'>{} 导入失败：{}</span>", esc(&name), esc(&e))),
        }
    }
    Html(format!(r#"<p>{}</p><p><a href="/">返回总览</a></p>"#, msgs.join("<br>"))).into_response()
}
