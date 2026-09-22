//! Pages and JSON handlers for sources/objects/graph/branches + actions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::post;
use axum::{Form, Router};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::model::Budget;
use crate::web::home::{esc, layout, status_badge, BranchQ, St};

// ---------------- sources ----------------

pub async fn sources_page(State(st): State<St>) -> Response {
    let sources = st.list_sources().unwrap_or_default();
    let mut rows = String::new();
    for s in &sources {
        let kind_zh = match s.kind.as_str() {
            "pack" => "📦 pack",
            "idx" => "🗂 idx",
            _ => "📄 loose",
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/sources/{id}">{name}</a></td>
            <td><span class="pill">{kind_zh}</span></td>
            <td class="mono">{size}</td><td class="mono">{entries}</td>
            <td class="mono small">{sha}</td></tr>"#,
            id = s.id,
            name = esc(&s.name),
            size = s.size,
            entries = s.entries,
            sha = esc(&s.sha256.get(0..16).unwrap_or(&s.sha256))
        ));
    }
    let body = format!(
        r#"<h2>源文件（{n}）</h2>
        <p class="small">导入顺序仅记录为序号；候选排序只依据 类型→文件名→偏移，与导入先后无关。</p>
        <table><thead><tr><th>文件</th><th>类型</th><th>大小</th><th>条目</th><th>sha256</th></tr></thead>
        <tbody>{rows}</tbody></table>"#,
        n = sources.len()
    );
    layout("源文件", body).into_response()
}

pub async fn source_detail(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    let store = st.store.lock().unwrap();
    let head: Option<(String, String, i64, Option<bool>, Option<bool>, Option<String>)> = store
        .db
        .query_row(
            "SELECT name,kind,size,idx_ok,pack_checksum_ok,COALESCE(note,'') FROM sources WHERE id=?1",
            params![sid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .ok();
    let Some((name, kind, size, idx_ok, pack_ok, note)) = head else {
        return (StatusCode::NOT_FOUND, "source not found").into_response();
    };
    let note = note.unwrap_or_default();

    // layout bars
    let mut entries: Vec<(i64, Option<i64>, Option<String>, Option<i64>, Option<i64>, Option<i64>, Option<String>)> = Vec::new();
    if kind == "pack" {
        let mut s = store
            .db
            .prepare(
                "SELECT id,offset,COALESCE(type_name,delta,'?'),declared_size,z_off,z_len,
                        COALESCE(parse_err,'') FROM entries WHERE source_id=?1 ORDER BY offset",
            )
            .unwrap();
        let rows = s
            .query_map(params![sid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })
            .unwrap();
        for r in rows.flatten() {
            entries.push(r);
        }
    }

    // fanout (idx)
    let mut fan: Vec<(i64, i64)> = Vec::new();
    if kind == "idx" {
        let mut s = store.db.prepare("SELECT bucket,cumulative FROM fanout WHERE source_id=?1 ORDER BY bucket").unwrap();
        for r in s.query_map(params![sid], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten() {
            fan.push(r);
        }
    }
    let crc_rows: Vec<(i64, i64, i64, bool)> = {
        let mut s = store.db.prepare("SELECT offset,expected,actual,ok FROM idx_crc WHERE source_id=?1 ORDER BY offset").unwrap();
        s.query_map(params![sid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? == 1)))
            .unwrap().flatten().collect()
    };
    drop(store);

    let mut layout_html = String::new();
    if kind == "pack" {
        let span_end = entries
            .iter()
            .filter_map(|(_, _o, _, _, zo, zl, _)| Some(((*zo)? + (*zl)?) as f64))
            .fold(0f64, f64::max)
            .max(size as f64);
        layout_html.push_str("<h2>Pack 布局（header → 对象流 → sha1 trailer）</h2>");
        layout_html.push_str(r#"<div class="bar" style="height:26px"></div>"#);
        let mut rows = String::new();
        for (id, off, tname, decl, zoff, zlen, perr_opt) in &entries {
            let perr = perr_opt.clone().unwrap_or_default();
            let o = off.unwrap_or(0) as f64;
            let zo = zoff.unwrap_or(0) as f64;
            let zl = zlen.unwrap_or(0) as f64;
            let left = o / span_end * 100.0;
            let width = ((zo + zl - o).max(1.0)) / span_end * 100.0;
            let cls = if !perr.is_empty() { "bad" } else if tname.as_deref() == Some("ofs-delta") || tname.as_deref() == Some("ref-delta") { "delta" } else { "" };
            rows.push_str(&format!(
                r#"<tr><td class="mono">{off}</td><td><a href="/objects/{id}" class="{cls}">{t}</a></td>
                <td class="mono">{decl}</td><td class="mono">{zoff} +{zlen}</td>
                <td style="min-width:240px"><div class="bar"><i style="left:{left:.3}%;width:{width:.3}%"></i></div></td>
                <td>{err}</td></tr>"#,
                off = off.unwrap_or(0),
                t = esc(tname.as_deref().unwrap_or("?")),
                decl = decl.unwrap_or(0),
                zoff = zoff.unwrap_or(0),
                zlen = zlen.unwrap_or(0),
                err = if perr.is_empty() { "—".into() } else { format!(r#"<span class="bad">{}</span>"#, esc(&perr)) }
            ));
        }
        layout_html.push_str(&format!(
            "<table><thead><tr><th>offset</th><th>类型</th><th>声明大小</th><th>zlib 边界(偏移+长度)</th><th>占比</th><th>错误证据</th></tr></thead><tbody>{rows}</tbody></table>"
        ));
    }

    let mut fan_html = String::new();
    if kind == "idx" && !fan.is_empty() {
        let n = fan.last().map(|x| x.1).unwrap_or(0);
        let cells: String = fan
            .iter()
            .enumerate()
            .map(|(i, (_, c))| {
                let h = (*c as f64 / n.max(1) as f64 * 120.0).max(2.0);
                format!(r#"<span title="{i:02x}: {c}" style="display:inline-block;width:3px;height:{h:.0}px;background:var(--accent);vertical-align:bottom;margin-right:1px"></span>"#)
            })
            .collect();
        fan_html = format!(
            r#"<h2>Index fanout（256 桶，对象总数 {n}）</h2><div class="card" style="overflow:auto">{cells}</div>
            <p class="small">idx 校验 {idx} · pack checksum {pck}{note}</p>
            <h2>逐对象 CRC32（idx 值 vs 重算）</h2>{crc}"#,
            idx = if idx_ok == Some(true) { r#"<span class="ok">OK</span>"# } else { r#"<span class="bad">不通过</span>"# },
            pck = if pack_ok == Some(true) { r#"<span class="ok">OK</span>"# } else { r#"<span class="bad">不通过/未验</span>"# },
            note = if note.is_empty() { String::new() } else { format!(r#" · <span class='bad'>{}</span>"#, esc(&note)) },
            crc = crc_table(&crc_rows)
        );
    }

    let body = format!(
        r#"<h2>{name}</h2>
        <p><span class="pill">{kind}</span> · <span class="mono">{size} bytes</span></p>
        {fan_html}{layout_html}
        <h2>删除前的依赖检查</h2>
        <p class="small">删除会先列出仍依赖该源的对象；确认后才移除文件并只重算受影响子图。</p>
        <a class="tag" href="/sources/{sid}/dependents">查看仍依赖此源的对象</a>"#,
    );
    layout(&name, body).into_response()
}

fn crc_table(rows: &[(i64, i64, i64, bool)]) -> String {
    if rows.is_empty() {
        return "<p class='mut'>无配对 pack，无法校验 CRC。</p>".into();
    }
    let mut t = String::from("<table><thead><tr><th>offset</th><th>idx CRC</th><th>重算 CRC</th><th>结果</th></tr></thead><tbody>");
    for (off, exp, act, ok) in rows {
        t.push_str(&format!(
            r#"<tr><td class="mono">{off}</td><td class="mono">{exp:08x}</td><td class="mono">{act:08x}</td>
            <td>{r}</td></tr>"#,
            r = if *ok { r#"<span class="ok">匹配</span>"# } else { r#"<span class="bad">错误 CRC</span>"# }
        ));
    }
    t.push_str("</tbody></table>");
    t
}

pub async fn source_dependents(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    let deps = st.dependents_of_source(sid).unwrap_or_default();
    let mut rows = String::new();
    for d in &deps {
        rows.push_str(&format!(
            r#"<tr><td><a href="/objects/{}">#{}</a></td><td>{}</td><td class="mono">{}</td>
            <td>{}</td><td>{badge}</td></tr>"#,
            d.entry_id, d.entry_id, esc(&d.source_name),
            d.offset.map(|x| x.to_string()).unwrap_or_else(|| "—".into()),
            d.kind.clone().unwrap_or_else(|| "?".into()),
            badge = status_badge(&d.status)
        ));
    }
    let body = format!(
        r#"<h2>仍依赖源 #{sid} 的对象（{n}）</h2>
        <form action="/sources/{sid}/delete" method="post">
         <button class="danger" type="submit">我已知晓，删除源文件并重算受影响子图</button>
         <a class="tag" href="/sources/{sid}">返回</a>
        </form>
        <table><thead><tr><th>entry</th><th>所在源</th><th>offset</th><th>类型</th><th>状态</th></tr></thead><tbody>{rows}</tbody></table>"#,
        n = deps.len()
    );
    layout("依赖检查", body).into_response()
}

pub async fn delete_source(State(st): State<St>, Path(sid): Path<i64>) -> Response {
    match st.delete_source(sid) {
        Ok(n) => Html(format!(r#"<p>已删除源，重算了 {n} 个受影响对象。</p><p><a href="/sources">返回源列表</a></p>"#)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, esc(&e)).into_response(),
    }
}
