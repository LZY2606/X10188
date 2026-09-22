//! Server-rendered UI + JSON API for 包链显微镜.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use rusqlite::params;
use serde::Deserialize;

use crate::model::Budget;
use crate::AppState;

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Deserialize)]
pub(crate) struct BranchQ {
    pub(crate) branch: Option<String>,
}
pub(crate) fn branch_of(q: &Option<BranchQ>) -> String {
    q.as_ref().and_then(|q| q.branch.clone()).unwrap_or_else(|| "default".into())
}

pub(crate) fn layout(title: &str, body: String) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — 包链显微镜</title>
<style>
:root{{--bg:#0f1420;--panel:#171e2e;--ink:#e6ecf7;--mut:#93a0b8;--line:#26314a;
--ok:#4ade80;--bad:#f87171;--pause:#fbbf24;--accent:#60a5fa;--delta:#c084fc;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
header{{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;gap:18px;align-items:center;flex-wrap:wrap}}
header h1{{font-size:18px;margin:0;letter-spacing:1px}}
nav a{{color:var(--accent);text-decoration:none;margin-right:14px}}
main{{padding:20px 22px;max-width:1200px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}
.card b{{font-size:22px;display:block;margin-top:4px}}
table{{border-collapse:collapse;width:100%;background:var(--panel);border-radius:10px;overflow:hidden}}
th,td{{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}}
th{{color:var(--mut);font-weight:600}}
tr:last-child td{{border-bottom:none}}
code,.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
.ok{{color:var(--ok)}} .bad{{color:var(--bad)}} .pause{{color:var(--pause)}} .delta{{color:var(--delta)}}
.mut{{color:var(--mut)}}
a{{color:var(--accent)}}
.tag{{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px}}
form.inline{{display:inline}}
input[type=file],input[type=text],input[type=number]{{background:#0c111c;border:1px solid var(--line);color:var(--ink);border-radius:6px;padding:5px 8px}}
button{{background:var(--accent);color:#08111f;border:0;border-radius:6px;padding:6px 12px;cursor:pointer;font-weight:600}}
button.ghost{{background:transparent;color:var(--ink);border:1px solid var(--line)}}
button.danger{{background:var(--bad);color:#210b0b}}
pre{{background:#0c111c;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;max-height:360px}}
.bar{{position:relative;height:18px;background:#0c111c;border:1px solid var(--line);border-radius:4px;overflow:hidden}}
.bar i{{position:absolute;top:0;bottom:0;background:var(--accent);opacity:.7}}
h2{{font-size:15px;margin:24px 0 10px}}
.small{{font-size:12px;color:var(--mut)}}
.pill{{font-size:11px;padding:0 7px;border-radius:999px;border:1px solid var(--line)}}
</style></head><body>
<header><h1>🔬 包链显微镜</h1>
<nav><a href="/">总览</a><a href="/sources">源文件</a><a href="/objects">对象</a><a href="/graph">Delta DAG</a><a href="/branches">分支</a></nav>
<span class="small">纯 Rust 解析 · 不调用系统 git</span></header>
<main>{body}</main></body></html>"#
    ))
}

pub(crate) fn status_badge(s: &str) -> String {
    let (cls, zh) = match s {
        "ok" => ("ok", "已还原"),
        "paused" => ("pause", "预算暂停·可重试"),
        "error" => ("bad", "坏对象·隔离"),
        "missing" => ("bad", "缺 base"),
        "cycle" => ("bad", "delta 环"),
        other => ("mut", other),
    };
    format!(r#"<span class="tag {cls}">{zh}</span>"#)
}

pub(crate) type St = Arc<AppState>;

pub async fn dashboard(State(st): State<St>) -> Response {
    let store = st.store.lock().unwrap();
    let counts = |sql: &str| -> i64 {
        store
            .db
            .query_row(sql, rusqlite::params![], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
    };
    let sources = counts("SELECT COUNT(*) FROM sources");
    let entries = counts("SELECT COUNT(*) FROM entries");
    let ok = counts("SELECT COUNT(*) FROM resolutions WHERE branch='default' AND status='ok'");
    let paused = counts("SELECT COUNT(*) FROM resolutions WHERE branch='default' AND status='paused'");
    let err = counts("SELECT COUNT(*) FROM resolutions WHERE branch='default' AND status='error'");
    let oid_bad = counts("SELECT COUNT(*) FROM resolutions WHERE branch='default' AND oid_ok=0");
    let budget = st.budget();
    drop(store);

    let recent: Vec<(i64, String, String, i64, i64)> = {
        let store = st.store.lock().unwrap();
        let mut s = store
            .db
            .prepare("SELECT seq,reason,budget_json,total_bytes,paused FROM runs ORDER BY seq DESC LIMIT 8")
            .unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };

    let mut run_rows = String::new();
    for (seq, reason, bj, total, paused) in recent {
        let depth = serde_json::from_str::<Budget>(&bj).map(|b| b.max_depth).unwrap_or(0);
        run_rows.push_str(&format!(
            "<tr><td>#{seq}</td><td class=mono>{}</td><td>{depth}</td><td class=mono>{total}</td><td>{}</td></tr>",
            esc(&reason),
            if paused != 0 { r#"<span class="pause">有暂停</span>"# } else { "<span class='ok'>完成</span>" }
        ));
    }

    let body = format!(
        r#"
<div class="grid">
 <div class="card">源文件<b>{sources}</b><span class="small">pack / idx / loose</span></div>
 <div class="card">条目<b>{entries}</b></div>
 <div class="card">已还原<b class="ok">{ok}</b></div>
 <div class="card">预算暂停<b class="pause">{paused}</b></div>
 <div class="card">隔离坏对象<b class="bad">{err}</b></div>
 <div class="card">oid 校验失败<b class="bad">{oid_bad}</b></div>
</div>

<h2>导入（所有输入只存入项目数据目录）</h2>
<form action="/import" method="post" enctype="multipart/form-data">
 <input type="file" name="file" multiple required>
 <button type="submit">导入并增量分析</button>
 <span class="small">loose 文件名可用 <code>&lt;oid&gt;</code> 或 <code>xx/38hex</code></span>
</form>

<h2>资源预算</h2>
<form action="/budget" method="post" class="card" style="max-width:720px">
 delta 深度上限 <input name="max_depth" type="number" value="{md}" style="width:90px"> ·
 总展开字节 <input name="total_bytes" type="number" value="{tb}" style="width:140px"> ·
 单对象字节 <input name="per_object_bytes" type="number" value="{po}" style="width:130px">
 <button>保存</button>
 <button class="ghost" formaction="/retry" formmethod="post">恢复暂停对象（有界重试）</button>
</form>

<h2>最近分析轮次</h2>
<table><thead><tr><th>#</th><th>原因</th><th>深度上限</th><th>本轮展开字节</th><th>状态</th></tr></thead>
<tbody>{run_rows}</tbody></table>
"#,
        md = budget.max_depth,
        tb = budget.total_bytes,
        po = budget.per_object_bytes
    );
    layout("总览", body).into_response()
}
