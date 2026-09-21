use crate::engine::{self, Budget};
use axum::{
    extract::{Multipart, Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Form, Router,
};
use rusqlite::Connection;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState {
    pub conn: Arc<Mutex<Connection>>,
    pub data_dir: Arc<PathBuf>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/files", get(files_page))
        .route("/import", axum::routing::post(import_upload))
        .route("/import_path", axum::routing::post(import_path))
        .route("/files/:id/delete", get(delete_confirm).post(delete_file))
        .route("/objects", get(objects_page))
        .route("/objects/:id", get(object_detail))
        .route("/dag", get(dag_page))
        .route("/conflicts", get(conflicts_page))
        .route("/conflicts/pin", axum::routing::post(pin_handler))
        .route("/budget", axum::routing::post(budget_handler))
        .route("/resume", axum::routing::post(resume_handler))
        .with_state(state)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn layout(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; }}
body {{ font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 0; background: #f6f7f9; color: #1f2329; }}
nav {{ background: #17233d; padding: 10px 20px; }}
nav a {{ color: #cdd6e4; margin-right: 16px; text-decoration: none; font-size: 14px; }}
nav a:hover {{ color: #fff; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 22px; }}
h1 {{ margin-top: 4px; }}
h2 {{ margin-top: 28px; border-left: 4px solid #2f6fed; padding-left: 8px; }}
table {{ border-collapse: collapse; background: #fff; width: 100%; font-size: 13px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }}
th, td {{ border: 1px solid #e3e6eb; padding: 6px 9px; text-align: left; vertical-align: top; }}
th {{ background: #eef2f8; }}
.card {{ background: #fff; border: 1px solid #e3e6eb; border-radius: 8px; padding: 16px; margin: 14px 0; }}
.status {{ padding: 1px 8px; border-radius: 10px; font-size: 12px; }}
.ok {{ background:#e3f6e8; color:#1a7f37; }}
.blocked {{ background:#fff3d6; color:#9a6700; }}
.paused {{ background:#e5efff; color:#0b57d0; }}
.error {{ background:#fde7e9; color:#c02d3a; }}
.pending {{ background:#eceef1; color:#555; }}
code, pre {{ font-family: ui-monospace, Menlo, Consolas, monospace; }}
pre {{ background:#0f172a; color:#dbe5f5; padding:10px; border-radius:6px; overflow:auto; font-size:12px; max-height:320px; }}
input[type=text], input[type=number] {{ padding:5px 8px; border:1px solid #c5cad3; border-radius:5px; }}
button, .btn {{ background:#2f6fed; color:#fff; border:0; border-radius:6px; padding:6px 14px; cursor:pointer; font-size:13px; }}
.btn.secondary {{ background:#6b7280; }}
.btn.danger {{ background:#c02d3a; }}
.muted {{ color:#6b7280; font-size:12px; }}
ul.tree {{ list-style:none; padding-left:18px; border-left:1px dashed #b9c0cc; }}
.grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; }}
.tile {{ background:#fff; border:1px solid #e3e6eb; border-radius:8px; padding:12px 16px; }}
.tile b {{ font-size:22px; display:block; }}
</style></head><body>
<nav>
  <a href="/">总览</a><a href="/files">文件</a><a href="/objects">对象</a>
  <a href="/dag">Delta DAG</a><a href="/conflicts">冲突来源</a>
</nav>
<main><h1>{title}</h1>
{body}
</main></body></html>"#,
        title = esc(title)
    )
}

fn page(title: &str, body: String) -> Html<String> {
    Html(layout(title, &body))
}

fn status_badge(s: &str) -> String {
    format!(r#"<span class="status {s}">{s}</span>"#)
}

async fn overview(State(s): State<AppState>) -> Html<String> {
    let conn = s.conn.lock().unwrap();
    let counts: Vec<(String, i64)> = conn
        .prepare("SELECT status, COUNT(*) FROM objects GROUP BY status ORDER BY status")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let files: i64 = conn
        .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
        .unwrap_or(0);
    let budget = engine::get_budget(&conn).unwrap();
    drop(conn);

    let mut body = String::new();
    body.push_str(&format!(
        r#"<div class="grid">
        <div class="tile"><b>{files}</b>源文件</div>
        <div class="tile"><b>{ok}</b>已还原</div>
        <div class="tile"><b>{blocked}</b>阻塞</div>
        <div class="tile"><b>{paused}</b>预算暂停</div>
        </div>
        <div class="tile" style="margin-top:12px"><b>{errors}</b>错误对象(已隔离,不影响其他对象分析)</div>"#,
        ok = counts.iter().find(|(k, _)| k == "ok").map(|(_, v)| v).unwrap_or(&0),
        blocked = counts.iter().find(|(k, _)| k == "blocked").map(|(_, v)| v).unwrap_or(&0),
        paused = counts.iter().find(|(k, _)| k == "paused").map(|(_, v)| v).unwrap_or(&0),
        errors = counts.iter().find(|(k, _)| k == "error").map(|(_, v)| v).unwrap_or(&0),
    ));

    body.push_str(&format!(
        r#"
        <h2>资源预算</h2>
        <div class="card">
        <form method="post" action="/budget" style="display:flex;gap:18px;align-items:end;flex-wrap:wrap">
          <label>delta 深度上限<br><input type="number" name="max_depth" value="{depth}"></label>
          <label>总展开字节上限<br><input type="number" name="max_total_bytes" value="{total}"></label>
          <label>单对象展开比例上限<br><input type="text" name="max_ratio" value="{ratio}"></label>
          <button type="submit">更新预算</button>
        </form>
        <p class="muted">当前已用展开字节: {used}
        <form method="post" action="/resume" style="margin-top:8px">
          <button class="btn secondary" type="submit">恢复分析(清零用量并重试暂停对象)</button>
        </form>
        </p>
        </div>"#,
        depth = budget.max_depth,
        total = budget.max_total_bytes,
        ratio = budget.max_ratio,
        used = budget.used_bytes,
    ));

    let conn = s.conn.lock().unwrap();
    let evidence: Vec<(i64, String, String, String, Option<i64>)> = conn
        .prepare("SELECT id, level, message, created_at, object_id FROM evidence ORDER BY id DESC LIMIT 60")
        .unwrap()
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    body.push_str("<h2>错误证据(最近 60 条)</h2><table><tr><th>级别</th><th>对象</th><th>时间</th><th>信息</th></tr>");
    for (id, level, msg, at, obj) in evidence {
        let objlink = match obj {
            Some(o) => format!(r#"<a href="/objects/{o}">#{o}</a>"#),
            None => "-".to_string(),
        };
        body.push_str(&format!(
            "<tr><td><span class=\"status {cls}\">{level}</span></td><td>{objlink}</td><td>{at}</td><td><code>{msg}</code></td></tr>",
            cls = if level == "error" { "error" } else if level == "warn" { "blocked" } else { "pending" },
            level = esc(&level),
            msg = esc(&msg),
            at = esc(&at),
        ));
        let _ = id;
    }
    body.push_str("</table>");
    page("包链显微镜", body)
}

async fn files_page(State(s): State<AppState>) -> Html<String> {
    let conn = s.conn.lock().unwrap();
    let files: Vec<(i64, String, String, String, i64, String)> = conn
        .prepare(
            "SELECT f.id, f.name, f.kind, f.digest, f.size, f.imported_at
             FROM files f ORDER BY f.id",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let mut body = r#"
        <h2>导入</h2>
        <div class="card">
        <form method="post" action="/import" enctype="multipart/form-data">
          <input type="file" name="file" required>
          <button type="submit">上传 pack / index / loose object</button>
        </form>
        <form method="post" action="/import_path" style="margin-top:10px">
          <label>或从服务器路径复制进数据目录: <input type="text" name="path" size="60" placeholder="/abs/path/to/repo.pack"></label>
          <button class="btn secondary" type="submit">按路径导入</button>
        </form>
        <p class="muted">所有导入内容都会复制到项目 <code>data/incoming/</code> 目录;相同内容去重。</p>
        </div>
        <h2>源文件</h2>
        <table><tr><th>id</th><th>名称</th><th>类型</th><th>内容摘要 (sha1)</th><th>大小</th><th>导入时间</th><th></th></tr>"#
        .to_string();
    for (id, name, kind, digest, size, at) in files {
        body.push_str(&format!(
            "<tr><td>{id}</td><td><code>{name}</code></td><td>{kind}</td><td><code>{d}</code></td><td>{size}</td><td>{at}</td>
             <td><a class=\"btn danger\" href=\"/files/{id}/delete\">删除</a></td></tr>",
            name = esc(&name),
            d = &digest[..digest.len().min(16)],
        ));
    }
    body.push_str("</table>");
    page("源文件", body)
}

async fn import_upload(
    State(s): State<AppState>,
    mut multipart: Multipart,
) -> axum::response::Response {
    let mut imported = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field
            .file_name()
            .unwrap_or("upload.bin")
            .to_string();
        let data = match field.bytes().await {
            Ok(b) => b.to_vec(),
            Err(_) => continue,
        };
        let conn = s.conn.lock().unwrap();
        if let Ok(id) = engine::import_bytes(&conn, &s.data_dir, &name, &data) {
            imported.push(id);
        }
    }
    let _ = imported;
    Redirect::to("/files").into_response()
}

#[derive(Deserialize)]
struct PathForm {
    path: String,
}

async fn import_path(
    State(s): State<AppState>,
    Form(form): Form<PathForm>,
) -> axum::response::Response {
    let path = form.path.trim().to_string();
    let (name, data) = {
        let p = std::path::Path::new(&path);
        let n = p
            .file_name()
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_else(|| "import.bin".to_string());
        match std::fs::read(p) {
            Ok(b) => (n, b),
            Err(_) => return Redirect::to("/files").into_response(),
        }
    };
    let conn = s.conn.lock().unwrap();
    let _ = engine::import_bytes(&conn, &s.data_dir, &name, &data);
    Redirect::to("/files").into_response()
}

async fn delete_confirm(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> axum::response::Response {
    let conn = s.conn.lock().unwrap();
    let file: Option<(String, String, String, i64)> = conn
        .query_row(
            "SELECT name, kind, digest, size FROM files WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    let Some((name, kind, digest, size)) = file else {
        return page("删除源文件", "<p class=\"muted\">文件不存在。</p>".to_string()).into_response();
    };
    let own: Vec<(i64, i64, String, String, Option<String>)> = conn
        .prepare(
            "SELECT id, offset, otype, status, oid FROM objects WHERE file_id=?1 ORDER BY offset LIMIT 200",
        )
        .unwrap()
        .query_map([id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let deps = engine::dependents_of_file(&conn, id).unwrap_or_default();
    let dep_rows: Vec<(i64, String, String, Option<String>)> = deps
        .iter()
        .filter_map(|dep| {
            conn.query_row(
                "SELECT id, otype, status, oid FROM objects WHERE id=?1",
                [dep],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .ok()
        })
        .collect();
    let mut body = format!(
        r#"<div class="card">
        <h2 style="margin-top:0">删除文件 <code>{name}</code></h2>
        <p>类型 {kind} · {size} 字节 · digest <code>{digest}</code></p>
        <p><b>该文件包含 {} 个对象(显示前 200)</b></p>
        <table><tr><th>对象</th><th>偏移</th><th>类型</th><th>状态</th><th>oid</th></tr>"#,
        own.len()
    );
    for (oid_obj, off, t, st, oid) in own {
        body.push_str(&format!(
            "<tr><td><a href=\"/objects/{oid_obj}\">#{oid_obj}</a></td><td>{off}</td><td>{t}</td><td>{}</td><td><code>{}</code></td></tr>",
            status_badge(&st),
            oid.unwrap_or_default()
        ));
    }
    body.push_str("</table>");
    body.push_str(&format!(
        r#"<h2>仍依赖该文件的对象({})</h2>
        <p class="muted">删除后这些对象将被置回 pending 并重新分析(base 缺失则进入阻塞)。</p>
        <table><tr><th>对象</th><th>类型</th><th>状态</th><th>oid</th></tr>"#,
        dep_rows.len()
    ));
    for (dep, t, st, oid) in dep_rows {
        body.push_str(&format!(
            "<tr><td><a href=\"/objects/{dep}\">#{dep}</a></td><td>{t}</td><td>{}</td><td><code>{}</code></td></tr>",
            status_badge(&st),
            oid.unwrap_or_default()
        ));
    }
    body.push_str("</table>");
    body.push_str(&format!(
        r#"<form method="post" action="/files/{id}/delete" style="margin-top:16px">
        <button class="btn danger" type="submit">确认删除并级联失效</button>
        <a class="btn secondary" href="/files">取消</a>
        </form></div>"#
    ));
    page("删除源文件", body).into_response()
}

async fn delete_file(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> axum::response::Response {
    let conn = s.conn.lock().unwrap();
    let _ = engine::delete_file(&conn, &s.data_dir, id);
    Redirect::to("/files").into_response()
}

async fn objects_page(State(s): State<AppState>) -> Html<String> {
    let conn = s.conn.lock().unwrap();
    let rows: Vec<(i64, String, i64, String, String, i64, Option<String>, Option<String>)> = conn
        .prepare(
            "SELECT o.id, f.name, o.offset, o.otype, o.status, o.hdr_size, o.oid, o.error
             FROM objects o JOIN files f ON f.id = o.file_id
             ORDER BY f.digest, o.offset, o.id LIMIT 1000",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let mut body = r#"<h2>对象列表(按源摘要 + 偏移排序,与导入顺序无关;前 1000 条)</h2>
        <table><tr><th>对象</th><th>源文件</th><th>原始偏移</th><th>类型</th><th>状态</th>
        <th>声明大小</th><th>oid / 错误</th></tr>"#
        .to_string();
    for (id, fname, off, t, st, sz, oid, err) in rows {
        let tail = match (&oid, &err) {
            (Some(o), _) => format!("<code>{}</code>", esc(o)),
            (None, Some(e)) => format!("<span class=\"status error\">{}</span>", esc(e)),
            _ => "-".to_string(),
        };
        body.push_str(&format!(
            "<tr><td><a href=\"/objects/{id}\">#{id}</a></td><td><code>{fname}</code></td><td>{off}</td>
             <td>{t}</td><td>{badge}</td><td>{sz}</td><td>{tail}</td></tr>",
            fname = esc(&fname),
            badge = status_badge(&st),
        ));
    }
    body.push_str("</table>");
    page("对象", body)
}

fn preview(content: &[u8]) -> String {
    let n = content.len().min(512);
    let slice = &content[..n];
    let printable = slice
        .iter()
        .all(|&b| b == b'\n' || b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b));
    if printable {
        format!("<pre>{}</pre>", esc(&String::from_utf8_lossy(slice)))
    } else {
        let mut hexed = String::new();
        for (i, b) in slice.iter().enumerate() {
            if i % 16 == 0 && i != 0 {
                hexed.push('\n');
            }
            hexed.push_str(&format!("{b:02x} "));
        }
        format!("<pre>{hexed}</pre>")
    }
}

fn render_blocking(conn: &Connection, id: i64, depth: usize, seen: &mut Vec<i64>) -> String {
    if depth > 6 || seen.contains(&id) {
        return String::new();
    }
    seen.push(id);
    let deps: Vec<(String, String)> = conn
        .prepare("SELECT dep, note FROM blocking WHERE object_id=?1")
        .unwrap()
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    if deps.is_empty() {
        return String::new();
    }
    let mut out = String::from("<ul>");
    for (dep, note) in deps {
        if let Some(obj_str) = dep.strip_prefix("obj:") {
            let dep_id: i64 = obj_str.parse().unwrap_or(-1);
            let info: Option<(String, String, Option<String>)> = conn
                .query_row(
                    "SELECT otype, status, error FROM objects WHERE id=?1",
                    [dep_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .ok();
            if let Some((t, st, err)) = info {
                out.push_str(&format!(
                    "<li>依赖对象 <a href=\"/objects/{dep_id}\">#{dep_id}</a> ({t}) {badge} {err} {sub}</li>",
                    badge = status_badge(&st),
                    err = esc(&err.unwrap_or_default()),
                    sub = render_blocking(conn, dep_id, depth + 1, seen),
                ));
            } else {
                out.push_str(&format!("<li>依赖对象 #{dep_id}(已不存在)</li>"));
            }
        } else {
            out.push_str(&format!(
                "<li><code>{dep}</code> — {note}</li>",
                dep = esc(&dep),
                note = esc(&note)
            ));
        }
    }
    out.push_str("</ul>");
    out
}

async fn object_detail(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> axum::response::Response {
    let conn = s.conn.lock().unwrap();
    let row: Option<(
        i64,
        String,
        i64,
        String,
        i64,
        Option<i64>,
        Option<String>,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    )> = conn
        .query_row(
            "SELECT o.id, f.name, o.offset, o.otype, o.hdr_size, o.base_ofs, o.base_oid,
                    o.comp_start, o.comp_len, o.idx_crc, o.data_crc, o.status, o.oid,
                    o.final_type, o.error, o.gen
             FROM objects o JOIN files f ON f.id=o.file_id WHERE o.id=?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                ))
            },
        )
        .ok();
    let Some((oid_obj, fname, off, t, hdr, bofs, boid, cs, cl, icrc, dcrc, st, oid, ftype, err, gen)) = row
    else {
        return page("对象详情", "<p>对象不存在。</p>".to_string()).into_response();
    };
    let content: Option<Vec<u8>> = conn
        .query_row("SELECT content FROM objects WHERE id=?1", [id], |r| r.get(0))
        .ok();
    let steps: Vec<(i64, String, i64, i64, i64, i64, bool, Option<String>)> = conn
        .prepare(
            "SELECT step, base_desc, instr_start, instr_end, in_len, out_len, ok, note
             FROM delta_steps WHERE object_id=?1 ORDER BY id",
        )
        .unwrap()
        .query_map([id], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get::<_, i64>(6)? != 0,
                r.get(7)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let base_link: Option<i64> = conn
        .query_row("SELECT base_object_id FROM links WHERE object_id=?1", [id], |r| {
            r.get(0)
        })
        .ok();
    let dependents: Vec<(i64, String, String)> = conn
        .prepare(
            "SELECT o.id, o.otype, o.status FROM objects o
             JOIN links l ON l.object_id=o.id WHERE l.base_object_id=?1 ORDER BY o.id",
        )
        .unwrap()
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    let mut body = String::new();
    body.push_str("<div class=\"card\"><table>");
    let crc = match (icrc, dcrc) {
        (Some(a), Some(b)) => format!("index {:08x} / 实际 {:08x} {}", a as u32, b as u32,
            if a == b { "✓" } else { "✗ CRC 不匹配" }),
        _ => "无 index CRC".to_string(),
    };
    let rows = [
        ("对象 id", format!("#{oid_obj}")),
        ("源文件", format!("<code>{}</code>", esc(&fname))),
        ("原始偏移", format!("{off}")),
        ("对象类型", t),
        ("头部声明大小", hdr.to_string()),
        ("ofs base 偏移", bofs.map(|v| v.to_string()).unwrap_or_else(|| "-".into())),
        ("ref base oid", boid.clone().unwrap_or_else(|| "-".into())),
        ("压缩数据范围", format!("[{cs} .. {})({} 字节)", cs + cl, cl)),
        ("CRC32", crc),
        ("状态", status_badge(&st)),
        ("还原 oid", oid.clone().unwrap_or_else(|| "-".into())),
        ("最终类型", ftype.unwrap_or_else(|| "-".into())),
        ("解析代数 gen", gen.to_string()),
        ("错误", esc(&err.unwrap_or_default())),
    ];
    for (k, v) in rows {
        body.push_str(&format!("<tr><th>{k}</th><td>{v}</td></tr>"));
    }
    body.push_str("</table></div>");

    if !steps.is_empty() {
        body.push_str(
            r#"<h2>Delta 还原步骤</h2>
            <table><tr><th>步</th><th>base</th><th>指令范围</th><th>输入长度</th><th>输出长度</th><th>校验</th><th>备注</th></tr>"#,
        );
        for (step, base, is_, ie, il, ol, ok, note) in steps {
            body.push_str(&format!(
                "<tr><td>{step}</td><td><code>{}</code></td><td>[{is_}..{ie})</td><td>{il}</td><td>{ol}</td>
                 <td>{}</td><td>{}</td></tr>",
                esc(&base),
                if ok { "<span class=\"status ok\">OK</span>" } else { "<span class=\"status error\">失败</span>" },
                esc(&note.unwrap_or_default())
            ));
        }
        body.push_str("</table>");
    }

    if let Some(bid) = base_link {
        body.push_str(&format!(
            "<h2>Delta 链</h2><p>base → <a href=\"/objects/{bid}\">#{bid}</a></p>"
        ));
    }
    if !dependents.is_empty() {
        body.push_str("<p>下游 delta: ");
        for (d, dt, ds) in dependents {
            body.push_str(&format!(
                r#"<a href="/objects/{d}">#{d}</a> ({dt} {}) "#,
                status_badge(&ds)
            ));
        }
        body.push_str("</p>");
    }

    if st != "ok" {
        body.push_str("<h2>阻塞链</h2>");
        let chain = render_blocking(&conn, id, 0, &mut vec![]);
        body.push_str(if chain.is_empty() {
            "<p class=\"muted\">无记录的阻塞依赖。</p>"
        } else {
            &chain
        });
    }

    if let Some(c) = content {
        body.push_str(&format!(
            "<h2>内容预览(前 512 / {} 字节)</h2>",
            c.len()
        ));
        body.push_str(&preview(&c));
    }
    page("对象详情", body).into_response()
}

async fn dag_page(State(s): State<AppState>) -> Html<String> {
    let conn = s.conn.lock().unwrap();
    let nodes: Vec<(i64, String, String, Option<String>)> = conn
        .prepare("SELECT id, otype, status, oid FROM objects ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let links: Vec<(i64, i64, Option<String>)> = conn
        .prepare("SELECT object_id, base_object_id, base_oid FROM links ORDER BY object_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    let mut children: std::collections::HashMap<i64, Vec<i64>> = std::collections::HashMap::new();
    let mut has_parent = std::collections::HashSet::new();
    for (child, base, _boid) in &links {
        children.entry(*base).or_default().push(*child);
        has_parent.insert(*child);
    }
    let label = |id: i64| -> String {
        let (_, t, st, oid) = nodes.iter().find(|(n, _, _, _)| *n == id).cloned().unwrap_or((id, "?".to_string(), "?".to_string(), None));
        let oid_txt = oid.map(|o| format!(" {}", &o[..o.len().min(8)])).unwrap_or_default();
        format!(
            r#"<a href="/objects/{id}">#{id}</a> <code>{t}</code>{oid_txt} {}"#,
            status_badge(&st)
        )
    };
    let mut body = String::from(
        r#"<p class="muted">箭头方向 base → delta(下游)。未解析的 delta 显示在下方未连接区域。</p>"#,
    );
    let mut seen = std::collections::HashSet::new();
    fn render(
        id: i64,
        children: &std::collections::HashMap<i64, Vec<i64>>,
        label: &impl Fn(i64) -> String,
        seen: &mut std::collections::HashSet<i64>,
        out: &mut String,
    ) {
        if !seen.insert(id) {
            out.push_str(&format!("<li>{} ⟲ 环</li>", label(id)));
            return;
        }
        out.push_str(&format!("<li>{}", label(id)));
        if let Some(kids) = children.get(&id) {
            if !kids.is_empty() {
                out.push_str("<ul class=\"tree\">");
                for k in kids {
                    render(*k, children, label, seen, out);
                }
                out.push_str("</ul>");
            }
        }
        out.push_str("</li>");
    }
    let roots: Vec<i64> = nodes
        .iter()
        .map(|(id, _, _, _)| *id)
        .filter(|id| !has_parent.contains(id))
        .collect();
    body.push_str("<ul class=\"tree\">");
    for r in roots {
        render(r, &children, &label, &mut seen, &mut body);
    }
    body.push_str("</ul>");
    let orphan: Vec<_> = nodes.iter().filter(|(id, _, _, _)| !seen.contains(id)).collect();
    if !orphan.is_empty() {
        body.push_str("<h2>未连接 / 阻塞节点</h2><ul class=\"tree\">");
        for (id, _, _, _) in orphan {
            body.push_str(&format!("<li>{}</li>", label(*id)));
        }
        body.push_str("</ul>");
    }
    page("Delta DAG", body)
}

async fn conflicts_page(State(s): State<AppState>) -> Html<String> {
    let conn = s.conn.lock().unwrap();
    let oids = engine::conflicting_oids(&conn).unwrap_or_default();
    let mut body = String::from(
        r#"<p class="muted">同一 Git oid 存在多个候选来源时,可固定一个来源形成分析分支;
           候选默认按(源内容摘要, pack 内偏移)排序,与导入顺序无关。</p>"#,
    );
    if oids.is_empty() {
        body.push_str("<p>当前没有重复 oid。</p>");
    }
    for oid in oids {
        let pinned: Option<i64> = conn
            .query_row("SELECT object_id FROM pins WHERE oid=?1", [&oid], |r| r.get(0))
            .ok();
        let cands: Vec<(i64, String, i64, String)> = conn
            .prepare(
                "SELECT o.id, f.name, o.offset, f.digest FROM objects o JOIN files f ON f.id=o.file_id
                 WHERE o.oid=?1 AND o.status='ok' ORDER BY f.digest, o.offset, o.id",
            )
            .unwrap()
            .query_map([&oid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        body.push_str(&format!(r#"<div class="card"><h2 style="margin-top:0"><code>{oid}</code></h2>
            <p>当前固定: {}</p>
            <table><tr><th></th><th>对象</th><th>源文件</th><th>偏移</th><th>源摘要</th></tr>"#,
            match pinned { Some(p) => format!("<a href=\"/objects/{p}\">#{p}</a>"), None => "无(使用默认排序)".into() }));
        for (id, fname, off, digest) in cands {
            body.push_str(&format!(
                "<tr><td><input type=\"radio\" name=\"object_id\" value=\"{id}\" {}></td>
                 <td><a href=\"/objects/{id}\">#{id}</a></td><td><code>{fname}</code></td>
                 <td>{off}</td><td><code>{d}</code></td></tr>",
                if pinned == Some(id) { "checked" } else { "" },
                fname = esc(&fname),
                d = &digest[..digest.len().min(16)]
            ));
        }
        body.push_str("</table>");
        body.push_str(&format!(
            r#"<form method="post" action="/conflicts/pin" style="margin-top:10px">
            <input type="hidden" name="oid" value="{oid}">
            <button type="submit">固定选中来源并重算子图</button>
            <button class="btn secondary" formaction="/conflicts/pin?clear=1">取消固定</button>
            </form></div>"#
        ));
    }
    page("冲突来源", body)
}

#[derive(Deserialize)]
struct PinForm {
    oid: String,
    object_id: Option<i64>,
}

async fn pin_handler(
    State(s): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    Form(form): Form<PinForm>,
) -> axum::response::Response {
    let clear = q.contains_key("clear");
    let conn = s.conn.lock().unwrap();
    let pick = if clear { None } else { form.object_id };
    let _ = engine::pin_oid(&conn, &s.data_dir, &form.oid, pick);
    Redirect::to("/conflicts").into_response()
}

#[derive(Deserialize)]
struct BudgetForm {
    max_depth: i64,
    max_total_bytes: i64,
    max_ratio: String,
}

async fn budget_handler(
    State(s): State<AppState>,
    Form(form): Form<BudgetForm>,
) -> axum::response::Response {
    let ratio = form.max_ratio.parse::<f64>().unwrap_or(1000.0);
    let conn = s.conn.lock().unwrap();
    let _ = engine::set_budget(&conn, form.max_depth, form.max_total_bytes, ratio);
    Redirect::to("/").into_response()
}

async fn resume_handler(State(s): State<AppState>) -> axum::response::Response {
    let conn = s.conn.lock().unwrap();
    let _ = engine::resume(&conn, &s.data_dir);
    Redirect::to("/").into_response()
}

#[allow(dead_code)]
fn budget_type_anchor(_b: &Budget) {}
