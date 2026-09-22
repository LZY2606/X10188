//! Object list/detail, DAG, branches.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use rusqlite::params;

use crate::git::preview;
use crate::web::home::{branch_of, esc, layout, status_badge, BranchQ, St};

#[derive(serde::Deserialize)]
pub(crate) struct ObjFilter {
    status: Option<String>,
    oid: Option<String>,
}

pub async fn objects_page(
    State(st): State<St>,
    Query(q): Query<ObjFilter>,
    qb: Option<Query<BranchQ>>,
) -> Response {
    let branch = branch_of(&qb.map(|q| q.0));
    let store = st.store.lock().unwrap();
    let mut sql = String::from(
        "SELECT e.id,s.name,e.offset,COALESCE(r.status,'unresolved'),COALESCE(r.kind,e.type_name,'?'),
                COALESCE(r.actual_oid,e.claimed_oid,''),r.oid_ok
         FROM entries e JOIN sources s ON s.id=e.source_id
         LEFT JOIN resolutions r ON r.entry_id=e.id AND r.branch=?1",
    );
    let mut conds: Vec<String> = Vec::new();
    if q.status.is_some() {
        conds.push("r.status=?2".into());
    }
    if q.oid.is_some() {
        conds.push("(r.actual_oid=?3 OR e.claimed_oid=?3)".into());
    }
    if !conds.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conds.join(" AND "));
    }
    sql.push_str(" ORDER BY s.name, e.offset IS NULL, e.offset, e.id");

    let mut s = match store.db.prepare(&sql) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let status_p = q.status.clone();
    let oid_p = q.oid.clone();
    let rows = s.query_map(
        rusqlite::params_from_iter([
            rusqlite::types::Value::from(branch.clone()),
            rusqlite::types::Value::from(status_p.unwrap_or_default()),
            rusqlite::types::Value::from(oid_p.unwrap_or_default()),
        ]),
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        },
    );
    let mut body = String::from(
        r#"<h2>对象列表</h2>
        <p class="small">筛选：
        <a href="/objects">全部</a> · <a href="/objects?status=error">坏对象</a>
        · <a href="/objects?status=paused">预算暂停</a></p>"#,
    );
    body.push_str("<table><thead><tr><th>entry</th><th>来源</th><th>offset</th><th>类型</th><th>oid</th><th>校验</th><th>状态</th></tr></thead><tbody>");
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            let (id, sname, off, status, kind, oid, oid_ok) = r;
            let oid_disp = esc(oid.get(0..12).unwrap_or(&oid));
            let verify = match oid_ok {
                Some(1) => r#"<span class="ok">oid✓</span>"#.to_string(),
                Some(0) => r#"<span class="bad">重新计算的 oid 与来源不符</span>"#.to_string(),
                _ => "<span class='mut'>—</span>".to_string(),
            };
            body.push_str(&format!(
                r#"<tr><td><a href="/objects/{id}">#{id}</a></td><td>{sn}</td>
                <td class="mono">{off}</td><td>{kind}</td><td class="mono">{oid_disp}</td>
                <td>{verify}</td><td>{badge}</td></tr>"#,
                sn = esc(&sname),
                off = off.map(|x| x.to_string()).unwrap_or_else(|| "loose".into()),
                badge = status_badge(&status)
            ));
        }
    }
    body.push_str("</tbody></table>");
    layout("对象", body).into_response()
}

pub async fn object_detail(
    State(st): State<St>,
    Path(id): Path<i64>,
    qb: Option<Query<BranchQ>>,
) -> Response {
    let branch = branch_of(&qb.map(|q| q.0));
    let store = st.store.lock().unwrap();
    let head: Option<(i64, String, Option<i64>, Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>, Option<i64>, Option<i64>, Option<i64>)> = store
        .db
        .query_row(
            "SELECT e.source_id,s.name,e.offset,COALESCE(e.type_name,''),COALESCE(e.delta,''),
                    COALESCE(e.claimed_oid,''),COALESCE(e.parse_err,''),e.declared_size,e.inflated_size,
                    e.z_off,e.z_len
             FROM entries e JOIN sources s ON s.id=e.source_id WHERE e.id=?1",
            params![id],
            |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                    r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?,
                ))
            },
        )
        .ok();
    let Some((sid, sname, off, type_name, delta, claimed_oid, parse_err, decl, infl, zoff, zlen)) = head else {
        return (StatusCode::NOT_FOUND, "object not found").into_response();
    };
    let delta_s = delta.unwrap_or_default();
    let claimed_s = claimed_oid.unwrap_or_default();
    let parse_s = parse_err.unwrap_or_default();
    let type_s = type_name.unwrap_or_default();

    let res: Option<(String, Option<String>, Option<String>, Option<String>, Option<i64>, Option<i64>, Option<String>, Option<String>, Option<String>)> = store
        .db
        .query_row(
            "SELECT status,COALESCE(kind,''),content_path,COALESCE(actual_oid,''),oid_ok,depth,
                    COALESCE(error,''),COALESCE(blockers,''),COALESCE(steps,'')
             FROM resolutions WHERE branch=?1 AND entry_id=?2",
            params![branch, id],
            |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,
                    r.get(6)?, r.get(7)?, r.get(8)?,
                ))
            },
        )
        .ok();

    let mut content_preview = String::new();
    let mut content_meta = String::new();
    if let Some((status, _, Some(path), Some(actual), oid_ok, depth, Some(error), Some(blockers), Some(steps))) = res.clone() {
        if let Ok(bytes) = store.read_content(&path) {
            let pv = esc(&preview(&bytes, 4096));
            content_preview = format!(
                r#"<h2>还原内容预览</h2><div class="small">长度 {len} · 深度 {depth} ·
                 重新计算 git object id <code>{actual}</code> {oidok}</div>
                 <pre>{pv}</pre>"#,
                len = bytes.len(),
                depth = depth.unwrap_or(0),
                actual = esc(&actual),
                oidok = if oid_ok == Some(1) {
                    r#"<span class="ok">✓ 与来源一致</span>"#
                } else {
                    r#"<span class="bad">✗ 与来源声明不符</span>"#
                }
            );
        }
        content_meta = render_meta(&status, &error, &blockers, &steps, &claimed_s, &delta_s);
    } else if let Some((status, _, _, _, _, _, Some(error), Some(blockers), _)) = res.clone() {
        content_meta = render_meta(&status, &error, &blockers, "", &claimed_s, &delta_s);
    }

    // candidate sources for the resulting oid (conflict/fork support)
    let mut cand_html = String::new();
    let oid_for_lookup = res
        .as_ref()
        .and_then(|r| r.3.clone())
        .filter(|x| !x.is_empty())
        .or_else(|| (!claimed_s.is_empty()).then(|| claimed_s.clone()));
    if let Some(oid) = oid_for_lookup {
        cand_html = candidates_html(&store.db, &branch, &oid);
    }
    drop(store);

    let body = format!(
        r#"<h2>对象 #{id}</h2>
        <p><span class="pill">{ty}</span>{deltatag} · 来源 <a href="/sources/{sid}">{sn}</a> ·
        offset <code>{off}</code> · 声明来源 oid <code>{claimed}</code></p>
        <p class="small">原始偏移：header→zlib <code>{zoff}</code>，zlib 压缩长度 <code>{zlen}</code>，
        声明大小 <code>{decl}</code>，膨胀后 <code>{infl}</code></p>
        {perr}{content_meta}{content_preview}{cand_html}"#,
        ty = esc(&type_s),
        deltatag = if delta_s.is_empty() {
            String::new()
        } else {
            format!(r#" <span class="tag delta">{}</span>"#, esc(&delta_s))
        },
        sn = esc(&sname),
        off = off.map(|x| x.to_string()).unwrap_or_else(|| "—".into()),
        claimed = esc(&claimed_s),
        zoff = zoff.unwrap_or(0),
        zlen = zlen.unwrap_or(0),
        decl = decl.unwrap_or(0),
        infl = infl.unwrap_or(0),
        perr = if parse_s.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card"><b class="bad">隔离的结构性错误</b><pre>{}</pre></div>"#, esc(&parse_s))
        }
    );
    layout(&format!("对象 #{id}"), body).into_response()
}

fn render_meta(status: &str, error: &str, blockers: &str, steps: &str, claimed: &str, delta: &str) -> String {
    let badge = status_badge(status);
    let mut html = format!("<h2>还原状态</h2><p>{badge}</p>");
    if !error.is_empty() {
        html.push_str(&format!(r#"<h2>错误证据</h2><pre>{}</pre>"#, esc(error)));
    }
    if !blockers.is_empty() && blockers != "null" {
        if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(blockers) {
            html.push_str("<h2>阻塞链</h2><ol>");
            for b in &v {
                html.push_str(&format!(
                    "<li>entry <code>{}</code> — <b>{}</b> <span class='small'>{}</span></li>",
                    b.get("entry").and_then(|x| x.get("entry").cloned()).map(|_| String::new()).unwrap_or_default(),
                    b.get("code").and_then(|x| x.as_str()).unwrap_or("?"),
                    esc(b.get("detail").and_then(|x| x.as_str()).unwrap_or(""))
                ));
            }
            html.push_str("</ol>");
        }
    }
    if !steps.is_empty() && steps != "null" && delta.contains("delta") {
        if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(steps) {
            html.push_str("<h2>Delta 链逐步记录</h2>");
            html.push_str("<table><thead><tr><th>#</th><th>类型</th><th>base</th><th>指令范围</th><th>输入字节</th><th>输出字节</th><th>校验</th></tr></thead><tbody>");
            for st in &v {
                let g = |k: &str| st.get(k).cloned().unwrap_or(serde_json::Value::Null);
                html.push_str(&format!(
                    r#"<tr><td>{seq}</td><td class="delta">{kind}</td>
                    <td class="mono">e{be} {bo}</td><td class="mono">[{a},{b})</td>
                    <td class="mono">{il}</td><td class="mono">{ol}</td><td>{ck}</td></tr>"#,
                    seq = g("seq").as_u64().unwrap_or(0),
                    kind = g("kind").as_str().unwrap_or(""),
                    be = g("base_entry").as_i64().unwrap_or(-1),
                    bo = g("base_oid").as_str().unwrap_or("").chars().take(10).collect::<String>(),
                    a = g("instr_start").as_u64().unwrap_or(0),
                    b = g("instr_end").as_u64().unwrap_or(0),
                    il = g("in_len").as_u64().unwrap_or(0),
                    ol = g("out_len").as_u64().unwrap_or(0),
                    ck = g("check").as_str().unwrap_or("")
                ));
            }
            html.push_str("</tbody></table>");
        }
    }
    let _ = claimed;
    html
}

fn candidates_html(store: &rusqlite::Connection, branch: &str, oid: &str) -> String {
    let cands: Vec<(i64, String, Option<i64>)> = {
        let mut s = store
            .prepare(
                "SELECT e.id,s.name,e.offset FROM entries e JOIN sources s ON s.id=e.source_id
                 WHERE e.claimed_oid=?1 AND e.parse_err IS NULL ORDER BY s.kind, s.name, e.offset",
            )
            .unwrap();
        s.query_map(params![oid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap().flatten().collect()
    };
    if cands.len() < 2 {
        return String::new();
    }
    let pinned: Option<i64> = store
        .query_row(
            "SELECT p.entry_id FROM branch_pins p JOIN branches b ON b.id=p.branch_id
             WHERE b.name=?1 AND p.oid=?2",
            params![branch, oid],
            |r| r.get::<_, i64>(0),
        )
        .ok();
    let mut rows = String::new();
    for (eid, sname, off) in &cands {
        let is_pin = pinned == Some(*eid);
        rows.push_str(&format!(
            r#"<tr><td>#{eid}</td><td>{sn}</td><td class="mono">{off}</td><td>{pin}</td>
            <td><form method="post" action="/pin">
             <input type="hidden" name="oid" value="{oid}">
             <input type="hidden" name="entry_id" value="{eid}">
             <input type="text" name="branch" value="fork-{eid}" style="width:130px">
             <button class="ghost">固定此来源形成分析分支</button></form></td></tr>"#,
            sn = esc(sname),
            off = off.map(|x| x.to_string()).unwrap_or_else(|| "loose".into()),
            pin = if is_pin { r#"<span class="ok">本分支固定</span>"# } else { "" }
        ));
    }
    format!(
        r#"<h2>同一 oid 的多个候选来源（冲突，可分叉）</h2>
        <p class="small">默认选择与导入顺序无关：loose 优先，其次按文件名、偏移排序。</p>
        <table><thead><tr><th>entry</th><th>来源</th><th>offset</th><th>固定</th><th></th></tr></thead><tbody>{rows}</tbody></table>"#
    )
}
