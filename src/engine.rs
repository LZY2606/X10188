//! Resolution engine: rebuilds Git objects from pack entries / loose objects,
//! isolating bad objects, enforcing resource budgets (delta depth, total
//! expanded bytes, single-object share) with pausable/resumable runs, and
//! recomputing only the affected dependency subgraph on invalidation.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::delta::apply_delta;
use crate::gitutil;

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: i64,
    pub max_total_bytes: i64,
    /// A single object may not exceed this percentage of the total budget.
    pub max_object_pct: i64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 1024,
            max_total_bytes: 1 << 30,
            max_object_pct: 100,
        }
    }
}

#[derive(Debug, Clone)]
struct Node {
    key: String,
    source_sha1: String,
    pack_offset: u64,
    hdr_len: u64,
    comp_len: u64,
    type_id: u8,
    parse_error: Option<String>,
    crc_ok: Option<bool>,
    inflated: Option<Rc<Vec<u8>>>,
    base_key: Option<String>,
    ofs_missing: bool,
    base_oid: Option<String>,
    claimed_oid: Option<String>,
}

#[derive(Debug, Clone)]
struct Obj {
    oid: String,
    type_name: String,
    content: Rc<Vec<u8>>,
    depth: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainStep {
    pub key: String,
    pub note: String,
}

#[derive(Debug, Clone)]
enum Fail {
    Missing { oid: String, chain: Vec<ChainStep> },
    Perm { kind: String, msg: String, chain: Vec<ChainStep> },
    Budget(String),
}

impl Fail {
    fn prepend(self, key: &str, note: &str) -> Fail {
        let step = ChainStep { key: key.to_string(), note: note.to_string() };
        match self {
            Fail::Missing { oid, mut chain } => {
                chain.insert(0, step);
                Fail::Missing { oid, chain }
            }
            Fail::Perm { kind, msg, mut chain } => {
                chain.insert(0, step);
                Fail::Perm { kind, msg, chain }
            }
            Fail::Budget(r) => Fail::Budget(r),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub run_id: i64,
    pub status: String,
    pub reason: Option<String>,
    pub resolved_total: usize,
    pub errors: usize,
    pub blocked: usize,
    pub expanded_bytes: i64,
}

struct Ctx<'a> {
    conn: &'a Connection,
    nodes: HashMap<String, Node>,
    claimed: HashMap<String, Vec<String>>,
    resolved_oids: HashMap<String, Vec<String>>,
    cache: HashMap<String, Rc<Obj>>,
    perm_failed: HashSet<String>,
    pins: HashMap<String, String>,
    budget: Budget,
    expanded: i64,
    run_id: i64,
    paused: Option<String>,
}

fn type_id_of_name(name: &str) -> u8 {
    match name {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => 0,
    }
}

fn load_nodes(conn: &Connection) -> rusqlite::Result<HashMap<String, Node>> {
    struct Tmp {
        node: Node,
        pack_id: i64,
        base_off: Option<i64>,
    }
    let mut tmps: Vec<Tmp> = Vec::new();
    let mut by_pack_offset: HashMap<(i64, i64), String> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT e.id, e.offset, e.hdr_len, e.comp_len, e.type_id, e.crc_ok,
                    e.base_offset, e.base_oid, e.claimed_oid, e.inflated, e.parse_error,
                    e.pack_id, s.sha1
             FROM entries e
             JOIN packs p ON e.pack_id = p.id
             JOIN sources s ON p.source_id = s.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, u8>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<Vec<u8>>>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, i64>(11)?,
                r.get::<_, String>(12)?,
            ))
        })?;
        for row in rows {
            let (id, off, hdr, comp, tid, crc_ok_i, base_off, base_oid, claimed, inflated, perr, pack_id, ssha) = row?;
            let key = format!("e:{id}");
            by_pack_offset.insert((pack_id, off), key.clone());
            tmps.push(Tmp {
                node: Node {
                    key,
                    source_sha1: ssha,
                    pack_offset: off as u64,
                    hdr_len: hdr as u64,
                    comp_len: comp as u64,
                    type_id: tid,
                    parse_error: perr,
                    crc_ok: crc_ok_i.map(|v| v != 0),
                    inflated: inflated.map(Rc::new),
                    base_key: None,
                    ofs_missing: false,
                    base_oid,
                    claimed_oid: claimed,
                },
                pack_id,
                base_off,
            });
        }
    }
    let mut nodes: HashMap<String, Node> = HashMap::new();
    for mut t in tmps {
        if let Some(boff) = t.base_off {
            match by_pack_offset.get(&(t.pack_id, boff)) {
                Some(k) => t.node.base_key = Some(k.clone()),
                None => t.node.ofs_missing = true,
            }
        }
        nodes.insert(t.node.key.clone(), t.node);
    }
    // Loose objects.
    {
        let mut stmt = conn.prepare(
            "SELECT l.id, l.claimed_oid, l.type_name, l.content, l.error, s.sha1
             FROM loose_objects l JOIN sources s ON l.source_id = s.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        for row in rows {
            let (id, claimed, tname, content, err, ssha) = row?;
            let key = format!("l:{id}");
            let type_id = tname.as_deref().map(type_id_of_name).unwrap_or(0);
            nodes.insert(
                key.clone(),
                Node {
                    key,
                    source_sha1: ssha,
                    pack_offset: 0,
                    hdr_len: 0,
                    comp_len: 0,
                    type_id,
                    parse_error: err,
                    crc_ok: None,
                    inflated: content.map(Rc::new),
                    base_key: None,
                    ofs_missing: false,
                    base_oid: None,
                    claimed_oid: claimed,
                },
            );
        }
    }
    Ok(nodes)
}

fn preload(conn: &Connection) -> (HashMap<String, Rc<Obj>>, HashMap<String, Vec<String>>) {
    let mut cache = HashMap::new();
    let mut by_oid: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(mut st) = conn.prepare("SELECT key, oid, type_name, content, depth FROM resolved") {
        if let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        }) {
            for r in rows.flatten() {
                let obj = Rc::new(Obj {
                    oid: r.1.clone(),
                    type_name: r.2,
                    content: Rc::new(r.3),
                    depth: r.4,
                });
                by_oid.entry(r.1).or_default().push(r.0.clone());
                cache.insert(r.0, obj);
            }
        }
    }
    (cache, by_oid)
}

fn record_status(conn: &Connection, key: &str, status: &str, kind: Option<&str>, msg: Option<&str>, chain: &[ChainStep]) {
    let blockers = if chain.is_empty() {
        None
    } else {
        Some(serde_json::to_string(chain).unwrap_or_default())
    };
    let _ = conn.execute(
        "INSERT OR REPLACE INTO entry_status(key,status,error_kind,error_msg,blockers) VALUES(?1,?2,?3,?4,?5)",
        params![key, status, kind, msg, blockers],
    );
}

fn candidate_rank(ctx: &Ctx, key: &str) -> (i64, i64, String, u64, String) {
    let n = &ctx.nodes[key];
    let resolved = if ctx.cache.contains_key(key) { 0 } else { 1 };
    (
        resolved,
        0,
        n.source_sha1.clone(),
        n.pack_offset,
        key.to_string(),
    )
}

fn dfs(ctx: &mut Ctx, key: &str, stack: &mut Vec<String>) -> Result<Rc<Obj>, Fail> {
    if let Some(o) = ctx.cache.get(key) {
        return Ok(o.clone());
    }
    if ctx.perm_failed.contains(key) {
        return Err(Fail::Perm {
            kind: "known-failed".into(),
            msg: "该对象此前已判定失败".into(),
            chain: vec![],
        });
    }
    if let Some(pos) = stack.iter().position(|k| k == key) {
        let mut cyc: Vec<String> = stack[pos..].to_vec();
        cyc.push(key.to_string());
        let chain: Vec<ChainStep> = cyc
            .iter()
            .map(|k| ChainStep { key: k.clone(), note: "环成员".into() })
            .collect();
        let msg = format!("delta 形成环: {}", cyc.join(" -> "));
        for k in &cyc {
            record_status(ctx.conn, k, "error", Some("delta-cycle"), Some(&msg), &chain);
            ctx.perm_failed.insert(k.clone());
        }
        return Err(Fail::Perm { kind: "delta-cycle".into(), msg, chain });
    }
    let node = match ctx.nodes.get(key) {
        Some(n) => n.clone(),
        None => {
            return Err(Fail::Perm {
                kind: "missing-node".into(),
                msg: "对象不存在".into(),
                chain: vec![],
            })
        }
    };
    if let Some(e) = &node.parse_error {
        return Err(Fail::Perm { kind: "parse-error".into(), msg: e.clone(), chain: vec![] });
    }
    if node.crc_ok == Some(false) {
        return Err(Fail::Perm {
            kind: "crc-mismatch".into(),
            msg: "CRC32 与 index 记录不符".into(),
            chain: vec![],
        });
    }
    let inflated = match &node.inflated {
        Some(b) => b.clone(),
        None => {
            return Err(Fail::Perm {
                kind: "no-data".into(),
                msg: "无可用解压数据".into(),
                chain: vec![],
            })
        }
    };

    let is_delta = gitutil::is_delta(node.type_id);
    let mut base: Option<(Rc<Obj>, String)> = None;
    if node.type_id == 6 {
        if node.ofs_missing {
            return Err(Fail::Perm {
                kind: "ofs-out-of-range".into(),
                msg: "ofs 距离越界: 目标偏移处无对象".into(),
                chain: vec![],
            });
        }
        let bk = match &node.base_key {
            Some(k) => k.clone(),
            None => {
                return Err(Fail::Perm {
                    kind: "ofs-out-of-range".into(),
                    msg: "ofs-delta 缺少 base 引用".into(),
                    chain: vec![],
                })
            }
        };
        stack.push(key.to_string());
        let r = dfs(ctx, &bk, stack);
        stack.pop();
        match r {
            Ok(o) => base = Some((o, bk)),
            Err(f) => return Err(f.prepend(key, "ofs-delta 依赖")),
        }
    } else if node.type_id == 7 {
        let oid = node.base_oid.clone().unwrap_or_default();
        let mut cands: Vec<String> = Vec::new();
        if let Some(v) = ctx.resolved_oids.get(&oid) {
            cands.extend(v.iter().cloned());
        }
        if let Some(v) = ctx.claimed.get(&oid) {
            for k in v {
                if !cands.contains(k) {
                    cands.push(k.clone());
                }
            }
        }
        if cands.is_empty() {
            return Err(Fail::Missing {
                oid: oid.clone(),
                chain: vec![ChainStep {
                    key: key.to_string(),
                    note: format!("缺少外部 base {oid}"),
                }],
            });
        }
        cands.sort_by(|a, b| candidate_rank(ctx, a).cmp(&candidate_rank(ctx, b)));
        if let Some(pin) = ctx.pins.get(&oid) {
            if let Some(p) = cands.iter().position(|k| k == pin) {
                let k = cands.remove(p);
                cands.insert(0, k);
            }
        }
        let mut last_fail: Option<Fail> = None;
        let mut got: Option<(Rc<Obj>, String)> = None;
        for c in &cands {
            stack.push(key.to_string());
            let r = dfs(ctx, c, stack);
            stack.pop();
            match r {
                Ok(o) => {
                    got = Some((o, c.clone()));
                    break;
                }
                Err(Fail::Budget(r_)) => return Err(Fail::Budget(r_)),
                Err(f) => last_fail = Some(f),
            }
        }
        match got {
            Some(x) => base = Some(x),
            None => {
                let f = last_fail.unwrap_or(Fail::Perm {
                    kind: "no-candidate".into(),
                    msg: "所有候选源均失败".into(),
                    chain: vec![],
                });
                return Err(f.prepend(key, "ref-delta 依赖"));
            }
        }
    }

    let (content, type_name, depth, step_info) = if is_delta {
        let (b, bkey) = base.expect("delta entry must have a base");
        let info = apply_delta(&b.content, &inflated).map_err(|e| Fail::Perm {
            kind: "delta-apply".into(),
            msg: e,
            chain: vec![],
        })?;
        let depth = b.depth + 1;
        (
            info.output,
            b.type_name.clone(),
            depth,
            Some((b, bkey, info.src_size, info.tgt_size)),
        )
    } else {
        (
            (*inflated).clone(),
            gitutil::type_name(node.type_id).to_string(),
            0,
            None,
        )
    };

    // Budget checks happen BEFORE anything is persisted: a tripped budget
    // never leaves partial output registered as a complete object.
    let out_len = content.len() as i64;
    if depth > ctx.budget.max_depth {
        return Err(Fail::Budget(format!(
            "delta 深度 {depth} 超过上限 {}",
            ctx.budget.max_depth
        )));
    }
    if (out_len as i128) * 100
        > (ctx.budget.max_total_bytes as i128) * (ctx.budget.max_object_pct as i128)
    {
        return Err(Fail::Budget(format!(
            "单对象 {out_len} 字节超过总预算 {}% 的比例限制",
            ctx.budget.max_object_pct
        )));
    }
    if ctx.expanded + out_len > ctx.budget.max_total_bytes {
        return Err(Fail::Budget(format!(
            "总展开字节将超过上限 {} 字节",
            ctx.budget.max_total_bytes
        )));
    }
    ctx.expanded += out_len;

    let oid = gitutil::object_id(&type_name, &content);
    let obj = Rc::new(Obj {
        oid: oid.clone(),
        type_name,
        content: Rc::new(content),
        depth,
    });
    let _ = ctx.conn.execute(
        "INSERT OR REPLACE INTO resolved(key,oid,type_name,content,depth,run_id) VALUES(?1,?2,?3,?4,?5,?6)",
        params![key, obj.oid, obj.type_name, obj.content.as_slice(), depth, ctx.run_id],
    );
    let _ = ctx.conn.execute(
        "INSERT OR REPLACE INTO entry_status(key,status,error_kind,error_msg,blockers) VALUES(?1,'resolved',NULL,NULL,NULL)",
        params![key],
    );
    if let Some((b, bkey, src_size, tgt_size)) = step_info {
        let _ = ctx.conn.execute(
            "INSERT OR IGNORE INTO deps(child,parent) VALUES(?1,?2)",
            params![key, bkey],
        );
        let _ = ctx.conn.execute(
            "INSERT INTO delta_steps(entry_key,base_key,base_oid,instr_offset,instr_len,src_size,tgt_size,in_len,out_len,src_ok,tgt_ok,oid,run_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1,1,?10,?11)",
            params![
                key,
                bkey,
                b.oid,
                (node.pack_offset + node.hdr_len) as i64,
                node.comp_len as i64,
                src_size as i64,
                tgt_size as i64,
                b.content.len() as i64,
                out_len,
                oid,
                ctx.run_id
            ],
        );
    }
    ctx.resolved_oids.entry(oid).or_default().push(key.to_string());
    ctx.cache.insert(key.to_string(), obj.clone());
    Ok(obj)
}

pub fn run_resolve(conn: &Connection, budget: Budget) -> RunReport {
    let _ = conn.execute(
        "INSERT INTO runs(status,max_depth,max_total_bytes,max_object_pct) VALUES('running',?1,?2,?3)",
        params![budget.max_depth, budget.max_total_bytes, budget.max_object_pct],
    );
    let run_id = conn.last_insert_rowid();
    let nodes = load_nodes(conn).unwrap_or_default();
    let (cache, resolved_oids) = preload(conn);
    let mut claimed: HashMap<String, Vec<String>> = HashMap::new();
    for n in nodes.values() {
        if let Some(c) = &n.claimed_oid {
            claimed.entry(c.clone()).or_default().push(n.key.clone());
        }
    }
    let mut pins: HashMap<String, String> = HashMap::new();
    if let Ok(mut st) = conn.prepare("SELECT oid, entry_key FROM pins") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            for r in rows.flatten() {
                pins.insert(r.0, r.1);
            }
        }
    }
    // Statuses from previous runs are recomputed for anything not resolved.
    let _ = conn.execute("DELETE FROM entry_status WHERE key NOT IN (SELECT key FROM resolved)", []);

    let mut ctx = Ctx {
        conn,
        nodes,
        claimed,
        resolved_oids,
        cache,
        perm_failed: HashSet::new(),
        pins,
        budget,
        expanded: 0,
        run_id,
        paused: None,
    };

    let mut keys: Vec<String> = ctx.nodes.keys().cloned().collect();
    keys.sort_by(|a, b| {
        let na = &ctx.nodes[a];
        let nb = &ctx.nodes[b];
        (&na.source_sha1, na.pack_offset, a).cmp(&(&nb.source_sha1, nb.pack_offset, b))
    });

    loop {
        let mut progress = false;
        for key in &keys {
            if ctx.paused.is_some() {
                break;
            }
            if ctx.cache.contains_key(key) || ctx.perm_failed.contains(key) {
                continue;
            }
            let mut stack = Vec::new();
            match dfs(&mut ctx, key, &mut stack) {
                Ok(_) => progress = true,
                Err(Fail::Budget(r)) => {
                    record_status(
                        ctx.conn,
                        key,
                        "blocked",
                        Some("budget"),
                        Some(&r),
                        &[ChainStep { key: key.clone(), note: "预算耗尽, 可提高预算后恢复".into() }],
                    );
                    ctx.paused = Some(r);
                    break;
                }
                Err(Fail::Missing { oid, chain }) => {
                    record_status(
                        ctx.conn,
                        key,
                        "blocked",
                        Some("missing-base"),
                        Some(&format!("缺少 base {oid}")),
                        &chain,
                    );
                }
                Err(Fail::Perm { kind, msg, chain }) => {
                    ctx.perm_failed.insert(key.clone());
                    record_status(ctx.conn, key, "error", Some(&kind), Some(&msg), &chain);
                }
            }
        }
        if ctx.paused.is_some() || !progress {
            break;
        }
    }

    let (status, reason) = match &ctx.paused {
        Some(r) => ("paused", Some(r.clone())),
        None => ("done", None),
    };
    let resolved_total = ctx.cache.len();
    let errors: i64 = conn
        .query_row("SELECT COUNT(*) FROM entry_status WHERE status='error'", [], |r| r.get(0))
        .unwrap_or(0);
    let blocked: i64 = conn
        .query_row("SELECT COUNT(*) FROM entry_status WHERE status='blocked'", [], |r| r.get(0))
        .unwrap_or(0);
    let _ = conn.execute(
        "UPDATE runs SET status=?1, expanded_bytes=?2, resolved_count=?3, reason=?4 WHERE id=?5",
        params![status, ctx.expanded, resolved_total as i64, reason, run_id],
    );
    RunReport {
        run_id,
        status: status.to_string(),
        reason,
        resolved_total,
        errors: errors as usize,
        blocked: blocked as usize,
        expanded_bytes: ctx.expanded,
    }
}

/// All keys that (transitively) depend on any of `seeds`.
pub fn descendants(conn: &Connection, seeds: &[String]) -> HashSet<String> {
    let mut affected = HashSet::new();
    let mut frontier: Vec<String> = seeds.to_vec();
    while let Some(k) = frontier.pop() {
        if let Ok(mut st) = conn.prepare("SELECT child FROM deps WHERE parent=?1") {
            if let Ok(rows) = st.query_map(params![k], |r| r.get::<_, String>(0)) {
                for r in rows.flatten() {
                    if affected.insert(r.clone()) {
                        frontier.push(r);
                    }
                }
            }
        }
    }
    affected
}

pub fn invalidate_keys(conn: &Connection, keys: &HashSet<String>) {
    for k in keys {
        let _ = conn.execute("DELETE FROM resolved WHERE key=?1", params![k]);
        let _ = conn.execute("DELETE FROM entry_status WHERE key=?1", params![k]);
        let _ = conn.execute("DELETE FROM delta_steps WHERE entry_key=?1", params![k]);
        let _ = conn.execute("DELETE FROM deps WHERE child=?1 OR parent=?1", params![k]);
    }
}

fn candidate_keys_for_oid(conn: &Connection, oid: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(mut st) = conn.prepare("SELECT key FROM resolved WHERE oid=?1") {
        if let Ok(rows) = st.query_map(params![oid], |r| r.get::<_, String>(0)) {
            out.extend(rows.flatten());
        }
    }
    if let Ok(mut st) = conn.prepare(
        "SELECT 'e:'||e.id FROM entries e WHERE e.claimed_oid=?1
         UNION SELECT 'l:'||l.id FROM loose_objects l WHERE l.claimed_oid=?1",
    ) {
        if let Ok(rows) = st.query_map(params![oid], |r| r.get::<_, String>(0)) {
            for r in rows.flatten() {
                if !out.contains(&r) {
                    out.push(r);
                }
            }
        }
    }
    out
}

/// Pin a conflict source for `oid`, forming an analysis branch: dependents of
/// every candidate of this oid are invalidated so only the affected subgraph
/// is recomputed on the next run.
pub fn set_pin(conn: &Connection, oid: &str, key: &str, branch: &str) -> Result<usize, String> {
    conn.execute(
        "INSERT INTO pins(oid,entry_key,branch) VALUES(?1,?2,?3)
         ON CONFLICT(oid) DO UPDATE SET entry_key=excluded.entry_key, branch=excluded.branch",
        params![oid, key, branch],
    )
    .map_err(|e| e.to_string())?;
    let _ = conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('active_branch',?1)", params![branch]);
    let seeds = candidate_keys_for_oid(conn, oid);
    let affected = descendants(conn, &seeds);
    let n = affected.len();
    invalidate_keys(conn, &affected);
    Ok(n)
}

pub fn unset_pin(conn: &Connection, oid: &str) -> Result<(), String> {
    conn.execute("DELETE FROM pins WHERE oid=?1", params![oid])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Dependent {
    pub key: String,
    pub oid: Option<String>,
    pub relation: String,
}

fn resolved_oid_of(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT oid FROM resolved WHERE key=?1", params![key], |r| r.get(0))
        .ok()
}

pub fn source_keys(conn: &Connection, source_id: i64) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut st) = conn.prepare(
        "SELECT 'e:'||e.id FROM entries e JOIN packs p ON e.pack_id=p.id WHERE p.source_id=?1
         UNION ALL SELECT 'l:'||l.id FROM loose_objects l WHERE l.source_id=?1",
    ) {
        if let Ok(rows) = st.query_map(params![source_id], |r| r.get::<_, String>(0)) {
            out.extend(rows.flatten());
        }
    }
    out
}

/// Objects still depending on a source: its own entries plus everything whose
/// resolution chain passes through them. Shown before deletion.
pub fn source_dependents(conn: &Connection, source_id: i64) -> Vec<Dependent> {
    let own = source_keys(conn, source_id);
    let mut out: Vec<Dependent> = own
        .iter()
        .map(|k| Dependent {
            key: k.clone(),
            oid: resolved_oid_of(conn, k),
            relation: "来自该源".into(),
        })
        .collect();
    for k in descendants(conn, &own) {
        out.push(Dependent {
            oid: resolved_oid_of(conn, &k),
            key: k,
            relation: "依赖链经过该源".into(),
        });
    }
    out
}

pub fn delete_source(conn: &Connection, source_id: i64) -> Vec<Dependent> {
    let deps_report = source_dependents(conn, source_id);
    let own: HashSet<String> = source_keys(conn, source_id).into_iter().collect();
    let mut all = descendants(conn, &own.clone().into_iter().collect::<Vec<_>>());
    all.extend(own);
    invalidate_keys(conn, &all);
    let _ = conn.execute("DELETE FROM sources WHERE id=?1", params![source_id]);
    deps_report
}
