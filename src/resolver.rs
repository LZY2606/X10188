//! Delta DAG reconstruction with budgets, cycle detection, per-candidate
//! evidence and incremental (subgraph-only) recomputation.

use crate::error::AppResult;
use crate::git::{git_object_id, ObjType};
use crate::store::Store;
use rusqlite::{params, Connection};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: i64,
    pub oid: Option<String>,
    pub source_id: i64,
    pub source_hash: String,
    pub origin: String,
    pub ordinal: Option<i64>,
    pub header_offset: Option<i64>,
    pub data_offset: Option<i64>,
    pub end_offset: Option<i64>,
    pub declared_size: Option<i64>,
    pub inflated_size: Option<i64>,
    pub obj_type: String,
    pub ref_base: Option<String>,
    pub ofs_distance: Option<i64>,
    pub base_header_offset: Option<i64>,
    pub content_sha256: Option<String>,
    pub content_path: Option<String>,
    pub bad: bool,
    pub bad_reason: Option<String>,
}

pub struct RunOptions {
    pub add_bytes: i64,
    pub add_depth: i64,
    pub add_ratio: i64,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            add_bytes: 0,
            add_depth: 0,
            add_ratio: 0,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunReport {
    pub run_seq: i64,
    pub complete: usize,
    pub blocked: usize,
    pub paused: usize,
    pub bad: usize,
    pub pause_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct Budget {
    depth_limit: i64,
    byte_budget: i64,
    ratio_limit: i64,
    bytes_used: i64,
    depth_used: i64,
}

#[derive(Debug, Clone)]
pub struct Reconstructed {
    pub obj_type: ObjType,
    pub payload: Vec<u8>,
    pub steps: Vec<StepRecord>,
}

#[derive(Debug, Clone)]
pub struct StepRecord {
    pub base_oid: Option<String>,
    pub base_candidate_id: Option<i64>,
    pub candidate_id: i64,
    pub in_size: usize,
    pub out_size: usize,
    pub declared_base_size: usize,
    pub declared_target_size: usize,
    pub instr_count: usize,
    pub instr_range_start: usize,
    pub instr_range_end: usize,
    pub check_ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct BlockerHop {
    pub oid: String,
    pub candidate_id: Option<i64>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum Fail {
    /// Missing external base, cycle, size spoof, bad candidate: permanent.
    Hard(String, String),
    /// Budget exhausted; retryable after resume.
    Paused(String),
}

#[derive(Debug, Clone)]
struct OutcomeErr {
    fail: Fail,
    attempts: Vec<(i64, Fail)>,
    chain: Vec<BlockerHop>,
}

type Fold<T> = Result<T, OutcomeErr>;

impl Fail {
    fn code(&self) -> &'static str {
        match self {
            Fail::Hard(c, _) => Box::leak(c.clone().into_boxed_str()),
            Fail::Paused(_) => "paused",
        }
    }
    fn message(&self) -> String {
        match self {
            Fail::Hard(_, m) | Fail::Paused(m) => m.clone(),
        }
    }
}

fn hard(code: &str, msg: impl Into<String>) -> OutcomeErr {
    OutcomeErr {
        fail: Fail::Hard(code.to_string(), msg.into()),
        attempts: Vec::new(),
        chain: Vec::new(),
    }
}
fn paused(msg: impl Into<String>) -> OutcomeErr {
    OutcomeErr {
        fail: Fail::Paused(msg.into()),
        attempts: Vec::new(),
        chain: Vec::new(),
    }
}

struct Ctx<'a> {
    conn: &'a Connection,
    store: &'a Store,
    branch_id: i64,
    budget: &'a mut Budget,
    by_oid: &'a HashMap<String, Vec<Candidate>>,
    by_source_offset: &'a HashMap<(i64, i64), Candidate>,
    by_id: &'a HashMap<i64, Candidate>,
    pins: &'a HashMap<String, i64>,
    active: HashSet<String>,
    cache: HashMap<String, Reconstructed>,
    run_seq: i64,
}

pub fn pseudo_oid(cid: i64) -> String {
    format!("anon:cid:{cid}")
}

fn load_candidates(conn: &Connection) -> AppResult<Vec<Candidate>> {
    let mut stmt = conn.prepare(
        "SELECT c.id, c.oid, c.source_id, s.content_sha256, c.origin, c.ordinal,
                c.header_offset, c.data_offset, c.end_offset,
                c.declared_size, c.inflated_size, c.obj_type, c.ref_base, c.ofs_distance,
                c.base_header_offset, c.content_sha256, c.content_path, c.bad, c.bad_reason
         FROM candidates c JOIN sources s ON s.id=c.source_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Candidate {
            id: r.get(0)?,
            oid: r.get(1)?,
            source_id: r.get(2)?,
            source_hash: r.get(3)?,
            origin: r.get(4)?,
            ordinal: r.get(5)?,
            header_offset: r.get(6)?,
            data_offset: r.get(7)?,
            end_offset: r.get(8)?,
            declared_size: r.get(9)?,
            inflated_size: r.get(10)?,
            obj_type: r.get(11)?,
            ref_base: r.get(12)?,
            ofs_distance: r.get(13)?,
            base_header_offset: r.get(14)?,
            content_sha256: r.get(15)?,
            content_path: r.get(16)?,
            bad: r.get::<_, i64>(17)? != 0,
            bad_reason: r.get(18)?,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

fn effective_targets(conn: &Connection) -> AppResult<Vec<String>> {
    let mut targets = Vec::new();
    let mut have = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT oid FROM candidates WHERE oid IS NOT NULL",
    )?;
    for oid in stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
    {
        if have.insert(oid.clone()) {
            targets.push(oid);
        }
    }
    let mut stmt2 = conn.prepare(
        "SELECT id FROM candidates WHERE oid IS NULL
         AND obj_type IN ('ofs-delta','ref-delta')",
    )?;
    for cid in stmt2
        .query_map([], |r| r.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
    {
        let p = pseudo_oid(cid);
        if have.insert(p.clone()) {
            targets.push(p);
        }
    }
    targets.sort();
    Ok(targets)
}

fn load_pins(conn: &Connection, branch_id: i64) -> AppResult<HashMap<String, i64>> {
    let mut stmt = conn.prepare("SELECT oid, candidate_id FROM pins WHERE branch_id=?1")?;
    let rows = stmt.query_map(params![branch_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

fn ordered_candidates<'b>(
    list: &'b [Candidate],
    pins: &HashMap<String, i64>,
    oid: &str,
) -> Vec<&'b Candidate> {
    let pinned = pins.get(oid).copied();
    let mut v: Vec<&Candidate> = list.iter().collect();
    v.sort_by_key(|c| {
        (
            c.bad as i64,
            if Some(c.id) == pinned { 0 } else { 1 },
            c.source_hash.clone(),
            if c.origin == "loose" { 0 } else { 1 },
            c.ordinal.unwrap_or(c.header_offset.unwrap_or(0)),
            c.id,
        )
    });
    v
}

#[allow(clippy::too_many_arguments)]
pub fn run_branch(
    conn: &mut Connection,
    store: Store,
    branch_id: i64,
    opts: &RunOptions,
    changed_oids: Option<&HashSet<String>>,
    force_all: bool,
) -> AppResult<RunReport> {
    let run_seq = {
        conn.execute(
            "UPDATE budget SET run_seq=run_seq+1,
             depth_limit=depth_limit+?2,
             byte_budget=byte_budget+?3,
             ratio_limit=ratio_limit+?4
             WHERE branch_id=?1",
            params![branch_id, opts.add_depth, opts.add_bytes, opts.add_ratio],
        )?;
        conn.query_row(
            "SELECT run_seq FROM budget WHERE branch_id=?1",
            params![branch_id],
            |r| r.get::<_, i64>(0),
        )?
    };
    let row: (i64, i64, i64, i64) = conn.query_row(
        "SELECT depth_limit, byte_budget, bytes_used, ratio_limit
         FROM budget WHERE branch_id=?1",
        params![branch_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let mut budget = Budget {
        depth_limit: row.0,
        byte_budget: row.1,
        ratio_limit: row.2,
        bytes_used: row.3,
        depth_used: 0,
    };

    let all = load_candidates(conn)?;
    let mut by_oid: HashMap<String, Vec<Candidate>> = HashMap::new();
    let mut by_source_offset: HashMap<(i64, i64), Candidate> = HashMap::new();
    let mut by_id: HashMap<i64, Candidate> = HashMap::new();
    for c in all {
        if let Some(oid) = &c.oid {
            by_oid.entry(oid.clone()).or_default().push(c.clone());
        }
        if let Some(ho) = c.header_offset {
            by_source_offset.insert((c.source_id, ho), c.clone());
        }
        by_id.insert(c.id, c);
    }
    let pins = load_pins(conn, branch_id)?;
    let targets = effective_targets(conn)?;

    let mut work: Vec<String> = Vec::new();
    for oid in &targets {
        if let Some(sub) = changed_oids {
            if !sub.contains(oid) {
                continue;
            }
        }
        let state: Option<String> = conn
            .query_row(
                "SELECT status FROM resolved WHERE branch_id=?1 AND oid=?2",
                params![branch_id, oid],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        if force_all || state.as_deref() != Some("complete") {
            work.push(oid.clone());
        }
    }
    work.sort();
    for oid in &work {
        conn.execute(
            "DELETE FROM delta_steps WHERE branch_id=?1 AND oid=?2",
            params![branch_id, oid],
        )?;
        conn.execute(
            "DELETE FROM blockers WHERE branch_id=?1 AND oid=?2",
            params![branch_id, oid],
        )?;
    }

    let mut report = RunReport {
        run_seq,
        ..Default::default()
    };

    let mut ctx = Ctx {
        conn,
        store: &store,
        branch_id,
        budget: &mut budget,
        by_oid: &by_oid,
        by_source_offset: &by_source_offset,
        by_id: &by_id,
        pins: &pins,
        active: HashSet::new(),
        cache: HashMap::new(),
        run_seq,
    };

    for oid in work {
        let outcome = resolve_oid(&mut ctx, &oid, 0, &mut Vec::new());
        persist_outcome(&mut ctx, &oid, outcome, &mut report);
    }

    let paused_count = report.paused;
    drop(ctx);
    let (depth_used, bytes_used) = (budget.depth_used, budget.bytes_used);
    let pause_msg = if paused_count > 0 {
        Some(
            conn.query_row(
                "SELECT failure FROM resolved
                 WHERE branch_id=?1 AND status='paused' LIMIT 1",
                params![branch_id],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "budget exhausted".to_string()),
        )
    } else {
        None
    };
    report.pause_reason = pause_msg.clone();
    conn.execute(
        "UPDATE budget SET depth_used=?2, bytes_used=?3, paused=?4, last_pause=?5
         WHERE branch_id=?1",
        params![
            branch_id,
            depth_used,
            bytes_used,
            if pause_msg.is_some() { 1 } else { 0 },
            pause_msg
        ],
    )?;
    Ok(report)
}

fn resolve_oid(
    ctx: &mut Ctx,
    oid: &str,
    depth: i64,
    chain: &mut Vec<BlockerHop>,
) -> Fold<Reconstructed> {
    if depth > 0 {
        if let Some(rec) = ctx.cache.get(oid).cloned() {
            return Ok(rec);
        }
        if let Some(rec) = load_completed(ctx, oid) {
            return Ok(rec);
        }
    }
    if ctx.active.contains(oid) {
        let path: Vec<String> = chain
            .iter()
            .map(|h| h.oid.clone())
            .chain(std::iter::once(oid.to_string()))
            .collect();
        return Err(hard(
            "delta_cycle",
            format!("delta cycle detected: {}", path.join(" -> ")),
        ));
    }
    ctx.active.insert(oid.to_string());

    let ordered: Vec<Candidate> = if let Some(stripped) = oid.strip_prefix("anon:cid:") {
        let cid: i64 = stripped.parse().unwrap_or(-1);
        ctx.by_id.get(&cid).cloned().into_iter().collect()
    } else {
        ctx.by_oid.get(oid).cloned().unwrap_or_default()
    };
    let ranked: Vec<&Candidate> = ordered_candidates(&ordered, ctx.pins, oid);

    let mut attempts: Vec<(i64, Fail)> = Vec::new();
    let mut outcome: Fold<Reconstructed> =
        Err(hard("missing_base", format!("no candidate objects for {oid}")));
    for cand in &ranked {
        let mut sub_chain = chain.clone();
        sub_chain.push(BlockerHop {
            oid: oid.to_string(),
            candidate_id: Some(cand.id),
            code: "candidate".into(),
            message: format!("trying candidate {}", cand.id),
        });
        match resolve_candidate(ctx, oid, cand, depth, &mut sub_chain) {
            Ok(rec) => {
                outcome = Ok(rec);
                break;
            }
            Err(mut e) => {
                attempts.push((cand.id, e.fail.clone()));
                e.attempts = attempts.clone();
                e.chain = sub_chain;
                outcome = Err(e);
            }
        }
    }

    if let Err(e) = &outcome {
        // Merge child attempt chains for the blocker list.
        attempts = e.attempts.clone();
        let _ = chain;
    }

    ctx.active.remove(oid);
    match outcome {
        Ok(rec) => {
            if depth > 0 {
                ctx.cache.insert(oid.to_string(), rec.clone());
            }
            Ok(rec)
        }
        Err(mut e) => {
            e.attempts = attempts;
            Err(e)
        }
    }
}

fn load_completed(ctx: &Ctx, oid: &str) -> Option<Reconstructed> {
    let (type_name, rel): (String, String) = ctx
        .conn
        .query_row(
            "SELECT obj_type, content_path FROM resolved
             WHERE branch_id=?1 AND oid=?2 AND status='complete'",
            params![ctx.branch_id, oid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()?;
    let data = ctx.store.read_content(&rel).ok()?;
    Some(Reconstructed {
        obj_type: ObjType::parse_loose(&type_name).unwrap_or(ObjType::Blob),
        payload: data,
        steps: Vec::new(),
    })
}

fn inflate_candidate(ctx: &Ctx, cand: &Candidate) -> Result<Vec<u8>, String> {
    if let Some(rel) = &cand.content_path {
        return ctx.store.read_content(rel).map_err(|e| e.to_string());
    }
    let stored: String = ctx
        .conn
        .query_row(
            "SELECT stored_path FROM sources WHERE id=?1",
            params![cand.source_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let bytes = std::fs::read(ctx.store.data_dir.join(&stored)).map_err(|e| e.to_string())?;
    let start = cand.data_offset.ok_or("candidate missing data offset")? as usize;
    let end = cand.end_offset.ok_or("candidate missing end offset")? as usize;
    if end > bytes.len() || start > end {
        return Err("candidate zlib range outside source file".into());
    }
    let z = crate::zlibm::inflate_member(&bytes, start, end - start + 1)?;
    if start + z.consumed != end {
        return Err(format!(
            "zlib boundary mismatch: consumed {} expected {}",
            z.consumed,
            end - start
        ));
    }
    Ok(z.data)
}

fn charge_bytes(ctx: &mut Ctx, n: usize) -> Fold<()> {
    if n as i64 > ctx.budget.ratio_limit * 1024 * 1024 {
        return Err(paused(format!(
            "single object expansion {n} bytes exceeds per-object ratio limit {} MiB; \
             raise the ratio and resume",
            ctx.budget.ratio_limit
        )));
    }
    let total = ctx.budget.bytes_used + n as i64;
    if total > ctx.budget.byte_budget {
        return Err(paused(format!(
            "total inflated byte budget {} exceeded ({total} bytes); \
             add budget and resume (partial output is never accepted)",
            ctx.budget.byte_budget
        )));
    }
    ctx.budget.bytes_used = total;
    Ok(())
}

fn parse_type(name: &str) -> Option<ObjType> {
    match name {
        "commit" => Some(ObjType::Commit),
        "tree" => Some(ObjType::Tree),
        "blob" => Some(ObjType::Blob),
        "tag" => Some(ObjType::Tag),
        "ofs-delta" => Some(ObjType::OfsDelta),
        "ref-delta" => Some(ObjType::RefDelta),
        _ => None,
    }
}

fn resolve_candidate(
    ctx: &mut Ctx,
    oid: &str,
    cand: &Candidate,
    depth: i64,
    chain: &mut Vec<BlockerHop>,
) -> Fold<Reconstructed> {
    if depth > ctx.budget.depth_limit {
        return Err(paused(format!(
            "delta chain depth {depth} exceeds limit {}; increase depth and resume",
            ctx.budget.depth_limit
        )));
    }
    if depth > ctx.budget.depth_used {
        ctx.budget.depth_used = depth;
    }
    if cand.bad {
        return Err(hard(
            "bad_candidate",
            format!(
                "candidate {} flagged corrupt: {}",
                cand.id,
                cand.bad_reason.clone().unwrap_or_default()
            ),
        ));
    }
    let obj_type = parse_type(&cand.obj_type)
        .ok_or_else(|| hard("unknown_type", format!("type {}", cand.obj_type)))?;

    if !obj_type.is_delta() {
        let payload = inflate_candidate(ctx, cand)
            .map_err(|e| hard("inflate_failed", e))?;
        if let Some(decl) = cand.declared_size {
            if decl as usize != payload.len() {
                return Err(hard(
                    "size_spoof",
                    format!("declared {decl} bytes but inflated to {}", payload.len()),
                ));
            }
        }
        charge_bytes(ctx, payload.len())?;
        let computed = git_object_id(obj_type, &payload);
        let is_anon = oid == pseudo_oid(cand.id);
        if !is_anon && computed != oid {
            return Err(hard(
                "oid_mismatch",
                format!("content hashes to {computed}, expected {oid}"),
            ));
        }
        return Ok(Reconstructed {
            obj_type,
            payload,
            steps: Vec::new(),
        });
    }

    let (base_oid, base_cand) = if obj_type == ObjType::RefDelta {
        let base_oid = cand
            .ref_base
            .clone()
            .ok_or_else(|| hard("delta_bad_ref", "ref-delta without base oid"))?;
        let list = ctx.by_oid.get(&base_oid).cloned();
        let ranked = list.map(|l| ordered_candidates(&l, ctx.pins, &base_oid).into_iter().cloned().collect::<Vec<_>>());
        let base_cand = ranked
            .and_then(|mut v| if v.is_empty() { None } else { Some(v.remove(0)) })
            .ok_or_else(|| {
                hard(
                    "missing_base",
                    format!("external ref-delta base {base_oid} is not imported"),
                )
            })?;
        (base_oid, base_cand)
    } else {
        let base_off = cand
            .base_header_offset
            .ok_or_else(|| hard("ofs_out_of_range", "ofs-delta missing base offset"))?;
        if base_off < 12 || base_off >= cand.header_offset.unwrap_or(i64::MAX) {
            return Err(hard(
                "ofs_out_of_range",
                format!(
                    "ofs distance {} escapes the pack (base offset {base_off})",
                    cand.ofs_distance.unwrap_or(0)
                ),
            ));
        }
        let base_cand = ctx
            .by_source_offset
            .get(&(cand.source_id, base_off))
            .cloned()
            .ok_or_else(|| {
                hard(
                    "ofs_out_of_range",
                    format!(
                        "ofs distance {} does not land on a pack entry",
                        cand.ofs_distance.unwrap_or(0)
                    ),
                )
            })?;
        let base_oid = base_cand
            .oid
            .clone()
            .unwrap_or_else(|| pseudo_oid(base_cand.id));
        (base_oid, base_cand)
    };

    chain.push(BlockerHop {
        oid: base_oid.clone(),
        candidate_id: Some(base_cand.id),
        code: "depends_on".into(),
        message: "delta base".into(),
    });
    let base = resolve_oid(ctx, &base_oid, depth + 1, chain)?;
    chain.pop();

    let delta_bytes = inflate_candidate(ctx, cand)
        .map_err(|e| hard("inflate_failed", e))?;
    if let Some(decl) = cand.declared_size {
        if decl as usize != delta_bytes.len() {
            return Err(hard(
                "size_spoof",
                format!("delta declares {decl} bytes but inflated to {}", delta_bytes.len()),
            ));
        }
    }
    charge_bytes(ctx, delta_bytes.len())?;
    let applied = crate::delta::apply_delta(&base.payload, &delta_bytes)
        .map_err(|e| hard("delta_apply", e))?;
    let out_type = base.obj_type;
    charge_bytes(ctx, applied.output.len())?;
    let computed = git_object_id(out_type, &applied.output);
    let is_anon = oid == pseudo_oid(cand.id);
    let check_ok = is_anon || computed == oid;
    let first = applied
        .instructions
        .first()
        .map(|i| i.start)
        .unwrap_or(applied.header_end);
    let last = applied
        .instructions
        .last()
        .map(|i| i.end)
        .unwrap_or(applied.header_end);
    let mut steps = base.steps.clone();
    steps.push(StepRecord {
        base_oid: Some(base_oid.clone()),
        base_candidate_id: Some(base_cand.id),
        candidate_id: cand.id,
        in_size: base.payload.len(),
        out_size: applied.output.len(),
        declared_base_size: applied.declared_base_size,
        declared_target_size: applied.declared_target_size,
        instr_count: applied.instructions.len(),
        instr_range_start: first,
        instr_range_end: last,
        check_ok,
        detail: serde_json::to_string(&applied.instructions).unwrap_or_default(),
    });
    if !check_ok {
        return Err(hard(
            "oid_mismatch",
            format!("reconstructed object id is {computed}, expected {oid}"),
        ));
    }
    Ok(Reconstructed {
        obj_type: out_type,
        payload: applied.output,
        steps,
    })
}

fn persist_outcome(
    ctx: &mut Ctx,
    oid: &str,
    outcome: Fold<Reconstructed>,
    report: &mut RunReport,
) {
    match outcome {
        Ok(rec) => {
            write_completed(ctx, oid, &rec);
            // Also cache intermediary bases for siblings within the same run.
            ctx.cache.insert(oid.to_string(), rec);
            report.complete += 1;
        }
        Err(e) => {
            write_failed(ctx, oid, e, report);
        }
    }
}

fn write_completed(ctx: &mut Ctx, oid: &str, rec: &Reconstructed) {
    let (hash, rel) = match ctx.store.write_content(&rec.payload) {
        Ok(v) => v,
        Err(_) => return,
    };
    let chosen = rec
        .steps
        .last()
        .map(|s| s.candidate_id)
        .or_else(|| ctx.by_oid.get(oid).and_then(|v| v.first()).map(|c| c.id));
    ctx.conn
        .execute(
            "INSERT INTO resolved(branch_id, oid, candidate_id, status, obj_type, final_size,
                content_sha256, content_path, check_ok, failure, resume_hint, run_seq)
             VALUES(?1,?2,?3,'complete',?4,?5,?6,?7,1,NULL,NULL,?8)
             ON CONFLICT(branch_id, oid) DO UPDATE SET
               candidate_id=excluded.candidate_id, status='complete',
               obj_type=excluded.obj_type, final_size=excluded.final_size,
               content_sha256=excluded.content_sha256,
               content_path=excluded.content_path, check_ok=1,
               failure=NULL, resume_hint=NULL, run_seq=excluded.run_seq",
            params![
                ctx.branch_id,
                oid,
                chosen,
                rec.obj_type.name(),
                rec.payload.len() as i64,
                hash,
                rel,
                ctx.run_seq
            ],
        )
        .ok();
    for (i, st) in rec.steps.iter().enumerate() {
        ctx.conn
            .execute(
                "INSERT INTO delta_steps(branch_id, oid, step, base_oid, base_candidate_id,
                   candidate_id, in_size, out_size, declared_base_size, declared_target_size,
                   instr_count, instr_range_start, instr_range_end, check_ok, detail)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    ctx.branch_id,
                    oid,
                    i as i64,
                    st.base_oid,
                    st.base_candidate_id,
                    st.candidate_id,
                    st.in_size as i64,
                    st.out_size as i64,
                    st.declared_base_size as i64,
                    st.declared_target_size as i64,
                    st.instr_count as i64,
                    st.instr_range_start as i64,
                    st.instr_range_end as i64,
                    st.check_ok as i64,
                    st.detail
                ],
            )
            .ok();
    }
}

fn write_failed(ctx: &mut Ctx, oid: &str, e: OutcomeErr, report: &mut RunReport) {
    let chain_json = serde_json::to_string(
        &e.chain
            .iter()
            .map(|h| {
                serde_json::json!({
                    "oid": h.oid,
                    "candidate_id": h.candidate_id,
                    "code": h.code,
                    "message": h.message,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default();

    for (i, (cid, f)) in e.attempts.iter().enumerate() {
        ctx.conn
            .execute(
                "INSERT INTO blockers(branch_id, oid, ordinal, level, code, message, candidate_id, chain)
                 VALUES(?1,?2,?3,'warning','alt_candidate_failed',?4,?5,NULL)",
                params![ctx.branch_id, oid, i as i64, f.message(), cid],
            )
            .ok();
    }

    let chosen = e.attempts.last().map(|(cid, _)| *cid);
    match &e.fail {
        Fail::Paused(msg) => {
            ctx.conn
                .execute(
                    "INSERT INTO resolved(branch_id, oid, candidate_id, status, failure, resume_hint, run_seq)
                     VALUES(?1,?2,?3,'paused',?4,?4,?5)
                     ON CONFLICT(branch_id, oid) DO UPDATE SET
                       candidate_id=excluded.candidate_id, status='paused',
                       failure=excluded.failure, resume_hint=excluded.failure,
                       run_seq=excluded.run_seq",
                    params![ctx.branch_id, oid, chosen, msg, ctx.run_seq],
                )
                .ok();
            ctx.conn
                .execute(
                    "INSERT INTO blockers(branch_id, oid, ordinal, level, code, message, candidate_id, chain)
                     VALUES(?1,?2,0,'error','paused',?3,?4,?5)",
                    params![ctx.branch_id, oid, msg, chosen, chain_json],
                )
                .ok();
            report.paused += 1;
        }
        Fail::Hard(code, msg) => {
            let status = if code == "missing_base"
                || code == "delta_cycle"
                || code == "ofs_out_of_range"
            {
                "blocked"
            } else {
                "bad"
            };
            ctx.conn
                .execute(
                    "INSERT INTO resolved(branch_id, oid, candidate_id, status, failure, run_seq)
                     VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(branch_id, oid) DO UPDATE SET
                       candidate_id=excluded.candidate_id, status=excluded.status,
                       failure=excluded.failure, resume_hint=NULL, run_seq=excluded.run_seq",
                    params![ctx.branch_id, oid, chosen, status, msg, ctx.run_seq],
                )
                .ok();
            ctx.conn
                .execute(
                    "INSERT INTO blockers(branch_id, oid, ordinal, level, code, message, candidate_id, chain)
                     VALUES(?1,?2,0,'error',?3,?4,?5,?6)",
                    params![ctx.branch_id, oid, code, msg, chosen, chain_json],
                )
                .ok();
            if status == "blocked" {
                report.blocked += 1;
            } else {
                report.bad += 1;
            }
        }
    }
}

/// Compute the set of oids whose candidate set changed (`seed`) plus every
/// oid that depends on them through delta edges (reverse closure).
pub fn affected_subgraph(
    conn: &Connection,
    seed_oids: &HashSet<String>,
) -> AppResult<HashSet<String>> {
    let mut affected = seed_oids.clone();
    // Edge map: base_oid -> candidate ids that use it (ref-delta),
    // base_header_offset handled by resolving to oid via pack candidates.
    let mut stack: Vec<String> = seed_oids.iter().cloned().collect();
    while let Some(base) = stack.pop() {
        // ref-delta dependents
        let mut stmt = conn.prepare(
            "SELECT c.oid FROM candidates c
             JOIN graph_edges g ON g.candidate_id=c.id
             WHERE g.kind='ref-delta' AND g.base_oid=?1 AND c.oid IS NOT NULL",
        )?;
        let deps: Vec<String> = stmt
            .query_map(params![base], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for d in deps {
            if affected.insert(d.clone()) {
                stack.push(d);
            }
        }
        // ofs-delta dependents: find candidate(s) with this oid's header
        // offsets then children whose base_header_offset matches.
        let mut stmt2 = conn.prepare(
            "SELECT c2.oid
             FROM candidates c1
             JOIN candidates c2 ON c2.source_id=c1.source_id
             JOIN graph_edges g ON g.candidate_id=c2.id
             WHERE g.kind='ofs-delta'
               AND c1.oid=?1
               AND g.base_header_offset=c1.header_offset
               AND c2.oid IS NOT NULL",
        )?;
        let deps2: Vec<String> = stmt2
            .query_map(params![base], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for d in deps2 {
            if affected.insert(d.clone()) {
                stack.push(d);
            }
        }
    }
    Ok(affected)
}

/// Seed set: every oid with a candidate belonging to newly imported sources.
pub fn seed_oids_for_sources(
    conn: &Connection,
    source_ids: &[i64],
) -> AppResult<HashSet<String>> {
    let mut set = HashSet::new();
    for sid in source_ids {
        let mut stmt = conn.prepare(
            "SELECT oid FROM candidates WHERE source_id=?1 AND oid IS NOT NULL
             UNION
             SELECT 'x'",
        )?;
        let _ = stmt;
        let mut stmt =
            conn.prepare("SELECT oid FROM candidates WHERE source_id=?1 AND oid IS NOT NULL")?;
        let rows = stmt
            .query_map(params![sid], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok());
        for oid in rows {
            set.insert(oid);
        }
    }
    Ok(set)
}
