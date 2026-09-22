//! Delta DAG resolution: candidate ranking, budgets, cycles, blockers,
//! incremental recomputation and branch pinning.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::params;

use crate::git::{apply_delta, git_oid, Kind};
use crate::model::{
    Blocker, Budget, EvalOutcome, ResolveError, StepRec,
};
use crate::store::{EntryRow, Store};

/// Loaded in-memory view of one entry plus its inflated payload.
#[derive(Clone)]
pub struct Node {
    pub row: EntryRow,
    pub payload: Option<Vec<u8>>,
}

pub struct Engine<'a> {
    pub store: &'a Store,
    pub branch: String,
    pub budget: Budget,
    pub nodes: BTreeMap<i64, Node>,
    /// oid -> candidate entry ids, in deterministic rank order
    pub providers: BTreeMap<String, Vec<i64>>,
    /// oid -> pinned entry id for current branch
    pub pins: HashMap<String, i64>,
    /// entry -> memoized outcome within this pass
    pub memo: HashMap<i64, EvalOutcome>,
    /// entries on the active DFS stack (cycle detection)
    pub stack: Vec<i64>,
    /// cumulative produced bytes this pass
    pub total_bytes: u64,
    pub run_seq: i64,
    /// total bytes at which this pass began (for persisted cumulative budget)
    pub budget_start_bytes: u64,
    /// number of entries whose previous ok resolution was reused
    pub reused: u64,
}

#[derive(Default, Debug, Clone)]
pub struct RunReport {
    pub run_seq: i64,
    pub ok: usize,
    pub paused: usize,
    pub error: usize,
    pub total_bytes: u64,
    pub reused: u64,
}

/// Deterministic candidate ranking key, independent of import order.
/// loose before pack, then source name, then byte offset (loose = 0).
fn rank_key(store: &Store, e: &EntryRow) -> (i64, String, i64) {
    let (kind, name): (String, String) = store
        .db
        .query_row(
            "SELECT kind,name FROM sources WHERE id=?1",
            params![e.source_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_default();
    let loose_first = if kind == "loose" { 0 } else { 1 };
    (loose_first, name, e.offset.unwrap_or(0))
}

impl<'a> Engine<'a> {
    pub fn new(store: &'a Store, branch: &str, budget: Budget, run_seq: i64) -> Self {
        Engine {
            store,
            branch: branch.to_string(),
            budget,
            nodes: BTreeMap::new(),
            providers: BTreeMap::new(),
            pins: HashMap::new(),
            memo: HashMap::new(),
            stack: Vec::new(),
            total_bytes: 0,
            run_seq,
            budget_start_bytes: 0,
            reused: 0,
        }
    }

    pub(crate) fn load(&mut self) -> rusqlite::Result<()> {
        let mut stmt = self.store.db.prepare(
            "SELECT id,source_id,offset,type_code,type_name,delta,base_oid,base_offset,
                    base_entry_id,declared_size,inflated_size,z_off,z_len,claimed_oid,
                    parse_err,sha256
             FROM entries",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(EntryRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                offset: r.get(2)?,
                type_code: r.get(3)?,
                type_name: r.get(4)?,
                delta: r.get(5)?,
                base_oid: r.get(6)?,
                base_offset: r.get(7)?,
                base_entry_id: r.get(8)?,
                declared_size: r.get(9)?,
                inflated_size: r.get(10)?,
                z_off: r.get(11)?,
                z_len: r.get(12)?,
                claimed_oid: r.get(13)?,
                parse_err: r.get(14)?,
                sha256: r.get(15)?,
            })
        })?;
        let mut all = Vec::new();
        for r in rows {
            all.push(r?);
        }
        drop(stmt);

        // Pins
        let mut ps = self
            .store
            .db
            .prepare(
                "SELECT p.oid,p.entry_id FROM branch_pins p
                 JOIN branches b ON b.id=p.branch_id WHERE b.name=?1",
            )?;
        let prs = ps.query_map(params![self.branch], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for x in prs {
            let (oid, eid) = x?;
            self.pins.insert(oid, eid);
        }
        drop(ps);

        // Sort deterministically, assign ofs bases, build providers from
        // claimed oids (only structurally valid entries are candidates).
        let store = self.store;
        all.sort_by(|a, b| {
            rank_key(store, a)
                .cmp(&rank_key(store, b))
                .then(a.id.cmp(&b.id))
        });

        // offset -> entry id per source for ofs base assignment
        let mut off_map: BTreeMap<(i64, i64), i64> = BTreeMap::new();
        for e in &all {
            if let (Some(sid), Some(off)) = (e.source_id.into(), e.offset) {
                off_map.insert((sid, off), e.id);
            }
        }
        for e in &all {
            let base = if e.delta.as_deref() == Some("ofs-delta") {
                e.base_offset
                    .and_then(|bo| off_map.get(&(e.source_id, bo)).copied())
            } else {
                e.base_entry_id
            };
            let cur = self
                .store
                .db
                .query_row(
                    "SELECT base_entry_id FROM entries WHERE id=?1",
                    params![e.id],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten();
            if cur != base {
                self.store.set_base_entry(e.id, base)?;
            }
        }

        for e in all {
            let payload = if e.parse_err.is_none() {
                let rel = format!("inflated/s{}_e{}", e.source_id, e.id);
                std::fs::read(self.store.data_dir.join(rel)).ok()
            } else {
                None
            };
            self.nodes.insert(e.id, Node { row: e, payload });
        }
        // Providers: structurally valid entries keyed by claimed oid.
        for (_, n) in self.nodes.iter() {
            if let Some(oid) = n.row.claimed_oid.clone() {
                if n.row.parse_err.is_none() {
                    self.providers.entry(oid).or_default().push(n.row.id);
                }
            }
        }
        Ok(())
    }

    fn kind_of(node: &Node) -> Option<Kind> {
        node.row.type_code.and_then(|c| Kind::from_code(c as u8))
    }

    fn parse_error_of(node: &Node) -> Option<ResolveError> {
        node.row
            .parse_err
            .as_ref()
            .and_then(|j| serde_json::from_str::<ResolveError>(j).ok())
    }

    /// Choose the provider entry for `oid`, honoring branch pins.
    fn choose_provider(&self, oid: &str) -> Result<i64, Option<ResolveError>> {
        let cands = match self.providers.get(oid) {
            Some(c) => c,
            None => return Err(Some(ResolveError::MissingBase(oid.to_string()))),
        };
        if let Some(pinned) = self.pins.get(oid) {
            if cands.contains(pinned) {
                return Ok(*pinned);
            }
            return Err(Some(ResolveError::MissingBase(format!(
                "pinned source no longer provides {oid}"
            ))));
        }
        Ok(*cands.first().unwrap())
    }

    fn eval(&mut self, id: i64) -> EvalOutcome {
        if let Some(o) = self.memo.get(&id) {
            return o.clone();
        }
        if let Some(p) = self.stack.iter().position(|x| *x == id) {
            let cyc = self.stack[p..].to_vec();
            return EvalOutcome::Error(ResolveError::Cycle(cyc));
        }
        self.stack.push(id);
        let out = self.eval_inner(id);
        self.stack.pop();
        if !matches!(out, EvalOutcome::Paused { .. }) {
            self.memo.insert(id, out.clone());
        }
        out
    }

    fn eval_inner(&mut self, id: i64) -> EvalOutcome {
        let node = match self.nodes.get(&id) {
            Some(n) => n.clone(),
            None => {
                return EvalOutcome::Error(ResolveError::MissingBase(format!("entry {id}")))
            }
        };

        if let Some(e) = Self::parse_error_of(&node) {
            return EvalOutcome::Error(e);
        }
        let payload = match &node.payload {
            Some(p) => p.clone(),
            None => {
                return EvalOutcome::Error(ResolveError::Entry(crate::model::EntryError::Inflate(
                    "inflated payload missing".into(),
                )))
            }
        };

        let delta = node.row.delta.clone();
        if delta.is_none() {
            // Non-delta: payload is canonical object content.
            let kind = match Self::kind_of(&node) {
                Some(k) => k,
                None => {
                    return EvalOutcome::Error(ResolveError::Entry(
                        crate::model::EntryError::UnknownType(node.row.type_code.unwrap_or(0) as u8),
                    ))
                }
            };
            let size = payload.len() as u64;
            if size > self.budget.per_object_bytes {
                return EvalOutcome::Paused {
                    reason: format!("per-object cap: {size} > {}", self.budget.per_object_bytes),
                    partial_depth: 0,
                };
            }
            if self.total_bytes + size > self.budget.total_bytes {
                return EvalOutcome::Paused {
                    reason: format!("total expansion budget reached ({size} more bytes)"),
                    partial_depth: 0,
                };
            }
            self.total_bytes += size;
            let actual = git_oid(kind, &payload);
            let oid_ok = node
                .row
                .claimed_oid
                .as_ref()
                .map(|c| c == &actual)
                .unwrap_or(true);
            return EvalOutcome::Ok {
                kind: kind.name().to_string(),
                content: payload,
                actual_oid: actual,
                oid_ok,
                depth: 0,
                bytes: size,
                steps: Vec::new(),
            };
        }

        // ---- delta node ----
        let base_id: i64 = if delta.as_deref() == Some("ofs-delta") {
            match node.row.base_entry_id {
                Some(b) => b,
                None => {
                    return EvalOutcome::Error(ResolveError::OfsMissing(
                        node.row.base_offset.unwrap_or(-1) as u64,
                    ))
                }
            }
        } else {
            match &node.row.base_oid {
                Some(oid) => match self.choose_provider(oid) {
                    Ok(b) => b,
                    Err(e) => return EvalOutcome::Error(e.unwrap()),
                },
                None => {
                    return EvalOutcome::Error(ResolveError::MissingBase(
                        "ref-delta without base oid".into(),
                    ))
                }
            }
        };

        let depth_here = {
            // depth budget enforced from base depth + 1
            let base_depth_probe = match self.memo.get(&base_id) {
                Some(EvalOutcome::Ok { depth, .. }) => *depth + 1,
                _ => 1,
            };
            base_depth_probe
        };
        if depth_here > self.budget.max_depth {
            return EvalOutcome::Paused {
                reason: format!("delta depth {} exceeds {}", depth_here, self.budget.max_depth),
                partial_depth: depth_here.saturating_sub(1),
            };
        }

        let base_out = self.eval(base_id);
        let (base_kind, base_content, base_depth, base_oid, base_ok, prior_steps) = match &base_out {
            EvalOutcome::Ok {
                kind,
                content,
                depth,
                actual_oid,
                oid_ok,
                steps,
                ..
            } => (
                kind.clone(),
                content.clone(),
                *depth,
                actual_oid.clone(),
                *oid_ok,
                steps.clone(),
            ),
            other => return other.clone(),
        };

        // budget for producing this object from the base
        let cap = self
            .budget
            .per_object_bytes
            .min(self.budget.total_bytes.saturating_sub(self.total_bytes));
        let applied = match apply_delta(&base_content, &payload, cap as usize) {
            Ok(a) => a,
            Err(e) if e.starts_with("CAP:") => {
                return EvalOutcome::Paused {
                    reason: e,
                    partial_depth: base_depth + 1,
                }
            }
            Err(e) => {
                return EvalOutcome::Error(ResolveError::Entry(
                    crate::model::EntryError::BadDelta(e),
                ))
            }
        };

        let size = applied.out.len() as u64;
        self.total_bytes += size;

        let kind = match base_kind.as_str() {
            "blob" => Kind::Blob,
            "tree" => Kind::Tree,
            "commit" => Kind::Commit,
            "tag" => Kind::Tag,
            other => {
                return EvalOutcome::Error(ResolveError::Entry(
                    crate::model::EntryError::UnknownType(
                        other.parse::<u8>().unwrap_or(0),
                    ),
                ))
            }
        };
        let actual = git_oid(kind, &applied.out);
        let claimed_ok = node
            .row
            .claimed_oid
            .as_ref()
            .map(|c| c == &actual)
            .unwrap_or(true);
        let oid_ok = base_ok && claimed_ok;

        // Instruction range: byte range of opcodes within inflated delta.
        let (_, h1) = crate::git::read_size(&payload, 0).unwrap_or((0, 0));
        let (_, h2) = crate::git::read_size(&payload, h1).unwrap_or((0, 0));
        let instr_start = h1 + h2;
        let instr_end = payload.len();
        let instrs_json = serde_json::to_string(
            &applied
                .instrs
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "range": [i.range.0, i.range.1],
                        "kind": i.kind,
                        "detail": i.detail,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into());

        let step = StepRec {
            seq: base_depth + 1,
            kind: delta.clone().unwrap_or_default(),
            base_entry: Some(base_id),
            base_oid: Some(base_oid),
            instr_start,
            instr_end,
            in_len: base_content.len(),
            out_len: applied.out.len(),
            declared_result: applied.out.len() as u64,
            check: if claimed_ok {
                "ok".to_string()
            } else {
                format!("oid mismatch: actual {actual}")
            },
            instrs_json,
        };
        let mut steps = prior_steps;
        steps.push(step);

        EvalOutcome::Ok {
            kind: base_kind,
            content: applied.out,
            actual_oid: actual,
            oid_ok,
            depth: base_depth + 1,
            bytes: size,
            steps,
        }
    }

}

fn resolve_detail(e: &ResolveError) -> String {
    match e {
        ResolveError::MissingBase(o) => format!("base {o} not present in any source"),
        ResolveError::OfsMissing(o) => format!("ofs target {o} missing"),
        ResolveError::BaseError(c) => format!("base failed: {c}"),
        ResolveError::Cycle(v) => format!("cycle through entries {v:?}"),
        ResolveError::Entry(en) => en.detail(),
    }
}

/// Build the blocker chain for an error outcome by walking the DAG again with
/// tracking disabled (read-only provider/base lookups).
fn blocker_chain(eng: &Engine, id: i64) -> Vec<Blocker> {
    fn walk(eng: &Engine, id: i64, out: &mut Vec<Blocker>, seen: &mut HashSet<i64>) {
        if !seen.insert(id) {
            return;
        }
        let node = match eng.nodes.get(&id) {
            Some(n) => n,
            None => return,
        };
        if let Some(e) = Engine::parse_error_of(node) {
            out.push(Blocker {
                entry: id,
                code: e.code(),
                detail: resolve_detail(&e),
            });
            return;
        }
        match node.row.delta.as_deref() {
            Some("ofs-delta") => match node.row.base_entry_id {
                Some(b) => {
                    walk(eng, b, out, seen);
                }
                None => out.push(Blocker {
                    entry: id,
                    code: "ofs_missing".into(),
                    detail: format!(
                        "negative offset target {} outside pack",
                        node.row.base_offset.unwrap_or(-1)
                    ),
                }),
            },
            Some("ref-delta") => {
                if let Some(oid) = &node.row.base_oid {
                    match eng.choose_provider(oid) {
                        Ok(b) => walk(eng, b, out, seen),
                        Err(e) => {
                            let e = e.unwrap();
                            out.push(Blocker {
                                entry: id,
                                code: e.code(),
                                detail: resolve_detail(&e),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk(eng, id, &mut out, &mut seen);
    if out.is_empty() {
        out.push(Blocker {
            entry: id,
            code: "unknown".into(),
            detail: "unresolved".into(),
        });
    }
    out
}

impl<'a> Engine<'a> {
    /// Full or incremental resolution of `targets`. If `targets` is empty all
    /// entries are evaluated. Existing `ok` resolutions are reused unless they
    /// are in `force` (or their chosen ref base changed).
    pub fn resolve(
        &mut self,
        reason: &str,
        targets: Option<&BTreeSet<i64>>,
        budget: Budget,
    ) -> rusqlite::Result<RunReport> {
        self.budget = budget;
        self.load()?;
        let run_seq = self.store.next_run_seq()?;
        self.run_seq = run_seq;

        // Determine evaluation set + reuse set.
        let all_ids: BTreeSet<i64> = self.nodes.keys().copied().collect();
        let mut force: BTreeSet<i64> = match targets {
            Some(t) => t.clone(),
            None => all_ids.clone(),
        };
        // always force entries that are not currently ok
        let mut prev = self
            .store
            .db
            .prepare("SELECT entry_id,status FROM resolutions WHERE branch=?1")?;
        let prev_rows = prev
            .query_map(params![self.branch], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(prev);
        let prev_ok: HashSet<i64> = prev_rows
            .iter()
            .filter(|(_, s)| s == "ok")
            .map(|(i, _)| *i)
            .collect();
        for id in &all_ids {
            if !prev_ok.contains(id) {
                force.insert(*id);
            }
        }

        // Propagate force across dependents: any entry whose chosen provider
        // (ref) chain hits a forced node is itself recomputed.
        let mut rev: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for (id, n) in &self.nodes {
            if let Some(b) = n.row.base_entry_id {
                rev.entry(b).or_default().push(*id);
            }
            if let Some(oid) = &n.row.base_oid {
                if let Ok(b) = self.choose_provider(oid) {
                    rev.entry(b).or_default().push(*id);
                }
            }
        }
        let mut stack: Vec<i64> = force.iter().copied().collect();
        while let Some(x) = stack.pop() {
            if let Some(deps) = rev.get(&x) {
                for d in deps {
                    if force.insert(*d) {
                        stack.push(*d);
                    }
                }
            }
        }

        // Seed memo from reusable ok resolutions so forced deltas still get
        // correct bytes/bases without re-evaluating unrelated subgraphs.
        let reusable: HashSet<i64> = all_ids.difference(&force).copied().collect();
        for id in &reusable {
            if let Some(o) = self.load_ok_outcome(*id) {
                self.memo.insert(*id, o);
                self.reused += 1;
            }
        }

        let mut report = RunReport {
            run_seq,
            ..Default::default()
        };

        // Evaluate forced entries in stable id order.
        let ordered: Vec<i64> = force.iter().copied().collect();
        for id in ordered {
            let outcome = self.eval(id);
            self.persist(id, &outcome)?;
            match &outcome {
                EvalOutcome::Ok { bytes, .. } => report.ok += 1,
                EvalOutcome::Paused { .. } => report.paused += 1,
                EvalOutcome::Error(_) => report.error += 1,
            }
            let _ = bytes_count(&outcome);
        }
        report.total_bytes = self.total_bytes;
        report.reused = self.reused;

        // Blocker chains for every non-ok resolution in this branch.
        self.fill_blockers()?;

        self.store.insert_run(
            reason,
            &serde_json::to_string(&budget).unwrap_or_default(),
            self.total_bytes as i64,
            report.paused > 0,
        )?;
        Ok(report)
    }

    fn load_ok_outcome(&self, id: i64) -> Option<EvalOutcome> {
        let row = self
            .store
            .db
            .query_row(
                "SELECT status,kind,content_path,actual_oid,oid_ok,depth,steps
                 FROM resolutions WHERE branch=?1 AND entry_id=?2",
                params![self.branch, id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .ok()?;
        let (status, kind, content_path, actual_oid, oid_ok, depth, steps) = row;
        if status != "ok" {
            return None;
        }
        let path = content_path?;
        let content = self.store.read_content(&path).ok()?;
        Some(EvalOutcome::Ok {
            kind: kind?,
            content,
            actual_oid: actual_oid?,
            oid_ok: oid_ok == Some(1),
            depth: depth.unwrap_or(0) as u32,
            bytes: 0,
            steps: serde_json::from_str(&steps.unwrap_or_default()).unwrap_or_default(),
        })
    }

    fn persist(&self, id: i64, o: &EvalOutcome) -> rusqlite::Result<()> {
        match o {
            EvalOutcome::Ok {
                kind,
                content,
                actual_oid,
                oid_ok,
                depth,
                steps,
                ..
            } => {
                let rel = self
                    .store
                    .write_content(id, self.run_seq, content)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                self.store.db.execute(
                    "INSERT INTO resolutions(branch,entry_id,status,kind,content_path,content_len,
                        actual_oid,oid_ok,depth,bytes,error,blockers,steps,budget_json,run_seq,reused)
                     VALUES(?1,?2,'ok',?3,?4,?5,?6,?7,?8,?9,NULL,NULL,?10,?11,?12,0)
                     ON CONFLICT(branch,entry_id) DO UPDATE SET
                        status='ok',kind=excluded.kind,content_path=excluded.content_path,
                        content_len=excluded.content_len,actual_oid=excluded.actual_oid,
                        oid_ok=excluded.oid_ok,depth=excluded.depth,bytes=excluded.bytes,
                        error=NULL,blockers=NULL,steps=excluded.steps,
                        budget_json=excluded.budget_json,run_seq=excluded.run_seq,reused=0",
                    params![
                        self.branch,
                        id,
                        kind,
                        rel,
                        content.len() as i64,
                        actual_oid,
                        oid_ok,
                        depth,
                        content.len() as i64,
                        serde_json::to_string(steps).unwrap_or_default(),
                        serde_json::to_string(&self.budget).unwrap_or_default(),
                        self.run_seq,
                    ],
                )?;
            }
            EvalOutcome::Paused {
                reason,
                partial_depth,
            } => {
                self.store.db.execute(
                    "INSERT INTO resolutions(branch,entry_id,status,depth,error,budget_json,run_seq)
                     VALUES(?1,?2,'paused',?3,?4,?5,?6)
                     ON CONFLICT(branch,entry_id) DO UPDATE SET
                        status='paused',depth=excluded.depth,error=excluded.error,
                        content_path=NULL,actual_oid=NULL,oid_ok=NULL,blockers=NULL,
                        steps=NULL,budget_json=excluded.budget_json,run_seq=excluded.run_seq",
                    params![
                        self.branch,
                        id,
                        partial_depth,
                        reason,
                        serde_json::to_string(&self.budget).unwrap_or_default(),
                        self.run_seq
                    ],
                )?;
            }
            EvalOutcome::Error(e) => {
                let payload = serde_json::to_string(e).unwrap_or_default();
                self.store.db.execute(
                    "INSERT INTO resolutions(branch,entry_id,status,error,budget_json,run_seq)
                     VALUES(?1,?2,'error',?3,?4,?5)
                     ON CONFLICT(branch,entry_id) DO UPDATE SET
                        status='error',error=excluded.error,content_path=NULL,
                        actual_oid=NULL,oid_ok=NULL,steps=NULL,blockers=NULL,
                        budget_json=excluded.budget_json,run_seq=excluded.run_seq",
                    params![
                        self.branch,
                        id,
                        payload,
                        serde_json::to_string(&self.budget).unwrap_or_default(),
                        self.run_seq
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn fill_blockers(&self) -> rusqlite::Result<()> {
        let ids: Vec<i64> = self.nodes.keys().copied().collect();
        for id in ids {
            let status: Option<String> = self
                .store
                .db
                .query_row(
                    "SELECT status FROM resolutions WHERE branch=?1 AND entry_id=?2",
                    params![self.branch, id],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let chain = match status.as_deref() {
                Some("error") => blocker_chain(self, id),
                _ => continue,
            };
            let j = serde_json::to_string(&chain).unwrap_or_default();
            self.store.db.execute(
                "UPDATE resolutions SET blockers=?3 WHERE branch=?1 AND entry_id=?2",
                params![self.branch, id, j],
            )?;
        }
        Ok(())
    }
}

fn bytes_count(o: &EvalOutcome) -> u64 {
    match o {
        EvalOutcome::Ok { bytes, .. } => *bytes,
        _ => 0,
    }
}
