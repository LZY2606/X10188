use rusqlite::types::Value;
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::delta::{apply_delta, object_frame, read_size_encoding, ObjectType};
use crate::error::{BudgetKind, Error, Result};
use crate::hash::sha1_hex;
use crate::importer::import_bytes;
use crate::inflate::inflate_limited;
use crate::store::Store;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_single_ratio: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_total_bytes: 16 * 1024 * 1024,
            max_single_ratio: 80,
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    id: String,
    source_id: String,
    kind: String,
    offset: Option<i64>,
    header_end: Option<i64>,
    data_end: Option<i64>,
    object_type: Option<String>,
    declared_size: Option<i64>,
    expected_oid: Option<String>,
    actual_oid: Option<String>,
    base_offset: Option<i64>,
    base_oid: Option<String>,
    parse_error: Option<String>,
    dirty: bool,
}

#[derive(Debug, Clone)]
struct Materialized {
    id: i64,
    base_candidate_id: Option<String>,
    object_type: String,
    actual_oid: String,
    output_len: i64,
    body: Vec<u8>,
    depth: i64,
}

#[derive(Debug, Clone)]
struct Outcome {
    status: String,
    object_type: Option<String>,
    actual_oid: Option<String>,
    output_len: Option<i64>,
    depth: Option<i64>,
    error: Option<String>,
    chain: Vec<String>,
    materialization_id: Option<i64>,
}

pub struct Analyzer;

impl Analyzer {
    pub fn run_default(store: &Store, budget: Budget) -> Result<String> {
        let analysis_id = {
            let conn = store.conn.lock().expect("database lock");
            let existing: Option<String> = conn
                .query_row("SELECT id FROM analyses WHERE label='default' ORDER BY rowid DESC LIMIT 1", [], |r| r.get(0))
                .optional()?;
            if let Some(id) = existing {
                id
            } else {
                let id = "analysis-default".to_string();
                conn.execute(
                    "INSERT INTO analyses (id, label, budget_depth, budget_bytes, single_object_ratio, status)
                     VALUES (?1, 'default', ?2, ?3, ?4, 'active')",
                    params![id, budget.max_depth as i64, budget.max_total_bytes as i64, budget.max_single_ratio as i64],
                )?;
                id
            }
        };
        Self::run(store, &analysis_id, budget)
    }

    pub fn run(store: &Store, analysis_id: &str, budget: Budget) -> Result<String> {
        let mut conn = store.conn.lock().expect("database lock");
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE analyses SET budget_depth=?2, budget_bytes=?3, single_object_ratio=?4,
             status='active', updated_at=datetime('now') WHERE id=?1",
            params![analysis_id, budget.max_depth as i64, budget.max_total_bytes as i64, budget.max_single_ratio as i64],
        )?;
        let roots = dirty_root_candidates(&tx)?;
        let mut root_ids: Vec<String> = roots.into_iter().map(|c| c.id).collect();
        root_ids.sort();
        for cid in root_ids {
            Self::retry_candidate(&tx, store, analysis_id, &cid, budget, &mut Vec::new())?;
        }
        finalize_analysis(&tx, analysis_id, budget)?;
        tx.execute("UPDATE candidates SET dirty=0", [])?;
        tx.commit()?;
        Ok(analysis_id.to_string())
    }

    pub fn pin_and_run(store: &Store, branch_label: &str, target_oid: &str, candidate_id: &str, budget: Budget) -> Result<String> {
        let analysis_id = format!("analysis-{}", sha1_hex(format!("{branch_label}:{target_oid}:{candidate_id}")));
        {
            let mut conn = store.conn.lock().expect("database lock");
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT OR IGNORE INTO analyses (id, label, budget_depth, budget_bytes, single_object_ratio, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
                params![analysis_id, branch_label, budget.max_depth as i64, budget.max_total_bytes as i64, budget.max_single_ratio as i64],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO pins (analysis_id, target_oid, candidate_id, label)
                 VALUES (?1, ?2, ?3, ?4)",
                params![analysis_id, target_oid, candidate_id, branch_label],
            )?;
            tx.commit()?;
        }
        Self::run(store, &analysis_id, budget)
    }

    fn retry_candidate(
        tx: &Transaction,
        store: &Store,
        analysis_id: &str,
        candidate_id: &str,
        budget: Budget,
        path: &mut Vec<String>,
    ) -> Result<Outcome> {
        if let Some(outcome) = load_outcome(tx, analysis_id, candidate_id)? {
            if outcome.status != "paused" && !is_candidate_dirty(tx, candidate_id)? {
                return Ok(outcome);
            }
        }
        tx.execute(
            "INSERT INTO analysis_results (analysis_id, candidate_id, status, attempt_count)
             VALUES (?1, ?2, 'running', 1)
             ON CONFLICT(analysis_id, candidate_id)
             DO UPDATE SET attempt_count=attempt_count+1, status='running', error=NULL, blocked_chain=NULL",
            params![analysis_id, candidate_id],
        )?;
        if path.iter().any(|id| id == candidate_id) {
            let mut chain = path.clone();
            chain.push(candidate_id.to_string());
            return Ok(fail_result(tx, analysis_id, candidate_id, "delta cycle", "cycle", chain)?);
        }
        path.push(candidate_id.to_string());
        let candidate = load_candidate(tx, candidate_id)?;
        let outcome = materialize(tx, store, analysis_id, &candidate, budget, path, 0)?;
        path.pop();
        persist_outcome(tx, analysis_id, &candidate.id, &outcome)?;
        Ok(outcome)
    }
}

trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>>;
}
impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn dirty_root_candidates(tx: &Transaction) -> Result<Vec<Candidate>> {
    let mut stmt = tx.prepare(
        "SELECT id, source_id, kind, offset, header_end, data_end, object_type, declared_size,
                expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty
         FROM candidates WHERE dirty=1 OR id NOT IN (
           SELECT candidate_id FROM analysis_results WHERE status IN ('resolved','blocked','corrupt','cycle')
         ) ORDER BY id",
    )?;
    let rows = stmt.query_map([], row_to_candidate)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn row_to_candidate(row: &rusqlite::Row<'_>) -> rusqlite::Result<Candidate> {
    Ok(Candidate {
        id: row.get(0)?,
        source_id: row.get(1)?,
        kind: row.get(2)?,
        offset: row.get(3)?,
        header_end: row.get(4)?,
        data_end: row.get(5)?,
        object_type: row.get(6)?,
        declared_size: row.get(7)?,
        expected_oid: row.get(8)?,
        actual_oid: row.get(9)?,
        base_offset: row.get(10)?,
        base_oid: row.get(11)?,
        parse_error: row.get(12)?,
        dirty: row.get::<_, i64>(13)? != 0,
    })
}

fn load_candidate(tx: &Transaction, id: &str) -> Result<Candidate> {
    tx.query_row(
        "SELECT id, source_id, kind, offset, header_end, data_end, object_type, declared_size,
                expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty
         FROM candidates WHERE id=?1",
        params![id],
        row_to_candidate,
    ).map_err(Into::into)
}

fn is_candidate_dirty(tx: &Transaction, id: &str) -> Result<bool> {
    Ok(tx.query_row("SELECT dirty FROM candidates WHERE id=?1", params![id], |r| r.get::<_, i64>(0))? != 0)
}

fn load_outcome(tx: &Transaction, analysis_id: &str, candidate_id: &str) -> Result<Option<Outcome>> {
    tx.query_row(
        "SELECT status, object_type, actual_oid, output_len, depth, error, blocked_chain, materialization_id
         FROM analysis_results WHERE analysis_id=?1 AND candidate_id=?2",
        params![analysis_id, candidate_id],
        |r| {
            let chain_text: Option<String> = r.get(6)?;
            Ok(Outcome {
                status: r.get(0)?,
                object_type: r.get(1)?,
                actual_oid: r.get(2)?,
                output_len: r.get(3)?,
                depth: r.get(4)?,
                error: r.get(5)?,
                chain: chain_text.map(|v| v.split('\n').map(str::to_string).collect()).unwrap_or_default(),
                materialization_id: r.get(7)?,
            })
        },
    ).optional()
}

fn fail_result(
    tx: &Transaction,
    analysis_id: &str,
    candidate_id: &str,
    error: &str,
    status: &str,
    chain: Vec<String>,
) -> Result<Outcome> {
    let outcome = Outcome {
        status: status.to_string(),
        object_type: None,
        actual_oid: None,
        output_len: None,
        depth: None,
        error: Some(error.to_string()),
        chain,
        materialization_id: None,
    };
    persist_outcome(tx, analysis_id, candidate_id, &outcome)?;
    Ok(outcome)
}

fn persist_outcome(tx: &Transaction, analysis_id: &str, candidate_id: &str, outcome: &Outcome) -> Result<()> {
    let chain = outcome.chain.join("\n");
    tx.execute(
        "INSERT INTO analysis_results
         (analysis_id, candidate_id, status, object_type, actual_oid, output_len, depth, error, blocked_chain, materialization_id)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(analysis_id, candidate_id) DO UPDATE SET
           status=excluded.status, object_type=excluded.object_type, actual_oid=excluded.actual_oid,
           output_len=excluded.output_len, depth=excluded.depth, error=excluded.error,
           blocked_chain=excluded.blocked_chain, materialization_id=excluded.materialization_id",
        params![
            analysis_id, candidate_id, outcome.status, outcome.object_type, outcome.actual_oid,
            outcome.output_len, outcome.depth, outcome.error, chain, outcome.materialization_id
        ],
    )?;
    Ok(())
}

fn materialize(
    tx: &Transaction,
    store: &Store,
    analysis_id: &str,
    candidate: &Candidate,
    budget: Budget,
    path: &mut Vec<String>,
    depth: u32,
) -> Result<Outcome> {
    let mut chain = path.clone();
    chain.push(candidate.id.clone());
    if let Some(error) = &candidate.parse_error {
        return Ok(Outcome {
            status: "corrupt".into(), object_type: None, actual_oid: None, output_len: None,
            depth: None, error: Some(error.clone()), chain, materialization_id: None,
        });
    }
    let object_type = match candidate.object_type.as_deref() {
        Some("delta") => {
            let base = choose_base(tx, analysis_id, candidate)?;
            return materialize_delta(tx, store, analysis_id, candidate, base, budget, path, depth, chain);
        }
        Some(v) => ObjectType::named(v).ok_or_else(|| Error::Corrupt(format!("unknown type {v}")))?,
        None => return Ok(corrupt("missing object type", chain)),
    };
    if depth > budget.max_depth {
        return Ok(paused(BudgetKind::Depth, chain));
    }
    let body = read_plain_body(store, tx, candidate)?;
    let output_len = body.len() as u64;
    if let Err(kind) = charge_output(tx, analysis_id, candidate, output_len, budget)? {
        return Ok(paused(kind, chain));
    }
    let frame = object_frame(object_type.git_name(), &body);
    let actual_oid = sha1_hex(&frame);
    verify_plain(tx, analysis_id, candidate, object_type, actual_oid, body, chain)
}

fn corrupt(error: &str, chain: Vec<String>) -> Outcome {
    Outcome {
        status: "corrupt".into(), object_type: None, actual_oid: None, output_len: None,
        depth: None, error: Some(error.into()), chain, materialization_id: None,
    }
}

fn paused(kind: BudgetKind, chain: Vec<String>) -> Outcome {
    Outcome {
        status: "paused".into(), object_type: None, actual_oid: None, output_len: None,
        depth: None, error: Some(format!("{kind} budget exhausted")), chain, materialization_id: None,
    }
}

fn read_plain_body(store: &Store, tx: &Transaction, candidate: &Candidate) -> Result<Vec<u8>> {
    if candidate.kind == "loose" {
        let relative = source_relative(tx, &candidate.source_id)?;
        let parsed = crate::loose::parse_loose_path(&store.config.data_dir.join(relative))?;
        return Ok(parsed.body);
    }
    let relative = source_relative(tx, &candidate.source_id)?;
    let data = std::fs::read(store.config.data_dir.join(relative))?;
    let start = candidate.header_end.ok_or_else(|| Error::Corrupt("missing pack data offset".into()))? as usize;
    let declared = candidate.declared_size.unwrap_or(0) as u64;
    let (body, _, warning) = inflate_limited(&data[start..], declared, 256 * 1024 * 1024)?;
    if let Some(warning) = warning {
        return Err(Error::Corrupt(warning));
    }
    Ok(body)
}

fn source_relative(tx: &Transaction, source_id: &str) -> Result<String> {
    Ok(tx.query_row(
        "SELECT disk_path FROM sources WHERE id=?1",
        params![source_id],
        |r| r.get(0),
    )?)
}

fn charge(
    tx: &Transaction,
    analysis_id: &str,
    candidate_id: &str,
    amount: u64,
    note: &str,
    budget: Budget,
) -> std::result::Result<(), BudgetKind> {
    tx.execute(
        "INSERT OR IGNORE INTO analysis_expenses (analysis_id, candidate_id, amount, note)
         VALUES (?1, ?2, ?3, ?4)",
        params![analysis_id, candidate_id, amount as i64, note],
    ).map_err(|_| BudgetKind::Bytes)?;
    let used: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM analysis_expenses WHERE analysis_id=?1",
            params![analysis_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if used as u64 > budget.max_total_bytes {
        Err(BudgetKind::Bytes)
    } else {
        Ok(())
    }
}

fn charge_output(
    tx: &Transaction,
    analysis_id: &str,
    candidate: &Candidate,
    amount: u64,
    budget: Budget,
) -> std::result::Result<(), BudgetKind> {
    let ratio_allowed = ((budget.max_total_bytes as u128) * (budget.max_single_ratio as u128)) / 100;
    if (amount as u128) > ratio_allowed {
        return Err(BudgetKind::Ratio);
    }
    charge(tx, analysis_id, &candidate.id, amount, "output", budget)
}

fn choose_base(tx: &Transaction, analysis_id: &str, candidate: &Candidate) -> Result<Option<Candidate>> {
    if let Some(offset) = candidate.base_offset {
        return tx.query_row(
            "SELECT id, source_id, kind, offset, header_end, data_end, object_type, declared_size,
                    expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty
             FROM candidates WHERE id <> ?3 AND source_id=?1 AND offset=?2",
            params![candidate.source_id, offset, candidate.id],
            row_to_candidate,
        ).optional();
    }
    let base_oid = match &candidate.base_oid {
        Some(oid) => oid.clone(),
        None => return Ok(None),
    };
    let pinned: Option<String> = tx
        .query_row(
            "SELECT candidate_id FROM pins WHERE analysis_id=?1 AND target_oid=?2",
            params![analysis_id, base_oid],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(cid) = pinned {
        return load_candidate(tx, &cid).map(Some);
    }
    tx.query_row(
        "SELECT id, source_id, kind, offset, header_end, data_end, object_type, declared_size,
                expected_oid, actual_oid, base_offset, base_oid, parse_error, dirty
         FROM candidates
         WHERE id <> ?2 AND (actual_oid=?1 OR expected_oid=?1)
         ORDER BY CASE WHEN parse_error IS NULL THEN 0 ELSE 1 END, id
         LIMIT 1",
        params![base_oid, candidate.id],
        row_to_candidate,
    ).optional()
}

fn materialize_delta(
    tx: &Transaction,
    store: &Store,
    analysis_id: &str,
    candidate: &Candidate,
    base: Option<Candidate>,
    budget: Budget,
    path: &mut Vec<String>,
    depth: u32,
    chain: Vec<String>,
) -> Result<Outcome> {
    let depth = depth + 1;
    if depth > budget.max_depth {
        record_delta_step(tx, analysis_id, candidate, None, None, None, 0, 0, "[]", "budget_depth", None)?;
        return Ok(paused(BudgetKind::Depth, chain));
    }
    let base = match base {
        Some(base) => base,
        None => {
            let missing = candidate.base_oid.clone()
                .map(|oid| format!("missing:{oid}"))
                .or_else(|| candidate.base_offset.map(|off| format!("missing-offset:{off}")))
                .unwrap_or_else(|| "missing-base".into());
            let mut chain = chain;
            chain.push(missing);
            record_delta_step(tx, analysis_id, candidate, None, None, None, 0, 0, "[]", "missing_base", None)?;
            return Ok(Outcome {
                status: "blocked".into(), object_type: None, actual_oid: None, output_len: None,
                depth: Some(depth as i64), error: Some("external base is unavailable".into()),
                chain, materialization_id: None,
            });
        }
    };
    let base_outcome = Analyzer::retry_candidate(tx, store, analysis_id, &base.id, budget, path)?;
    if base_outcome.status != "resolved" {
        let mut chain = base_outcome.chain;
        if chain.last().map(String::as_str) != Some(candidate.id.as_str()) {
            chain.insert(0, candidate.id.clone());
        }
        record_delta_step(
            tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(), None,
            base_outcome.output_len.unwrap_or(0), 0, "[]",
            &format!("base_{}", base_outcome.status), None,
        )?;
        return Ok(Outcome {
            status: if base_outcome.status == "paused" { "paused" } else { "blocked" }.into(),
            object_type: None, actual_oid: None, output_len: None,
            depth: Some(depth as i64), error: base_outcome.error, chain, materialization_id: None,
        });
    }
    let cache_key = format!("{}->{}", candidate.id, base.id);
    if let Some(found) = load_materialized(tx, &cache_key)? {
        let raw_delta = read_delta_bytes(store, tx, candidate)?;
        let ranges = match load_body(tx, base_outcome.materialization_id.unwrap_or(0)) {
            Ok(base_body) => apply_delta(&base_body, &raw_delta).ok().map(|v| ranges_json(&v.instructions)).unwrap_or_else(|| "[]".into()),
            Err(_) => "[]".into(),
        };
        record_delta_step(
            tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
            Some(found.object_type.as_str()), found.body.len() as i64, found.output_len,
            &ranges, "cached_ok", Some(&found.actual_oid),
        )?;
        return Ok(Outcome {
            status: "resolved".into(), object_type: Some(found.object_type),
            actual_oid: Some(found.actual_oid), output_len: Some(found.output_len),
            depth: Some(depth as i64), error: None, chain, materialization_id: Some(found.id),
        });
    }

    let raw_delta = read_delta_bytes(store, tx, candidate)?;
    if charge(tx, analysis_id, &candidate.id, raw_delta.len() as u64, "delta_raw", budget).is_err() {
        record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                          Some("delta"), base_outcome.output_len.unwrap_or(0), 0, "[]", "budget_bytes", None)?;
        return Ok(paused(BudgetKind::Bytes, chain));
    }
    let (source_size, header_pos) = read_size_encoding(&raw_delta, 0)?;
    let (target_size, instruction_start) = read_size_encoding(&raw_delta, header_pos)?;
    if source_size != base_outcome.output_len.unwrap_or(0) as u64 {
        record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                          Some("delta"), source_size as i64, 0, "[]", "source_size_mismatch", None)?;
        return Ok(corrupt("delta source size does not match reconstructed base", chain));
    }
    if charge_output(tx, analysis_id, candidate, target_size, budget).is_err() {
        let kind = if (target_size as u128) >
            ((budget.max_total_bytes as u128) * budget.max_single_ratio as u128 / 100) {
            BudgetKind::Ratio
        } else {
            BudgetKind::Bytes
        };
        record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                          Some("delta"), source_size as i64, target_size as i64, "[]",
                          if kind == BudgetKind::Ratio { "budget_ratio" } else { "budget_bytes" }, None)?;
        return Ok(paused(kind, chain));
    }
    let base_body = load_body(tx, base_outcome.materialization_id.unwrap_or(0))?;
    let applied = match apply_delta(&base_body, &raw_delta) {
        Ok(v) => v,
        Err(error) => {
            let ranges = "[]";
            record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                              Some("delta"), base_body.len() as i64, 0, ranges, "instruction_error", None)?;
            return Ok(corrupt(&error.to_string(), chain));
        }
    };
    let object_type = ObjectType::named(base_outcome.object_type.as_deref().unwrap_or("delta"))
        .unwrap_or(ObjectType::Blob);
    let actual_oid = sha1_hex(&object_frame(object_type.git_name(), &applied.output));
    if let Some(expected) = &candidate.expected_oid {
        if expected != &actual_oid {
            record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                              Some(object_type.git_name()), base_body.len() as i64,
                              applied.output.len() as i64, &ranges_json(&applied.instructions),
                              "oid_mismatch", Some(&actual_oid))?;
            return Ok(corrupt(&format!("recomputed oid {actual_oid} differs from expected {expected}"), chain));
        }
    }
    let mat = store_delta(tx, analysis_id, candidate, &base, object_type, &actual_oid, applied.output, depth as i64, &cache_key)?;
    record_delta_step(tx, analysis_id, candidate, Some(&base), base_outcome.actual_oid.as_deref(),
                      Some(object_type.git_name()), base_body.len() as i64, mat.1 as i64,
                      &ranges_json(&applied.instructions), "ok", Some(&actual_oid))?;
    Ok(Outcome {
        status: "resolved".into(), object_type: Some(object_type.git_name().to_string()),
        actual_oid: Some(actual_oid), output_len: Some(mat.1 as i64),
        depth: Some(depth as i64), error: None, chain, materialization_id: Some(mat.0),
    })
}

fn read_delta_bytes(store: &Store, tx: &Transaction, candidate: &Candidate) -> Result<Vec<u8>> {
    let relative = source_relative(tx, &candidate.source_id)?;
    let data = std::fs::read(store.config.data_dir.join(relative))?;
    let start = candidate
        .header_end
        .ok_or_else(|| Error::Corrupt("missing pack header end".into()))? as usize;
    let declared = candidate.declared_size.unwrap_or(0) as u64;
    let (body, _, warning) = inflate_limited(&data[start..], declared, 256 * 1024 * 1024)?;
    if let Some(warning) = warning {
        return Err(Error::Corrupt(warning));
    }
    let (source_size, hp) = read_size_encoding(&body, 0)?;
    let (target_size, _) = read_size_encoding(&body, hp)?;
    tx.execute(
        "UPDATE candidates SET delta_source_size=?2, delta_target_size=?3 WHERE id=?1",
        params![candidate.id, source_size as i64, target_size as i64],
    )?;
    Ok(body)
}

fn load_materialized(tx: &Transaction, cache_key: &str) -> Result<Option<Materialized>> {
    tx.query_row(
        "SELECT id, base_candidate_id, object_type, actual_oid, output_len, body, depth
         FROM materializations WHERE cache_key=?1",
        params![cache_key],
        |r| {
            Ok(Materialized {
                id: r.get(0)?,
                base_candidate_id: r.get(1)?,
                object_type: r.get(2)?,
                actual_oid: r.get(3)?,
                output_len: r.get(4)?,
                body: r.get(5)?,
                depth: r.get(6)?,
            })
        },
    ).optional()
}

fn load_body(tx: &Transaction, materialization_id: i64) -> Result<Vec<u8>> {
    Ok(tx.query_row(
        "SELECT body FROM materializations WHERE id=?1",
        params![materialization_id],
        |r| r.get::<_, Vec<u8>>(0),
    )?)
}

fn store_plain(
    tx: &Transaction,
    analysis_id: &str,
    candidate: &Candidate,
    base_candidate_id: &str,
    object_type: ObjectType,
    actual_oid: &str,
    body: Vec<u8>,
    depth: i64,
) -> Result<i64> {
    let output_len = body.len() as i64;
    tx.execute(
        "INSERT OR IGNORE INTO materializations
         (candidate_id, base_candidate_id, object_type, actual_oid, output_len, body, depth, created_analysis, cache_key)
         VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![candidate.id, object_type.git_name(), actual_oid, output_len, body, depth,
                analysis_id, format!("{}:{}", candidate.id, base_candidate_id)],
    )?;
    tx.execute("UPDATE candidates SET actual_oid=?2, object_type=?3, actual_size=?4 WHERE id=?1",
               params![candidate.id, actual_oid, object_type.git_name(), output_len])?;
    Ok(tx.last_insert_rowid())
}

fn store_delta(
    tx: &Transaction,
    analysis_id: &str,
    candidate: &Candidate,
    base: &Candidate,
    object_type: ObjectType,
    actual_oid: &str,
    body: Vec<u8>,
    depth: i64,
    cache_key: &str,
) -> Result<(i64, usize)> {
    let output_len = body.len();
    tx.execute(
        "INSERT OR IGNORE INTO materializations
         (candidate_id, base_candidate_id, object_type, actual_oid, output_len, body, depth, created_analysis, cache_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![candidate.id, base.id, object_type.git_name(), actual_oid, output_len as i64,
                body, depth, analysis_id, cache_key],
    )?;
    let id = tx.query_row(
        "SELECT id FROM materializations WHERE cache_key=?1",
        params![cache_key],
        |r| r.get(0),
    )?;
    tx.execute("UPDATE candidates SET actual_oid=?2, object_type=?3, actual_size=?4 WHERE id=?1",
               params![candidate.id, actual_oid, object_type.git_name(), output_len as i64])?;
    Ok((id, output_len))
}

fn verify_plain(
    tx: &Transaction,
    analysis_id: &str,
    candidate: &Candidate,
    object_type: ObjectType,
    actual_oid: String,
    body: Vec<u8>,
    chain: Vec<String>,
) -> Result<Outcome> {
    if let Some(expected) = &candidate.expected_oid {
        if expected != &actual_oid {
            return Ok(corrupt(
                &format!("recomputed oid {actual_oid} differs from expected {expected}"),
                chain,
            ));
        }
    }
    let output_len = body.len() as i64;
    let id = store_plain(tx, analysis_id, candidate, "", object_type, &actual_oid, body, 0)?;
    Ok(Outcome {
        status: "resolved".into(),
        object_type: Some(object_type.git_name().to_string()),
        actual_oid: Some(actual_oid),
        output_len: Some(output_len),
        depth: Some(0),
        error: None,
        chain,
        materialization_id: Some(id),
    })
}

fn ranges_json(instructions: &[crate::delta::DeltaInstruction]) -> String {
    let values: Vec<serde_json::Value> = instructions
        .iter()
        .map(|instruction| serde_json::json!({
            "start": instruction.start,
            "end": instruction.end,
            "kind": instruction.kind,
            "offset": instruction.offset,
            "length": instruction.length,
        }))
        .collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

#[allow(clippy::too_many_arguments)]
fn record_delta_step(
    tx: &Transaction,
    analysis_id: &str,
    candidate: &Candidate,
    base: Option<&Candidate>,
    base_oid: Option<&str>,
    object_type: Option<&str>,
    input_len: i64,
    output_len: i64,
    instruction_ranges: &str,
    check_status: &str,
    actual_oid: Option<&str>,
) -> Result<()> {
    let parsed: Vec<Value> = serde_json::from_str(instruction_ranges).unwrap_or_default();
    let first = parsed.first().and_then(|v| v.get("start")).and_then(|v| v.as_i64());
    let last = parsed.last().and_then(|v| v.get("end")).and_then(|v| v.as_i64());
    tx.execute("DELETE FROM delta_steps WHERE analysis_id=?1 AND candidate_id=?2",
               params![analysis_id, candidate.id])?;
    tx.execute(
        "INSERT INTO delta_steps
         (analysis_id, candidate_id, ordinal, base_candidate_id, base_oid, input_len, output_len,
          instruction_start, instruction_end, instruction_ranges, check_status, expected_oid, actual_oid, error)
         VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            analysis_id, candidate.id, depth_ordinal(tx, analysis_id, candidate),
            base.map(|b| b.id.clone()), base_oid, input_len, output_len,
            first.unwrap_or(0), last.unwrap_or(0), instruction_ranges, check_status,
            candidate.expected_oid, actual_oid,
            if check_status == "ok" || check_status == "cached_ok" { None } else { Some(check_status) }
        ],
    )?;
    let _ = object_type;
    Ok(())
}

fn depth_ordinal(tx: &Transaction, analysis_id: &str, candidate: &Candidate) -> i64 {
    let mut current = candidate.id.clone();
    let mut depth = 0;
    for _ in 0..64 {
        let parent: Option<String> = tx
            .query_row(
                "SELECT base_candidate_id FROM delta_steps
                 WHERE analysis_id=?1 AND candidate_id=?2 ORDER BY id DESC LIMIT 1",
                params![analysis_id, current],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten();
        match parent {
            Some(parent_id) => {
                current = parent_id;
                depth += 1;
            }
            None => break,
        }
    }
    depth
}

fn finalize_analysis(tx: &Transaction, analysis_id: &str, _budget: Budget) -> Result<()> {
    let paused = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM analysis_results WHERE analysis_id=?1 AND status='paused')",
        params![analysis_id],
        |r| r.get::<_, i64>(0),
    )? != 0;
    let status = if paused { "paused" } else { "complete" };
    tx.execute(
        "UPDATE analyses SET status=?2, updated_at=datetime('now') WHERE id=?1",
        params![analysis_id, status],
    )?;
    Ok(())
}

pub fn import_and_analyze(store: &Store, name: &str, data: Vec<u8>, budget: Budget) -> Result<String> {
    import_bytes(store, name, data)?;
    Analyzer::run_default(store, budget)
}

#[allow(dead_code)]
fn keep_map(_map: BTreeMap<String, String>, _set: BTreeSet<String>) {}
