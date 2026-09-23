use crate::db::{Budget, ResolveSummary, Store};
use crate::git::{apply_delta, git_object_id, GitType};
use std::collections::HashSet;

struct Run<'a> {
    store: &'a Store,
    budget: Budget,
    used: usize,
    ticket: i64,
    touched: HashSet<String>,
    resolved_count: usize,
    blocked_count: usize,
    bad_count: usize,
    paused_count: usize,
}

#[derive(Debug, Clone)]
enum Outcome {
    Resolved { kind: GitType, payload: Vec<u8>, oid: String, depth: i64, input_len: i64, output_len: i64 },
    Blocked(String),
    Bad(String),
    Paused(String),
    Cycle,
}

pub fn resolve(store: &Store, budget: Budget, roots: Option<&[i64]>) -> Result<ResolveSummary, String> {
    let ticket = store.conn
        .query_row("SELECT COALESCE(MAX(ticket),0)+1 FROM budget_events", [], |row| row.get(0))
        .map_err(|err| err.to_string())?;
    let root_ids = match roots {
        Some(ids) => {
            store.prepare_resolution(ids)?;
            ids.to_vec()
        }
        None => {
            store.reset_all_unresolved()?;
            store.queued()?
        }
    };
    let mut run = Run {
        store,
        budget,
        used: 0,
        ticket,
        touched: HashSet::new(),
        resolved_count: 0,
        blocked_count: 0,
        bad_count: 0,
        paused_count: 0,
    };
    for id in root_ids {
        let candidate = run.store.object(id)?;
        if candidate.status == "resolved" {
            run.touched.insert(candidate.oid);
            continue;
        }
        let outcome = run.resolve_id(id, 0, &mut Vec::new());
        run.classify(id, outcome)?;
    }
    let mut touched = run.touched.into_iter().collect::<Vec<_>>();
    touched.sort();
    Ok(ResolveSummary {
        resolved: run.resolved_count,
        blocked: run.blocked_count,
        bad: run.bad_count,
        paused: run.paused_count,
        touched_oids: touched,
    })
}

impl<'a> Run<'a> {
    fn resolve_id(&mut self, id: i64, depth: usize, stack: &mut Vec<i64>) -> Outcome {
        let candidate = match self.store.object(id) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        self.touched.insert(candidate.oid.clone());
        if candidate.status == "resolved" {
            let payload = self.store.resolved_payload(id).map(|(_, value)| value).unwrap_or_default();
            return Outcome::Resolved {
                kind: GitType::parse(&candidate.type_name).unwrap_or(GitType::Blob),
                payload,
                oid: candidate.actual_oid.unwrap_or(candidate.oid),
                depth: candidate.depth,
                input_len: candidate.input_len,
                output_len: candidate.output_len,
            };
        }
        if stack.contains(&id) {
            let _ = self.store.add_error(id, "cycle", "delta chain forms a cycle", &format!("stack={stack:?}"));
            return Outcome::Cycle;
        }
        if depth >= self.budget.max_depth {
            let msg = format!("delta depth {depth} exceeds limit {}", self.budget.max_depth);
            let _ = self.store.add_error(id, "depth", &msg, "retry with a larger depth budget");
            return Outcome::Paused(msg);
        }
        stack.push(id);
        let edges = self.store.base_edges(id).unwrap_or_default();
        if let Some((base_oid, base_kind, base_offset)) = edges.first().cloned() {
            let base_candidate = match self.store.active_base(&base_oid) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    let msg = format!("missing external base {base_oid} for {base_kind} delta");
                    let evidence = format!("base_offset={base_offset:?} child={id}");
                    let _ = self.store.add_error(id, "missing_base", &msg, &evidence);
                    stack.pop();
                    return Outcome::Blocked(msg);
                }
                Err(err) => {
                    stack.pop();
                    return Outcome::Bad(err);
                }
            };
            let base_outcome = self.resolve_id(base_candidate.id, depth + 1, stack);
            let base = match base_outcome {
                Outcome::Resolved { kind, payload, oid, .. } => (kind, payload, oid, base_candidate.id),
                Outcome::Cycle => {
                    stack.pop();
                    return Outcome::Cycle;
                }
                Outcome::Blocked(msg) => {
                    stack.pop();
                    return Outcome::Blocked(format!("base blocked: {msg}"));
                }
                Outcome::Bad(msg) => {
                    stack.pop();
                    return Outcome::Bad(format!("bad base: {msg}"));
                }
                Outcome::Paused(msg) => {
                    stack.pop();
                    return Outcome::Paused(format!("base paused: {msg}"));
                }
            };
            let outcome = self.apply_delta_candidate(id, depth, base, base_kind);
            stack.pop();
            outcome
        } else {
            let outcome = self.resolve_plain(id);
            stack.pop();
            outcome
        }
    }

    fn resolve_plain(&mut self, id: i64) -> Outcome {
        let candidate = match self.store.object(id) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        let (raw, _, _, _) = match self.store.object_payloads(id) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        let Some(kind) = GitType::parse(&candidate.type_name) else {
            return Outcome::Bad(format!("plain candidate has non-object type {}", candidate.type_name));
        };
        if raw.len() as i64 != candidate.input_len {
            return Outcome::Bad(format!("stored raw length {} disagrees with input length {}", raw.len(), candidate.input_len));
        }
        if let Err(outcome) = self.charge(id, raw.len(), raw.len(), "plain object expansion") {
            return outcome;
        }
        let actual_oid = hex::encode(git_object_id(kind, &raw));
        let check_ok = actual_oid == candidate.oid || candidate.oid.starts_with("unknown:");
        Outcome::Resolved {
            kind,
            payload: raw,
            oid: actual_oid,
            depth: 0,
            input_len: raw.len() as i64,
            output_len: raw.len() as i64,
        }.with_id_check(id, candidate.oid, check_ok)
    }

    fn apply_delta_candidate(&mut self, id: i64, depth: usize, base: (GitType, Vec<u8>, String, i64), base_kind: String) -> Outcome {
        let (base_type, base_payload, base_oid, base_id) = base;
        let candidate = match self.store.object(id) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        let (_, delta, _, _) = match self.store.object_payloads(id) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        if delta.is_empty() {
            return Outcome::Bad(format!("{base_kind} delta payload is missing"));
        }
        let source_len = match crate::git::read_delta_size(&delta) {
            Ok((size, used)) if size as usize == base_payload.len() => used,
            Ok((size, _)) => return Outcome::Bad(format!("delta source length {size} does not equal base length {}", base_payload.len())),
            Err(err) => return Outcome::Bad(err),
        };
        let target_len = match crate::git::read_delta_size(&delta[source_len..]) {
            Ok((size, used)) => (size as usize, source_len + used),
            Err(err) => return Outcome::Bad(err),
        };
        if let Err(outcome) = self.charge(id, base_payload.len(), target_len.0, "delta output reservation") {
            return outcome;
        }
        let (output, ops) = match apply_delta(&base_payload, &delta) {
            Ok(value) => value,
            Err(err) => return Outcome::Bad(err),
        };
        let _ = self.store.clear_candidate_steps(id);
        let mut all_checks = true;
        for (index, op) in ops.iter().enumerate() {
            let check_ok = match op.opcode.as_str() {
                "copy" => op.base_offset.zip(op.base_len).map(|(offset, len)| offset + len <= base_payload.len()).unwrap_or(false) && op.output_after <= output.len(),
                "insert" => op.insert_len.map(|len| op.range_start + 1 + len <= op.range_end).unwrap_or(false) && op.output_after <= output.len(),
                _ => false,
            };
            all_checks &= check_ok;
            let _ = self.store.insert_delta_step(
                id, depth as i64, Some(base_id), Some(&base_oid), index as i64, &op.opcode,
                op.range_start as i64, op.range_end as i64,
                op.base_offset.map(|value| value as i64), op.base_len.map(|value| value as i64),
                op.insert_len.map(|value| value as i64), base_payload.len() as i64,
                op.output_before as i64, op.output_after as i64, check_ok,
            );
        }
        if !all_checks {
            return Outcome::Bad("one or more delta instructions failed range checks".into());
        }
        let actual_oid = hex::encode(git_object_id(base_type, &output));
        let check_ok = actual_oid == candidate.oid || candidate.oid.starts_with("unknown:");
        Outcome::Resolved {
            kind: base_type,
            payload: output,
            oid: actual_oid,
            depth: depth as i64 + 1,
            input_len: delta.len() as i64,
            output_len: target_len.0 as i64,
        }.with_id_check(id, candidate.oid, check_ok)
    }

    fn charge(&mut self, id: i64, input_len: usize, output_len: usize, label: &str) -> Result<(), Outcome> {
        let total_budget = self.budget.total_bytes;
        let single_limit = ((total_budget as u128 * self.budget.single_ratio_num as u128) / self.budget.single_ratio_den as u128) as usize;
        if output_len > single_limit {
            let msg = format!("single object requests {output_len} bytes, limit is {single_limit} ({}/{})", self.budget.single_ratio_num, self.budget.single_ratio_den);
            let _ = self.record_budget(id, 0, "single_object_limit", &msg);
            return Err(Outcome::Paused(msg));
        }
        if self.used.saturating_add(output_len) > total_budget {
            let msg = format!("{label}: total expansion would be {}, limit is {total_budget}", self.used.saturating_add(output_len));
            let _ = self.record_budget(id, 0, "total_budget", &msg);
            return Err(Outcome::Paused(msg));
        }
        self.used += output_len;
        let _ = self.record_budget(id, output_len, "charge", &format!("{label}; input={input_len}"));
        Ok(())
    }

    fn record_budget(&self, id: i64, bytes: usize, kind: &str, message: &str) -> Result<(), String> {
        self.store.conn.execute(
            "INSERT INTO budget_events(ticket,candidate_id,kind,charged_bytes,total_after,message) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![self.ticket, id, kind, bytes as i64, self.used as i64, message],
        ).map(|_| ()).map_err(|err| err.to_string())
    }

    fn classify(&mut self, id: i64, outcome: Outcome) -> Result<(), String> {
        match outcome {
            Outcome::Resolved { kind, payload, oid, depth, input_len, output_len } => {
                let candidate = self.store.object(id)?;
                let id_ok = oid == candidate.oid || candidate.oid.starts_with("unknown:");
                if candidate.oid.starts_with("unknown:") {
                    self.store.update_oid(id, &oid)?;
                    self.touched.insert(oid);
                }
                if !id_ok {
                    let msg = format!("recomputed id {oid} does not match indexed/supplied id {}", candidate.oid);
                    self.store.add_error(id, "oid_mismatch", &msg, "object isolated")?;
                    self.store.set_failure(id, "bad", None)?;
                    self.bad_count += 1;
                } else {
                    self.store.set_success(id, kind.name(), &payload, &oid, true, depth, input_len, output_len)?;
                    self.resolved_count += 1;
                }
            }
            Outcome::Blocked(message) => {
                self.store.set_failure(id, "blocked", None)?;
                self.blocked_count += 1;
                let _ = self.store.add_error(id, "blocked", &message, "retry after supplying base");
            }
            Outcome::Bad(message) => {
                self.store.set_failure(id, "bad", None)?;
                self.bad_count += 1;
                let _ = self.store.add_error(id, "bad", &message, "object isolated");
            }
            Outcome::Paused(message) => {
                self.store.set_failure(id, "paused", Some(self.ticket))?;
                self.paused_count += 1;
                let _ = self.store.add_error(id, "budget_paused", &message, "retry with a larger budget; no partial object was accepted");
            }
            Outcome::Cycle => {
                self.store.set_failure(id, "bad", None)?;
                self.bad_count += 1;
            }
        }
        Ok(())
    }
}

impl Outcome {
    fn with_id_check(self, id: i64, expected_oid: String, check_ok: bool) -> Outcome {
        if !check_ok {
            Outcome::Bad(format!("recomputed object id for candidate {id} does not match {expected_oid}"))
        } else {
            self
        }
    }
}
