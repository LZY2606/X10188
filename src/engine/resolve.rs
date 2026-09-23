use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::engine::{candidate_rank_key, kind_str, parse_kind, Engine};
use crate::git::{self, delta, ObjType};

#[derive(Clone, Debug)]
struct NodeInfo {
    id: i64,
    source_id: i64,
    kind: String,
    declared_size: i64,
    ofs_base_offset: Option<i64>,
    ref_base_oid: Option<Vec<u8>>,
    pack_offset: Option<i64>,
    raw: Option<Vec<u8>>,
    parse_status: String,
    parse_error: Option<String>,
    crc_ok: Option<i64>,
    crc_expected: Option<i64>,
    crc_actual: Option<i64>,
}

struct StatusRow {
    status: &'static str,
    error_code: Option<&'static str>,
    error_message: Option<String>,
    note: Option<String>,
    final_type: Option<String>,
    final_size: Option<i64>,
    final_oid: Option<Vec<u8>>,
    oid_ok: Option<bool>,
    depth: Option<i64>,
    chain_json: Option<String>,
    blocking: Option<Vec<i64>>,
}

/// Expected produced size of one node: leaf = content size, delta = the target
/// size declared in the delta header (read without applying instructions).
fn planned_output_size(n: &NodeInfo) -> i64 {
    match n.kind.as_str() {
        "ofs_delta" | "ref_delta" => {
            if let Some(d) = &n.raw {
                if let Ok((base_size, p)) = git::varint::read_leb128(d, 0) {
                    let _ = base_size;
                    if let Ok((result_size, _)) = git::varint::read_leb128(d, p) {
                        return result_size as i64;
                    }
                }
            }
            n.declared_size
        }
        _ => n.raw.as_ref().map(|v| v.len() as i64).unwrap_or(n.declared_size),
    }
}

impl Engine {
    pub fn settle_branch(&self, branch_id: i64) -> rusqlite::Result<()> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let budget = self.budget_locked(&tx)?;
        self.reap_unblocked(&tx, branch_id)?;
        let roots: Vec<i64> = {
            let mut s = tx.prepare(
                "SELECT n.id FROM nodes n
                 LEFT JOIN resolved r ON r.node_id=n.id AND r.branch_id=?1
                 WHERE r.node_id IS NULL ORDER BY n.id",
            )?;
            let rows = s.query_map(params![branch_id], |r| r.get::<_, i64>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let nodes = self.load_nodes(&tx)?;
        let by_id: HashMap<i64, NodeInfo> = nodes.iter().map(|n| (n.id, n.clone())).collect();
        let used: i64 = tx.query_row(
            "SELECT COALESCE(SUM(cost),0) FROM budget_ledger WHERE branch_id=?1",
            params![branch_id],
            |r| r.get(0),
        )?;
        let mut ledger_used = used;
        for root in roots {
            self.settle_one(&tx, branch_id, root, &by_id, &budget, &mut ledger_used)?;
        }
        tx.commit()
    }

    pub fn retry_node(&self, branch_id: i64, node_id: i64) -> Result<(), String> {
        {
            let db = self.conn.lock().unwrap();
            db.execute(
                "DELETE FROM resolved WHERE branch_id=?1 AND node_id=?2 AND status='paused'",
                params![branch_id, node_id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.settle_branch(branch_id).map_err(|e| e.to_string())
    }

    /// Wipe the ledger and re-open paused subgraphs for re-planning.
    pub fn reset_budget(&self, branch_id: i64) -> Result<usize, String> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction().map_err(|e| e.to_string())?;
        let nodes = self.load_nodes(&tx).map_err(|e| e.to_string())?;
        let by_id: HashMap<i64, NodeInfo> = nodes.iter().map(|n| (n.id, n.clone())).collect();
        let paused: Vec<i64> = {
            let mut s = tx
                .prepare("SELECT node_id FROM resolved WHERE branch_id=?1 AND status='paused'")
                .map_err(|e| e.to_string())?;
            let rows = s.query_map(params![branch_id], |r| r.get::<_, i64>(0));
            rows.map_err(|e| e.to_string())?
                .collect::<rusqlite::Result<Vec<_>>>>()
                .map_err(|e| e.to_string())?
        };
        for p in paused {
            self.clear_closure_inner(&tx, branch_id, p, &by_id)?;
        }
        tx.execute(
            "DELETE FROM budget_ledger WHERE branch_id=?1",
            params![branch_id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        let n = paused.len();
        self.settle_branch(branch_id).map_err(|e| e.to_string())?;
        Ok(n)
    }

    fn budget_locked(
        &self,
        tx: &rusqlite::Transaction,
    ) -> rusqlite::Result<crate::engine::Budget> {
        Ok(crate::engine::Budget {
            max_depth: self.get_setting_tx(tx, "max_depth", crate::engine::DEFAULT_MAX_DEPTH)?,
            max_total_expand: self.get_setting_tx(
                tx,
                "max_total_expand",
                crate::engine::DEFAULT_MAX_TOTAL_EXPAND,
            )?,
            single_object_ratio: self.get_setting_tx(
                tx,
                "single_object_ratio",
                crate::engine::DEFAULT_SINGLE_OBJECT_RATIO,
            )?,
        })
    }

    fn get_setting_tx(
        &self,
        tx: &rusqlite::Transaction,
        key: &str,
        default: i64,
    ) -> rusqlite::Result<i64> {
        let v: Option<String> = tx
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .ok();
        Ok(v.and_then(|s| s.parse().ok()).unwrap_or(default))
    }

    fn reap_unblocked(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
    ) -> rusqlite::Result<()> {
        let nodes = self.load_nodes(tx)?;
        let by_id: HashMap<i64, NodeInfo> = nodes.iter().map(|n| (n.id, n.clone())).collect();
        let blocked: Vec<(i64, String)> = {
            let mut s = tx.prepare(
                "SELECT node_id, COALESCE(error_code,'') FROM resolved
                 WHERE branch_id=?1 AND status IN ('blocked','paused')",
            )?;
            let rows = s.query_map(params![branch_id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (node_id, code) in blocked {
            let node = match by_id.get(&node_id) {
                Some(n) => n.clone(),
                None => continue,
            };
            let now_available = match code.as_str() {
                "missing_ref_base" => {
                    if let Some(oid) = &node.ref_base_oid {
                        tx.query_row(
                            "SELECT COUNT(*) FROM oid_candidates WHERE oid=?1",
                            params![oid],
                            |r| r.get::<_, i64>(0),
                        )? > 0
                    } else {
                        false
                    }
                }
                "depth_limit" | "total_budget_exceeded" | "single_object_ratio" => {
                    // Paused verdicts stay until explicit retry/reset.
                    false
                }
                _ => false,
            };
            if now_available {
                self.clear_closure_inner(tx, branch_id, node_id, &by_id)?;
            }
        }
        Ok(())
    }

    /// Delete rows of `start` and its transitive dependents so they re-plan.
    fn clear_closure_inner(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        start: i64,
        by_id: &HashMap<i64, NodeInfo>,
    ) -> rusqlite::Result<()> {
        // Build reverse edges once from node metadata.
        let mut dependents: HashMap<i64, Vec<i64>> = HashMap::new();
        for n in by_id.values() {
            if let Some(base) = self.base_of(tx, n, by_id)? {
                dependents.entry(base).or_default().push(n.id);
            }
        }
        let mut stack = vec![start];
        let mut seen = HashSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(kids) = dependents.get(&id) {
                for k in kids {
                    stack.push(*k);
                }
            }
            tx.execute(
                "DELETE FROM delta_steps WHERE branch_id=?1 AND node_id=?2",
                params![branch_id, id],
            )?;
            tx.execute(
                "DELETE FROM budget_ledger WHERE branch_id=?1 AND node_id=?2",
                params![branch_id, id],
            )?;
            tx.execute(
                "DELETE FROM resolved WHERE branch_id=?1 AND node_id=?2",
                params![branch_id, id],
            )?;
        }
        Ok(())
    }

    fn load_nodes(&self, tx: &rusqlite::Transaction) -> rusqlite::Result<Vec<NodeInfo>> {
        let mut s = tx.prepare(
            "SELECT id,source_id,kind,declared_size,ofs_base_offset,ref_base_oid,pack_offset,
                    raw,parse_status,parse_error,crc_ok,crc_expected
             FROM nodes ORDER BY id",
        )?;
        let rows = s.query_map([], |r| {
            Ok(NodeInfo {
                id: r.get(0)?,
                source_id: r.get(1)?,
                kind: r.get(2)?,
                declared_size: r.get(3)?,
                ofs_base_offset: r.get(4)?,
                ref_base_oid: r.get(5)?,
                pack_offset: r.get(6)?,
                raw: r.get(7)?,
                parse_status: r.get(8)?,
                parse_error: r.get(9)?,
                crc_ok: r.get(10)?,
                crc_expected: r.get(11)?,
                crc_actual: None,
            })
        })?;
        rows.collect()
    }
}

impl Engine {
    fn base_of(
        &self,
        tx: &rusqlite::Transaction,
        node: &NodeInfo,
        by_id: &HashMap<i64, NodeInfo>,
    ) -> rusqlite::Result<Option<i64>> {
        self.resolve_base_node(tx, node, by_id)
    }

    fn settle_one(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        root: i64,
        by_id: &HashMap<i64, NodeInfo>,
        budget: &crate::engine::Budget,
        ledger_used: &mut i64,
    ) -> rusqlite::Result<()> {
        let mut chain: Vec<i64> = Vec::new();
        let mut on_path: HashSet<i64> = HashSet::new();
        let mut cur = root;
        loop {
            if on_path.contains(&cur) {
                return self.persist_settlement(
                    tx,
                    branch_id,
                    root,
                    StatusRow {
                        status: "error",
                        error_code: Some("delta_cycle"),
                        error_message: Some(format!("delta chain cycles back to node {cur}")),
                        note: Some("cyclic object isolated".into()),
                        final_type: None,
                        final_size: None,
                        final_oid: None,
                        oid_ok: None,
                        depth: Some(chain.len() as i64),
                        chain_json: Some(self.chain_json(&chain, by_id)),
                        blocking: Some(self.blocking_chain(&chain, Some(cur), by_id)),
                    },
                );
            }
            let node = match by_id.get(&cur) {
                Some(n) => n.clone(),
                None => {
                    return self.persist_settlement(
                        tx,
                        branch_id,
                        root,
                        StatusRow {
                            status: "blocked",
                            error_code: Some("missing_node"),
                            error_message: Some(format!("node {cur} vanished")),
                            note: None,
                            final_type: None,
                            final_size: None,
                            final_oid: None,
                            oid_ok: None,
                            depth: Some(chain.len() as i64),
                            chain_json: None,
                            blocking: Some(vec![cur]),
                        },
                    );
                }
            };
            if cur != root {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT status FROM resolved WHERE branch_id=?1 AND node_id=?2",
                        params![branch_id, cur],
                        |r| r.get(0),
                    )
                    .ok();
                if let Some(st) = existing {
                    if st != "resolved" {
                        return self.propagate_blocker(
                            tx, branch_id, root, &cur, &st, &chain, by_id,
                        );
                    }
                    break;
                }
            }
            // Index placeholders mean the pack side of an idx is missing.
            if node.kind == "idx_placeholder" {
                return self.persist_settlement(
                    tx,
                    branch_id,
                    root,
                    StatusRow {
                        status: "blocked",
                        error_code: Some("missing_pack"),
                        error_message: Some(
                            "index declares the object but no matching pack is imported".into(),
                        ),
                        note: Some("retryable automatically once the pack arrives".into()),
                        final_type: None,
                        final_size: None,
                        final_oid: None,
                        oid_ok: None,
                        depth: Some(chain.len() as i64),
                        chain_json: Some(self.chain_json(&chain, by_id)),
                        blocking: Some(self.blocking_chain(&chain, Some(cur), by_id)),
                    },
                );
            }
            if chain.len() as i64 >= budget.max_depth {
                return self.persist_settlement(
                    tx,
                    branch_id,
                    root,
                    StatusRow {
                        status: "paused",
                        error_code: Some("depth_limit"),
                        error_message: Some(format!(
                            "delta depth {} exceeds budget {}",
                            chain.len(),
                            budget.max_depth
                        )),
                        note: Some("retryable: raise max_depth and retry this object".into()),
                        final_type: None,
                        final_size: None,
                        final_oid: None,
                        oid_ok: None,
                        depth: Some(chain.len() as i64),
                        chain_json: Some(self.chain_json(&chain, by_id)),
                        blocking: Some(self.blocking_chain(&chain, None, by_id)),
                    },
                );
            }
            on_path.insert(cur);
            chain.push(cur);

            match node.kind.as_str() {
                "ofs_delta" | "ref_delta" => {
                    match self.resolve_base_node(tx, &node, by_id)? {
                        Some(b) => cur = b,
                        None => {
                            let code = if node.kind == "ref_delta" {
                                "missing_ref_base"
                            } else {
                                "missing_ofs_base"
                            };
                            let target = node
                                .ref_base_oid
                                .as_ref()
                                .map(hex::encode)
                                .unwrap_or_else(|| {
                                    format!("offset {}", node.ofs_base_offset.unwrap_or(-1))
                                });
                            return self.persist_settlement(
                                tx,
                                branch_id,
                                root,
                                StatusRow {
                                    status: "blocked",
                                    error_code: Some(code),
                                    error_message: Some(format!("base {target} cannot be found")),
                                    note: Some(
                                        "retryable automatically once a matching base is imported"
                                            .into(),
                                    ),
                                    final_type: None,
                                    final_size: None,
                                    final_oid: None,
                                    oid_ok: None,
                                    depth: Some(chain.len() as i64),
                                    chain_json: Some(self.chain_json(&chain, by_id)),
                                    blocking: Some(self.blocking_chain(&chain, Some(cur), by_id)),
                                },
                            );
                        }
                    }
                }
                _ => break,
            }
        }

        let order: Vec<i64> = chain.iter().rev().copied().collect();
        // Budget pre-check for new (not-yet-ledgered, not-resolved) nodes.
        let mut ledger_keys: HashSet<i64> = {
            let mut s = tx.prepare("SELECT node_id FROM budget_ledger WHERE branch_id=?1")?;
            let rows = s.query_map(params![branch_id], |r| r.get::<_, i64>(0))?;
            rows.collect::<rusqlite::Result<HashSet<_>>>()?
        };
        let mut new_cost: i64 = 0;
        for id in &order {
            let already = ledger_keys.contains(id)
                || tx
                    .query_row(
                        "SELECT 1 FROM resolved WHERE branch_id=?1 AND node_id=?2 AND status='resolved'",
                        params![branch_id, id],
                        |_| Ok(()),
                    )
                    .is_ok();
            if !already {
                new_cost += planned_output_size(&by_id[id]);
                ledger_keys.insert(*id);
            }
        }
        let max_single = budget.max_total_expand * budget.single_object_ratio;
        if new_cost > max_single {
            return self.persist_settlement(
                tx,
                branch_id,
                root,
                StatusRow {
                    status: "paused",
                    error_code: Some("single_object_ratio"),
                    error_message: Some(format!(
                        "single object expansion {new_cost} exceeds ratio cap {max_single}"
                    )),
                    note: Some("retryable: raise single_object_ratio".into()),
                    final_type: None,
                    final_size: None,
                    final_oid: None,
                    oid_ok: None,
                    depth: Some(order.len() as i64 - 1),
                    chain_json: Some(self.chain_json(&chain, by_id)),
                    blocking: Some(self.blocking_chain(&chain, None, by_id)),
                },
            );
        }
        if new_cost > budget.max_total_expand - *ledger_used {
            return self.persist_settlement(
                tx,
                branch_id,
                root,
                StatusRow {
                    status: "paused",
                    error_code: Some("total_budget_exceeded"),
                    error_message: Some(format!(
                        "object needs {new_cost} new bytes; ledger at {} of {}",
                        *ledger_used, budget.max_total_expand
                    )),
                    note: Some(
                        "retryable: raise max_total_expand or reset the expansion ledger".into(),
                    ),
                    final_type: None,
                    final_size: None,
                    final_oid: None,
                    oid_ok: None,
                    depth: Some(order.len() as i64 - 1),
                    chain_json: Some(self.chain_json(&chain, by_id)),
                    blocking: Some(self.blocking_chain(&chain, None, by_id)),
                },
            );
        }

        self.materialize_ordered(tx, branch_id, &order, by_id, ledger_used)?;
        Ok(())
    }
}

impl Engine {
    fn resolve_base_node(
        &self,
        tx: &rusqlite::Transaction,
        node: &NodeInfo,
        by_id: &HashMap<i64, NodeInfo>,
    ) -> rusqlite::Result<Option<i64>> {
        match node.kind.as_str() {
            "ofs_delta" => {
                let target_off = node.ofs_base_offset.unwrap_or(-1);
                Ok(by_id
                    .values()
                    .find(|n| n.source_id == node.source_id && n.pack_offset == Some(target_off))
                    .map(|n| n.id))
            }
            "ref_delta" => {
                let oid = match &node.ref_base_oid {
                    Some(o) => o.clone(),
                    None => return Ok(None),
                };
                if let Ok(nid) = tx.query_row(
                    "SELECT node_id FROM pins WHERE branch_id=?1 AND oid=?2",
                    params![1i64, oid],
                    |r| r.get::<_, i64>(0),
                ) {
                    return Ok(Some(nid));
                }
                Ok(tx.query_row(
                    "SELECT c.node_id FROM oid_candidates c
                     WHERE c.oid=?1
                     ORDER BY c.rank_key ASC LIMIT 1",
                    params![oid],
                    |r| r.get::<_, i64>(0),
                )
                .ok())
            }
            _ => Ok(None),
        }
    }

    fn materialize_ordered(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        order: &[i64],
        by_id: &HashMap<i64, NodeInfo>,
        ledger_used: &mut i64,
    ) -> rusqlite::Result<()> {
        let mut built: HashMap<i64, (ObjType, Vec<u8>)> = HashMap::new();
        for (step_index, &id) in order.iter().enumerate() {
            let node = by_id[&id].clone();

            // Skip nodes already materialized (shared bases / local reuse).
            let already_done = tx
                .query_row(
                    "SELECT 1 FROM resolved WHERE branch_id=?1 AND node_id=?2 AND status='resolved'",
                    params![branch_id, id],
                    |_| Ok(()),
                )
                .is_ok();
            if already_done {
                if built.get(&id).is_none() {
                    let (ty_s, content): (String, Vec<u8>) = tx.query_row(
                        "SELECT final_type,final_content FROM resolved
                         WHERE branch_id=?1 AND node_id=?2",
                        params![branch_id, id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    built.insert(
                        id,
                        (parse_kind(&ty_s).unwrap_or(ObjType::Blob), content),
                    );
                }
                continue;
            }

            if node.parse_status != "ok" {
                self.persist_settlement(
                    tx,
                    branch_id,
                    id,
                    StatusRow {
                        status: "error",
                        error_code: Some("inflate_failed"),
                        error_message: node.parse_error.clone(),
                        note: Some("object isolated; other objects continue analysis".into()),
                        final_type: None,
                        final_size: None,
                        final_oid: None,
                        oid_ok: None,
                        depth: Some(step_index as i64),
                        chain_json: Some(self.chain_json_from_order(order, by_id)),
                        blocking: Some(vec![id]),
                    },
                )?;
                continue;
            }
            if let Some(crc_ok) = node.crc_ok {
                if crc_ok == 0 {
                    self.persist_settlement(
                        tx,
                        branch_id,
                        id,
                        StatusRow {
                            status: "error",
                            error_code: Some("crc_mismatch"),
                            error_message: Some(format!(
                                "index CRC32 {} does not match the compressed bytes in the pack",
                                node.crc_expected.unwrap_or(-1)
                            )),
                            note: Some("corrupt entry isolated; not used as a base".into()),
                            final_type: None,
                            final_size: None,
                            final_oid: None,
                            oid_ok: Some(false),
                            depth: Some(step_index as i64),
                            chain_json: Some(self.chain_json_from_order(order, by_id)),
                            blocking: Some(vec![id]),
                        },
                    )?;
                    continue;
                }
            }

            if node.kind == "ofs_delta" || node.kind == "ref_delta" {
                let base_id = match self.resolve_base_node(tx, &node, by_id)? {
                    Some(b) => b,
                    None => continue,
                };
                let (base_type, base_bytes) = match built.get(&base_id) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                let delta_bytes = match &node.raw {
                    Some(d) => d.clone(),
                    None => continue,
                };
                let input_len = base_bytes.len();
                match delta::apply_delta(&base_bytes, &delta_bytes) {
                    Ok(res) => {
                        let output_len = res.target.len();
                        let oid = git::object_id::hash_object(base_type, &res.target);
                        let expected_idx: Option<Vec<u8>> = tx
                            .query_row(
                                "SELECT oid FROM oid_candidates WHERE node_id=?1 AND origin='index'
                                 ORDER BY rank_key LIMIT 1",
                                params![id],
                                |r| r.get(0),
                            )
                            .ok();
                        let oid_ok = expected_idx
                            .as_ref()
                            .map(|e| e.as_slice() == oid.as_slice());
                        let ranges: Vec<serde_json::Value> = res
                            .instrs
                            .iter()
                            .map(|i| {
                                serde_json::json!({
                                    "kind": if i.kind == delta::InstrKind::Copy {"copy"} else {"insert"},
                                    "start": i.range_start, "end": i.range_end,
                                    "src_offset": i.src_offset, "length": i.length,
                                    "out_offset": i.out_offset,
                                })
                            })
                            .collect();
                        let check_ok = oid_ok.unwrap_or(true);
                        tx.execute(
                            "INSERT INTO delta_steps(branch_id,node_id,step,base_node_id,base_oid,
                                input_len,output_len,instr_count,instr_ranges_json,check_ok,note)
                             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                             ON CONFLICT(branch_id,node_id,step) DO UPDATE SET
                                base_node_id=excluded.base_node_id,base_oid=excluded.base_oid,
                                input_len=excluded.input_len,output_len=excluded.output_len,
                                instr_count=excluded.instr_count,
                                instr_ranges_json=excluded.instr_ranges_json,
                                check_ok=excluded.check_ok,note=excluded.note",
                            params![
                                branch_id, id, step_index as i64, base_id, node.ref_base_oid,
                                input_len as i64, output_len as i64, res.instrs.len() as i64,
                                serde_json::to_string(&ranges).unwrap(),
                                check_ok as i64,
                                if check_ok {"oid verified against index"} else {"oid mismatch"},
                            ],
                        )?;
                        if !check_ok {
                            self.persist_settlement(
                                tx,
                                branch_id,
                                id,
                                StatusRow {
                                    status: "error",
                                    error_code: Some("oid_mismatch"),
                                    error_message: Some(format!(
                                        "reconstructed oid {} != index oid {}",
                                        hex::encode(oid),
                                        expected_idx.as_ref().map(hex::encode).unwrap_or_default()
                                    )),
                                    note: Some("delta result rejected; partial bytes not stored".into()),
                                    final_type: Some(kind_str(base_type).into()),
                                    final_size: Some(output_len as i64),
                                    final_oid: Some(oid.to_vec()),
                                    oid_ok: Some(false),
                                    depth: Some(total_depth(order)),
                                    chain_json: Some(self.chain_json_from_order(order, by_id)),
                                    blocking: Some(vec![id]),
                                },
                            )?;
                            continue;
                        }
                        let target = res.target.clone();
                        self.write_final(
                            tx, branch_id, id, base_type, target.clone(), oid, order, by_id,
                        )?;
                        built.insert(id, (base_type, target));
                        self.add_ledger_cost(tx, branch_id, id, output_len as i64, ledger_used)?;
                    }
                    Err(msg) => {
                        self.persist_settlement(
                            tx,
                            branch_id,
                            id,
                            StatusRow {
                                status: "error",
                                error_code: Some("bad_delta"),
                                error_message: Some(msg),
                                note: Some("bad delta instruction; object isolated".into()),
                                final_type: None,
                                final_size: None,
                                final_oid: None,
                                oid_ok: None,
                                depth: Some(step_index as i64),
                                chain_json: Some(self.chain_json_from_order(order, by_id)),
                                blocking: Some(vec![id]),
                            },
                        )?;
                    }
                }
            } else {
                let content = match &node.raw {
                    Some(c) => c.clone(),
                    None => continue,
                };
                let ty = parse_kind(&node.kind).unwrap_or(ObjType::Blob);
                let oid = git::object_id::hash_object(ty, &content);
                tx.execute("UPDATE nodes SET computed_oid=?1 WHERE id=?2",
                    params![oid.to_vec(), id])?;
                let expected_idx: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT oid FROM oid_candidates WHERE node_id=?1 AND origin='index'
                         ORDER BY rank_key LIMIT 1",
                        params![id],
                        |r| r.get(0),
                    )
                    .ok();
                if let Some(e) = &expected_idx {
                    if e.as_slice() != oid.as_slice() {
                        self.persist_settlement(
                            tx,
                            branch_id,
                            id,
                            StatusRow {
                                status: "error",
                                error_code: Some("oid_mismatch"),
                                error_message: Some(format!(
                                    "parsed oid {} != index oid {}",
                                    hex::encode(oid),
                                    hex::encode(e)
                                )),
                                note: None,
                                final_type: Some(kind_str(ty).into()),
                                final_size: Some(content.len() as i64),
                                final_oid: Some(oid.to_vec()),
                                oid_ok: Some(false),
                                depth: Some(0),
                                chain_json: Some(self.chain_json_from_order(order, by_id)),
                                blocking: Some(vec![id]),
                            },
                        )?;
                        continue;
                    }
                }
                let idx_present: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM oid_candidates WHERE node_id=?1 AND origin='index'",
                    params![id],
                    |r| r.get(0),
                )?;
                let exists: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM oid_candidates WHERE node_id=?1 AND oid=?2 AND origin='computed'",
                    params![id, oid.to_vec()],
                    |r| r.get(0),
                )?;
                if exists == 0 {
                    let rank = candidate_rank_key(
                        "computed",
                        idx_present > 0,
                        None,
                        node.source_id,
                        node.pack_offset,
                    );
                    tx.execute(
                        "INSERT INTO oid_candidates(oid,node_id,origin,idx_present,crc_ok,checksum_ok,rank_key)
                         VALUES(?1,?2,'computed',?3,?4,1,?5)",
                        params![oid.to_vec(), id, idx_present, node.crc_ok, rank],
                    )?;
                }
                self.write_final(tx, branch_id, id, ty, content.clone(), oid, order, by_id)?;
                built.insert(id, (ty, content.clone()));
                self.add_ledger_cost(tx, branch_id, id, content.len() as i64, ledger_used)?;
            }
        }
        Ok(())
    }

    fn add_ledger_cost(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        node_id: i64,
        cost: i64,
        ledger_used: &mut i64,
    ) -> rusqlite::Result<()> {
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO budget_ledger(branch_id,node_id,cost) VALUES(?1,?2,?3)",
            params![branch_id, node_id, cost],
        )?;
        if inserted > 0 {
            *ledger_used += cost;
        }
        Ok(())
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn write_final(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        node_id: i64,
        ty: ObjType,
        content: Vec<u8>,
        oid: [u8; 20],
        order: &[i64],
        by_id: &HashMap<i64, NodeInfo>,
    ) -> rusqlite::Result<()> {
        let depth = order
            .iter()
            .position(|x| *x == node_id)
            .unwrap_or(0) as i64;
        tx.execute(
            "INSERT INTO resolved(branch_id,node_id,status,final_type,final_size,final_oid,oid_ok,
                final_content,depth,chain_json,error_code,error_message,blocking_chain_json,
                last_settled_at,recompute_count)
             VALUES(?1,?2,'resolved',?3,?4,?5,1,?6,?7,?8,NULL,NULL,NULL,datetime('now'),0)
             ON CONFLICT(branch_id,node_id) DO UPDATE SET
                status='resolved',final_type=excluded.final_type,
                final_size=excluded.final_size,final_oid=excluded.final_oid,oid_ok=1,
                final_content=excluded.final_content,depth=excluded.depth,
                chain_json=excluded.chain_json,error_code=NULL,error_message=NULL,
                note=NULL,blocking_chain_json=NULL,last_settled_at=datetime('now'),
                recompute_count=resolved.recompute_count+1",
            params![
                branch_id,
                node_id,
                kind_str(ty),
                content.len() as i64,
                oid.to_vec(),
                content,
                depth,
                self.chain_json_from_order(order, by_id),
            ],
        )?;
        Ok(())
    }

    fn persist_settlement(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        node_id: i64,
        s: StatusRow,
    ) -> rusqlite::Result<()> {
        let blocking = s
            .blocking
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap());
        tx.execute(
            "INSERT INTO resolved(branch_id,node_id,status,error_code,error_message,note,
                final_type,final_size,final_oid,oid_ok,depth,chain_json,blocking_chain_json,
                last_settled_at,recompute_count)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,datetime('now'),0)
             ON CONFLICT(branch_id,node_id) DO UPDATE SET
                status=excluded.status,error_code=excluded.error_code,
                error_message=excluded.error_message,note=excluded.note,
                final_type=excluded.final_type,final_size=excluded.final_size,
                final_oid=excluded.final_oid,oid_ok=excluded.oid_ok,depth=excluded.depth,
                chain_json=excluded.chain_json,blocking_chain_json=excluded.blocking_chain_json,
                last_settled_at=datetime('now'),
                recompute_count=resolved.recompute_count+1",
            params![
                branch_id,
                node_id,
                s.status,
                s.error_code,
                s.error_message,
                s.note,
                s.final_type,
                s.final_size,
                s.final_oid,
                s.oid_ok.map(|v| v as i64),
                s.depth,
                s.chain_json,
                blocking,
            ],
        )?;
        Ok(())
    }

    fn propagate_blocker(
        &self,
        tx: &rusqlite::Transaction,
        branch_id: i64,
        root: i64,
        base_id: &i64,
        base_status: &str,
        chain: &[i64],
        by_id: &HashMap<i64, NodeInfo>,
    ) -> rusqlite::Result<()> {
        let (code, msg): (Option<String>, Option<String>) = tx.query_row(
            "SELECT error_code,error_message FROM resolved WHERE branch_id=?1 AND node_id=?2",
            params![branch_id, base_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let blockers = self.blocking_chain(chain, Some(*base_id), by_id);
        tx.execute(
            "INSERT INTO resolved(branch_id,node_id,status,error_code,error_message,note,
                depth,chain_json,blocking_chain_json,last_settled_at,recompute_count)
             VALUES(?1,?2,?3,?4,?5,'inherited from unresolved base',?6,?7,?8,datetime('now'),0)
             ON CONFLICT(branch_id,node_id) DO UPDATE SET status=excluded.status,
                error_code=excluded.error_code,error_message=excluded.error_message,
                blocking_chain_json=excluded.blocking_chain_json,last_settled_at=datetime('now')",
            params![
                branch_id,
                root,
                base_status,
                code,
                msg,
                chain.len() as i64,
                self.chain_json(chain, by_id),
                serde_json::to_string(&blockers).unwrap(),
            ],
        )?;
        Ok(())
    }

    fn chain_json(&self, chain: &[i64], by_id: &HashMap<i64, NodeInfo>) -> String {
        let v: Vec<serde_json::Value> = chain
            .iter()
            .map(|id| {
                let n = &by_id[id];
                serde_json::json!({
                    "node_id": id, "kind": n.kind,
                    "source_id": n.source_id, "offset": n.pack_offset,
                })
            })
            .collect();
        serde_json::to_string(&v).unwrap()
    }

    fn chain_json_from_order(&self, order: &[i64], by_id: &HashMap<i64, NodeInfo>) -> String {
        let chain: Vec<i64> = order.iter().rev().copied().collect();
        self.chain_json(&chain, by_id)
    }

    fn blocking_chain(
        &self,
        chain: &[i64],
        terminal: Option<i64>,
        by_id: &HashMap<i64, NodeInfo>,
    ) -> Vec<i64> {
        let mut v: Vec<i64> = chain
            .iter()
            .filter(|id| {
                let n = &by_id[*id];
                n.kind == "ofs_delta" || n.kind == "ref_delta"
            })
            .copied()
            .collect();
        if let Some(t) = terminal {
            v.push(t);
        }
        v.dedup();
        v
    }

    fn total_depth(order: &[i64]) -> i64 {
        order.len() as i64 - 1
    }
}
