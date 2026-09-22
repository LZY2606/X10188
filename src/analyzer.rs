use crate::git::{git_oid, oid_hex, parse_oid, read_delta_varint, ObjectType, Oid};
use crate::pack::{parse_loose, parse_pack, ParsedPack};
use crate::delta::apply_delta;
use rusqlite::{params, Connection};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub(crate) struct Node {
    pub id: String,
    pub source: String,
    pub import_order: i64,
    pub kind: String,
    pub object_type: ObjectType,
    pub payload: Vec<u8>,
    pub expected_oid: Option<Oid>,
    pub offset: i64,
    pub parse_error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Resolved {
    pub oid: Oid,
    pub object_type: ObjectType,
    pub data: Vec<u8>,
    pub depth: usize,
    pub expanded: u64,
    pub chain: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct Failure {
    pub reason: String,
    pub paused: bool,
    pub chain: Vec<String>,
    pub blocked_node: Option<String>,
    pub blocked_oid: Option<Oid>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Budget { pub total: u64, pub depth: usize, pub single: u64, pub ratio: u64 }

#[derive(Default)]
pub(crate) struct Graph {
    nodes: BTreeMap<String, Node>,
    by_oid: BTreeMap<String, Vec<String>>,
    pinned: Option<(Oid, String)>,
    budget: Budget,
    used_total: u64,
    max_depth: usize,
}

pub fn analyze(conn: &mut Connection, files_dir: &Path, branch: &str) -> rusqlite::Result<String> {
    let budget = load_budget(conn, branch);
    let mut graph = Graph { budget, ..Default::default() };
    graph.pinned = load_pin(conn, branch);
    load_nodes(conn, files_dir, &mut graph)?;
    seed_candidates(conn, &graph, branch)?;
    conn.execute("DELETE FROM resolved WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM delta_steps WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM blockers WHERE branch_id=?1", params![branch])?;
    conn.execute("DELETE FROM dependencies WHERE branch_id=?1", params![branch])?;

    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let mut cache: BTreeMap<String, Result<Resolved, Failure>> = BTreeMap::new();
    for id in ids {
        if cache.contains_key(&id) { continue; }
        let mut visiting = BTreeSet::new();
        let result = resolve(conn, &mut graph, &id, 1, &mut visiting, &mut cache, branch)?;
        persist_result(conn, &graph, branch, &id, &result)?;
    }
    let status = if graph.used_total >= budget.total { "paused" } else if cache.values().any(|r| r.is_err() && r.as_ref().err().map(|f| f.paused).unwrap_or(false)) { "paused" } else { "complete" };
    conn.execute("UPDATE analysis_runs SET status=?2,total_expanded=?3,max_depth=?4,updated_at=datetime('now') WHERE branch_id=?1",
        params![branch, status, graph.used_total as i64, graph.max_depth as i64])?;
    Ok(status.into())
}

fn load_budget(conn: &Connection, branch: &str) -> Budget {
    conn.query_row("SELECT budget_total,budget_depth,budget_single,budget_ratio FROM analysis_runs WHERE branch_id=?1", params![branch],
        |r| Ok(Budget { total: r.get(0)?, depth: r.get::<_,i64>(1)? as usize, single: r.get(2)?, ratio: r.get(3)? }))
        .unwrap_or_default()
}

fn load_pin(conn: &Connection, branch: &str) -> Option<(Oid, String)> {
    conn.query_row("SELECT pinned_oid,pinned_node FROM branches WHERE branch_id=?1", params![branch],
        |r| Ok((r.get::<_,Option<String>>(0)?, r.get::<_,Option<String>>(1)?))).ok()
        .and_then(|(oid,node)| oid.zip(node)).and_then(|(oid,node)| parse_oid(&oid).map(|o| (o,node)))
}

fn load_nodes(conn: &mut Connection, files_dir: &Path, graph: &mut Graph) -> rusqlite::Result<()> {
    let mut packs: BTreeMap<String, (ParsedPack, i64)> = BTreeMap::new();
    {
        let mut stmt = conn.prepare("SELECT s.source_id,s.stored_path,s.import_order FROM sources s JOIN packs p ON s.source_id=p.source_id ORDER BY s.import_order")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?)))?;
        for row in rows.flatten() {
            let bytes = fs::read(files_dir.join(row.1)).unwrap_or_default();
            let hints = hints_for_pack(conn, files_dir, &bytes);
            packs.insert(row.0.clone(), (parse_pack(bytes, &hints, 64*1024*1024), row.2));
        }
    }
    for (source, (pack, order)) in &packs {
        let expected = expected_map(conn, source);
        for entry in pack.entries.values() {
            let kind = if entry.parse_error.is_some() { "bad" } else { entry.object_type.name() }.to_string();
            let id = format!("pack:{source}:{}", entry.offset);
            graph.by_oid.entry(oid_hex(&[0;20])).or_default();
            if let Some(oid) = expected.get(&(entry.offset as i64)).or(entry.base_oid.as_ref().filter(|_| false)) {
                graph.by_oid.entry(oid_hex(oid)).or_default().push(id.clone());
            }
            graph.nodes.insert(id.clone(), Node {
                id, source: source.clone(), import_order: *order, kind: kind.clone(),
                object_type: entry.object_type, payload: entry.payload.clone().unwrap_or_default(),
                expected_oid: expected.get(&(entry.offset as i64)).copied(),
                offset: entry.offset as i64, parse_error: entry.parse_error.clone(),
            });
        }
    }
    let mut stmt = conn.prepare("SELECT l.source_id,s.stored_path,s.import_order,l.oid,l.type_name,l.size,l.parse_error FROM loose_objects l JOIN sources s ON s.source_id=l.source_id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,Option<String>>(6)?)))?;
    for row in rows.flatten() {
        let bytes = fs::read(files_dir.join(&row.1)).unwrap_or_default();
        let expected = parse_oid(&row.3);
        let object = parse_loose(&bytes, expected, 64*1024*1024);
        let id = format!("loose:{}:{}", row.0, oid_hex(&expected.unwrap_or(object.oid)));
        graph.by_oid.entry(oid_hex(&object.oid)).or_default().push(id.clone());
        graph.nodes.insert(id.clone(), Node { id, source: row.0, import_order: row.2, kind: "loose".into(), object_type: object.kind, payload: object.data, expected_oid: Some(object.oid), offset: -1, parse_error: row.6.or(object.parse_error) });
    }
    Ok(())
}

fn hints_for_pack(conn: &Connection, files_dir: &Path, pack_bytes: &[u8]) -> BTreeSet<u64> {
    if pack_bytes.len() < 20 { return BTreeSet::new(); }
    let checksum_array: Oid = pack_bytes[pack_bytes.len()-20..].try_into().unwrap_or([0;20]); let checksum = oid_hex(&checksum_array);
    let path: Option<String> = conn.query_row("SELECT s.stored_path FROM indexes i JOIN sources s ON s.source_id=i.source_id WHERE i.pack_checksum=?1", params![checksum], |r| r.get(0)).ok();
    path.and_then(|p| fs::read(files_dir.join(p)).ok()).map(|bytes| crate::pack::parse_index(bytes).records.into_iter().map(|r| r.offset).collect()).unwrap_or_default()
}

fn expected_map(conn: &Connection, pack_source: &str) -> BTreeMap<i64, Oid> {
    let mut out = BTreeMap::new();
    let mut stmt = conn.prepare("SELECT ir.offset,ir.oid FROM index_records ir JOIN indexes i ON ir.index_source=i.source_id WHERE i.pack_source_id=?1").unwrap();
    if let Ok(rows) = stmt.query_map(params![pack_source], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,String>(1)?))) {
        for row in rows.flatten() { if let Some(oid)=parse_oid(&row.1) { out.insert(row.0, oid); } }
    }
    out
}

fn rank_node(graph: &Graph, node: &Node) -> (i64, i64, String) {
    let origin_rank = if node.kind == "loose" { 0 } else { 1 };
    (origin_rank, node.import_order, node.id.clone())
}

fn seed_candidates(conn: &Connection, graph: &Graph, branch: &str) -> rusqlite::Result<()> {
    for (oid_hex_value, nodes) in &graph.by_oid {
        if oid_hex_value == &oid_hex(&[0;20]) { continue; }
        for node_id in nodes {
            let node = &graph.nodes[node_id];
            let (rank, order, sort_key) = rank_node(graph, node);
            conn.execute("INSERT OR IGNORE INTO candidates(oid,node,branch_id,source_id,origin_rank,kind,sort_key) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![oid_hex_value, node_id, branch, node.source, rank, node.kind, format!("{rank}:{order}:{sort_key}")])?;
        }
    }
    if let Some((oid, pinned_node)) = &graph.pinned {
        let key = oid_hex(&oid);
        conn.execute("UPDATE candidates SET pinned=1 WHERE branch_id=?1 AND oid=?2 AND node=?3", params![branch,key,pinned_node])?;
        conn.execute("UPDATE candidates SET pinned=0 WHERE branch_id=?1 AND oid=?2 AND node!=?3", params![branch,key,pinned_node])?;
    }
    Ok(())
}

fn choose_base_node(graph: &Graph, oid: &Oid) -> Option<String> {
    let nodes = graph.by_oid.get(&oid_hex(oid))?;
    let mut usable: Vec<&String> = nodes.iter().filter(|id| !graph.nodes[*id].kind.eq_ignore_ascii_case("bad")).collect();
    if let Some((pinned_oid, pinned_node)) = &graph.pinned {
        if pinned_oid == oid && graph.nodes.contains_key(pinned_node) { return Some(pinned_node.clone()); }
    }
    usable.sort_by(|a,b| rank_node(graph,&graph.nodes[*a]).cmp(&rank_node(graph,&graph.nodes[*b])));
    usable.into_iter().cloned().next()
}

fn fail(reason: &str, paused: bool, chain: &[String], blocked_node: Option<String>, blocked_oid: Option<Oid>) -> Failure {
    Failure { reason: reason.into(), paused, chain: chain.to_vec(), blocked_node, blocked_oid }
}

fn check_budget_output(len: u64, base_len: u64, graph: &Graph) -> Result<(), Failure> {
    let ratio_limit = base_len.saturating_mul(graph.budget.ratio);
    if len > graph.budget.single || (base_len > 0 && len > ratio_limit) {
        Err(fail(&format!("single-object budget reached: result {len} bytes, base {base_len}, ratio {}", graph.budget.ratio), true, &[], None, None))
    } else { Ok(()) }
}

fn resolve(
    conn: &Connection,
    graph: &mut Graph,
    node_id: &str,
    depth: usize,
    visiting: &mut BTreeSet<String>,
    cache: &mut BTreeMap<String, Result<Resolved, Failure>>,
    branch: &str,
) -> rusqlite::Result<Result<Resolved, Failure>> {
    if let Some(result) = cache.get(node_id) { return Ok(result.clone()); }
    let Some(node) = graph.nodes.get(node_id).cloned() else {
        return Ok(Err(fail("object node is missing", false, &[], None, None)));
    };
    if node.parse_error.is_some() {
        return Ok(Err(fail(&node.parse_error.clone().unwrap(), false, &[node_id.to_string()], Some(node_id.to_string()), None)));
    }
    if depth > graph.budget.depth {
        return Ok(Err(fail(&format!("delta depth budget reached at depth {depth}"), true, &[node_id.to_string()], Some(node_id.to_string()), None)));
    }
    if !visiting.insert(node_id.to_string()) {
        let mut chain = visiting.iter().cloned().collect::<Vec<_>>();
        chain.push(node_id.to_string());
        return Ok(Err(fail("delta dependency cycle detected", false, &chain, Some(node_id.to_string()), None)));
    }

    let result: Result<Resolved, Failure> = if node.kind == "loose" || !node.object_type.is_delta() {
        let actual = git_oid(node.object_type, &node.payload);
        if let Some(expected) = node.expected_oid {
            if expected != actual {
                Err(fail(&format!("object id mismatch: expected {}, computed {}", oid_hex(&expected), oid_hex(&actual)), false, &[node_id.to_string()], Some(node_id.to_string()), Some(actual)))
            } else {
                Ok(Resolved { oid: actual, object_type: node.object_type, data: node.payload.clone(), depth: 0, expanded: node.payload.len() as u64, chain: vec![node_id.to_string()] })
            }
        } else {
            Ok(Resolved { oid: actual, object_type: node.object_type, data: node.payload.clone(), depth: 0, expanded: node.payload.len() as u64, chain: vec![node_id.to_string()] })
        }
    } else {
        let (base_node, base_oid) = if node.kind == "ofs_delta" {
            let base_offset: Option<i64> = conn.query_row("SELECT base_offset FROM entries WHERE node=?1", params![node_id], |r| r.get(0)).unwrap_or(None);
            match base_offset {
                Some(offset) => (Some(format!("pack:{}:{offset}", node.source)), None),
                None => (None, None),
            }
        } else {
            let oid_text: Option<String> = conn.query_row("SELECT base_oid FROM entries WHERE node=?1", params![node_id], |r| r.get(0)).unwrap_or(None);
            let oid = oid_text.and_then(|s| parse_oid(&s));
            (oid.as_ref().and_then(|o| choose_base_node(graph, o)), oid)
        };
        let Some(base_node) = base_node else {
            let chain = vec![node_id.to_string()];
            return Ok(Err(fail("external base object is missing", false, &chain, None, base_oid)));
        };
        conn.execute("INSERT OR REPLACE INTO dependencies(node,branch_id,base_node,base_oid,kind) VALUES(?1,?2,?3,?4,?5)",
            params![node_id, branch, base_node, base_oid.map(|o| oid_hex(&o)), node.kind])?;
        if !graph.nodes.contains_key(&base_node) {
            return Ok(Err(fail(&format!("base node {base_node} is outside imported sources"), false, &[node_id.to_string()], Some(base_node), base_oid)));
        }
        let base = match resolve(conn, graph, &base_node, depth + 1, visiting, cache, branch)? {
            Ok(base) => base,
            Err(mut failure) => {
                failure.chain.insert(0, node_id.to_string());
                failure.reason = format!("blocked by base {base_node}: {}", failure.reason);
                return Ok(Err(failure));
            }
        };
        let (delta_size, pos) = read_delta_varint(&node.payload, 0).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData,e))))?;
        let (target_size, _) = read_delta_varint(&node.payload, pos).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData,e))))?;
        let _ = delta_size;
        if let Err(mut failure) = check_budget_output(target_size, base.data.len() as u64, graph) {
            failure.chain = vec![node_id.to_string()]; failure.blocked_node = Some(base_node); failure.blocked_oid = base_oid;
            cache.insert(node_id.to_string(), Err(failure.clone()));
            visiting.remove(node_id);
            return Ok(Err(failure));
        }
        let chain_expand = base.expanded.saturating_add(target_size);
        if graph.used_total.saturating_add(chain_expand) > graph.budget.total {
            let f = fail("total expanded-byte budget reached; result retained only as retryable intermediate state", true, &[node_id.to_string()], Some(base_node), base_oid);
            cache.insert(node_id.to_string(), Err(f.clone()));
            visiting.remove(node_id);
            return Ok(Err(f));
        }
        match apply_delta(base.object_type, &base.data, &node.payload, graph.budget.single) {
            Ok(applied) => {
                graph.used_total = graph.used_total.saturating_add(applied.data.len() as u64);
                graph.max_depth = graph.max_depth.max(depth);
                let oid = git_oid(applied.object_type, &applied.data);
                let produced_len = applied.data.len() as u64;
                let ranges: Vec<String> = applied.instructions.iter().map(|i| format!("{}:{}..{}", if matches!(i.operation, crate::delta::DeltaOperation::Copy) {"copy"} else {"insert"}, i.instruction_start, i.instruction_end)).collect();
                let check_ok = node.expected_oid.map_or(true, |expected| expected == oid) && base.data.len() as u64 == match read_delta_varint(&node.payload,0) { Ok((v,_))=>v, Err(_)=>0 };
                conn.execute("INSERT INTO delta_steps(branch_id,node,step,base_node,delta_node,input_len,output_len,instruction_count,instruction_ranges,check_ok,check_oid) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![branch,node_id,depth-1,base_node,node_id,base.data.len() as i64,applied.data.len() as i64,applied.instructions.len() as i64,json_string_array(&ranges),check_ok as i64,oid_hex(&oid)])?;
                if let Some(expected) = node.expected_oid.filter(|e| *e != oid) {
                    Err(fail(&format!("recomputed object id mismatch: index expects {}, computed {}", oid_hex(&expected), oid_hex(&oid)), false, &[node_id.to_string()], Some(node_id.to_string()), Some(oid)))
                } else {
                    let mut chain = base.chain; chain.push(node_id.to_string());
                    Ok(Resolved { oid, object_type: applied.object_type, data: applied.data, depth: base.depth + 1, expanded: base.expanded + produced_len, chain })
                }
            }
            Err(error) => Err(fail(&error.message(), false, &[node_id.to_string()], Some(base_node), base_oid)),
        }
    };

    cache.insert(node_id.to_string(), result.clone());
    visiting.remove(node_id);
    Ok(result)
}

fn json_string_array(values: &[String]) -> String {
    let mut out = String::from("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str(&serde_json_fragment(v));
    }
    out.push(']'); out
}
fn serde_json_fragment(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c { '\\'|'"' => { out.push('\\'); out.push(c); } '\n' => out.push_str("\\n"), c => out.push(c) }
    }
    out.push('"'); out
}

fn persist_result(conn: &Connection, graph: &Graph, branch: &str, node_id: &str, result: &Result<Resolved, Failure>) -> rusqlite::Result<()> {
    let node = &graph.nodes[node_id];
    match result {
        Ok(resolved) => {
            conn.execute(
                "INSERT OR REPLACE INTO resolved(node,branch_id,oid,type_name,size,status,content,check_ok,error,chain_json,expanded_bytes,depth)
                 VALUES(?1,?2,?3,?4,?5,'complete',?6,1,NULL,?7,?8,?9)",
                params![node_id, branch, oid_hex(&resolved.oid), resolved.object_type.name(), resolved.data.len() as i64,
                    resolved.data, json_string_array(&resolved.chain), resolved.expanded as i64, resolved.depth as i64],
            )?;
            graph.by_oid.iter().find(|(_, nodes)| nodes.iter().any(|n| n == node_id)).map(|(oid, _)| {
                conn.execute("UPDATE candidates SET verified=1 WHERE branch_id=?1 AND oid=?2 AND node=?3", params![branch, oid, node_id]).ok()
            });
        }
        Err(failure) => {
            let paused = if failure.paused { "paused" } else { "failed" };
            conn.execute(
                "INSERT OR REPLACE INTO resolved(node,branch_id,oid,type_name,size,status,content,check_ok,error,chain_json,expanded_bytes,depth)
                 VALUES(?1,?2,NULL,?3,NULL,?4,NULL,0,?5,?6,0,0)",
                params![node_id, branch, node.object_type.name(), paused, failure.reason, json_string_array(&failure.chain)],
            )?;
            let blocked_oid = failure.blocked_oid.map(|o| oid_hex(&o));
            conn.execute(
                "INSERT INTO blockers(branch_id,node,seq,reason,blocked_node,blocked_oid,chain_json) VALUES(?1,?2,0,?3,?4,?5,?6)",
                params![branch, node_id, failure.reason, failure.blocked_node, blocked_oid, json_string_array(&failure.chain)],
            )?;
        }
    }
    Ok(())
}

pub fn list_branches(conn: &Connection) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT branch_id FROM branches ORDER BY created_at,branch_id").unwrap();
    stmt.query_map([], |r| r.get::<_,String>(0)).unwrap().flatten().collect()
}

pub fn json_public(values: &[String]) -> String { json_string_array(values) }
