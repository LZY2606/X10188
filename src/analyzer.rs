use crate::db;
use crate::git::{
    self, apply_delta, oid_hex, parse_oid, GitObject, ObjectType,
};
use crate::loose::parse_loose;
use crate::model::{BlockedChain, Budget, CandidateStatus};
use crate::pack::{parse_index, parse_pack};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug)]
pub struct AnalyzeResult {
    pub source_id: i64,
    pub imported: bool,
    pub resolved: usize,
    pub failed: usize,
    pub paused: bool,
    pub changed_oids: Vec<String>,
}

#[derive(Debug, Clone)]
struct CandidateRow {
    id: i64,
    origin_kind: String,
    source_id: i64,
    source_sha: String,
    filename: String,
    pack_id: Option<i64>,
    offset: Option<i64>,
    input_type: String,
    payload: Vec<u8>,
    direct_base_candidate_id: Option<i64>,
    ref_base_oid: Option<[u8; 20]>,
    declared_oid: Option<[u8; 20]>,
    parse_error: Option<String>,
    status: CandidateStatus,
    pinned: bool,
}

#[derive(Debug, Clone)]
struct Resolved {
    oid: [u8; 20],
    kind: ObjectType,
    data: Vec<u8>,
    depth: usize,
    ratio: usize,
    base_candidate_id: Option<i64>,
}

#[derive(Debug, Clone)]
enum ResolveError {
    Bad(String),
    MissingBase(String),
    Cycle,
    Depth,
    BudgetBytes,
    Ratio,
}

struct Solver<'a> {
    conn: &'a mut Connection,
    candidates: HashMap<i64, CandidateRow>,
    stack: Vec<i64>,
    done: HashMap<i64, Result<Resolved, ResolveError>>,
    budget: Budget,
    affected: HashSet<String>,
}

pub fn default_budget() -> Budget {
    Budget {
        max_depth: 16,
        max_total_bytes: 256 * 1024 * 1024,
        max_single_ratio: 32,
        bytes_used: 0,
        paused: false,
    }
}

pub fn import_and_analyze(
    conn: &mut Connection,
    filename: &str,
    bytes: &[u8],
) -> rusqlite::Result<AnalyzeResult> {
    let tx_guard = conn.transaction()?;
    let mut tx = tx_guard;
    let sha = sha256_hex(bytes);
    let existing: Option<(i64, i64)> = tx
        .query_row(
            "SELECT s.id, COUNT(p.id) FROM sources s LEFT JOIN packs p ON p.source_id=s.id WHERE s.sha256=?1 AND s.filename=?2 GROUP BY s.id",
            params![sha, filename],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((source_id, child_count)) = existing {
        if child_count > 0 {
            let changed = collect_affected_for_source(&mut tx, source_id)?;
            resolve_changed(&mut tx, changed, false)?;
            return Ok(AnalyzeResult {
                source_id,
                imported: false,
                resolved: 0,
                failed: 0,
                paused: is_budget_paused(&tx)?,
                changed_oids: Vec::new(),
            });
        }
        return Err(rusqlite::Error::Other(
            format!("source {filename} was imported in an incompatible role").into(),
        ));
    }
    let kind = detect_kind(filename, bytes);
    tx.execute(
        "INSERT INTO sources(filename,kind,sha256,size,content) VALUES(?1,?2,?3,?4,?5)",
        params![filename, kind, sha, bytes.len() as i64, bytes],
    )?;
    let source_id = tx.last_insert_rowid();
    let changed = match kind {
        "pack" => import_pack(&mut tx, source_id, bytes)?,
        "index" => import_index(&mut tx, source_id, filename, bytes)?,
        "loose" => import_loose(&mut tx, source_id, filename, bytes)?,
        _ => HashSet::new(),
    };
    resolve_changed(&mut tx, changed.clone(), false)?;
    let stats = stats(&tx)?;
    tx.commit()?;
    Ok(AnalyzeResult {
        source_id,
        imported: true,
        resolved: stats.0,
        failed: stats.1,
        paused: stats.2,
        changed_oids: changed.into_iter().collect(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn detect_kind(filename: &str, bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[..4] == b"PACK" {
        "pack"
    } else if bytes.len() >= 8 && &bytes[..4] == b"\xfftOc" {
        "index"
    } else if filename.ends_with(".idx") {
        "index"
    } else if filename.ends_with(".pack") {
        "pack"
    } else {
        "loose"
    }
}

fn import_pack(tx: &mut Connection, source_id: i64, data: &[u8]) -> rusqlite::Result<HashSet<i64>> {
    let parsed = match parse_pack(data) {
        Ok(parsed) => parsed,
        Err(err) => {
            tx.execute(
                "INSERT INTO packs(source_id,version,object_count,raw_len,pack_sha1,trailer_sha1,checksum_valid,parse_error) VALUES(?1,2,0,?2,'','',0,?3)",
                params![source_id, data.len() as i64, err.to_string()],
            )?;
            return Ok(HashSet::new());
        }
    };
    tx.execute(
        "INSERT INTO packs(source_id,version,object_count,raw_len,pack_sha1,trailer_sha1,checksum_valid,parse_error) VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
        params![
            source_id,
            parsed.header.version,
            parsed.header.object_count,
            parsed.raw_len as i64,
            oid_hex(&parsed.evidence.computed_sha1),
            oid_hex(&parsed.evidence.actual_trailer),
            parsed.evidence.checksum_valid as i64,
        ],
    )?;
    let pack_id = tx.last_insert_rowid();
    let mut new_ids = HashSet::new();
    for object in &parsed.objects {
        tx.execute(
            "INSERT INTO pack_objects(pack_id,seq,offset,header_end,data_start,data_end,object_type,declared_size,payload,crc32,ofs_base_offset,ref_base_oid,parse_error) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                pack_id,
                object.index as i64,
                object.offset as i64,
                object.header_end as i64,
                object.data_start as i64,
                object.data_end as i64,
                object.kind.name(),
                object.declared_size as i64,
                object.payload,
                object.crc32 as i64,
                object.ofs_base,
                object.ref_base.map(|oid| oid_hex(&oid)),
                object.parse_error,
            ],
        )?;
        let po_id = tx.last_insert_rowid();
        let direct_base = match object.ofs_base {
            Some(base_offset) => tx.query_row(
                "SELECT id FROM candidates WHERE pack_id=?1 AND offset=?2",
                params![pack_id, base_offset],
                |row| row.get::<_, i64>(0),
            ).optional()?,
            None => None,
        };
        tx.execute(
            "INSERT INTO candidates(origin_kind,source_id,origin_table_id,pack_id,offset,input_type,payload,direct_base_candidate_id,ref_base_oid,parse_error) VALUES('pack',?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                source_id,
                po_id,
                pack_id,
                object.offset as i64,
                object.kind.name(),
                object.payload,
                direct_base,
                object.ref_base.map(|oid| oid_hex(&oid)),
                object.parse_error,
            ],
        )?;
        new_ids.insert(tx.last_insert_rowid());
    }
    for error in &parsed.object_errors {
        tx.execute(
            "UPDATE packs SET parse_error=?1 WHERE id=?2",
            params![error.message, pack_id],
        )?;
    }
    attach_existing_indexes_for_pack(tx, pack_id, source_id)?;
    Ok(new_ids)
}

fn import_index(
    tx: &mut Connection,
    source_id: i64,
    filename: &str,
    data: &[u8],
) -> rusqlite::Result<HashSet<i64>> {
    let candidate_pack = choose_pack_for_index(tx, filename, data)?;
    let pack_bytes = match candidate_pack {
        Some((_, bytes)) => Some(bytes),
        None => None,
    };
    let parsed = match parse_index(data, pack_bytes.as_deref()) {
        Ok(parsed) => parsed,
        Err(err) => {
            tx.execute(
                "INSERT INTO indexes(source_id,version,object_count,pack_checksum,index_checksum,fanout_json,parse_error) VALUES(?1,0,0,'','',?,?)",
                params![serde_json::json!([]).to_string(), err.to_string()],
            )?;
            return Ok(HashSet::new());
        }
    };
    let fanout_valid = validate_fanout(&parsed.fanout, parsed.entries.len());
    tx.execute(
        "INSERT INTO indexes(source_id,version,object_count,pack_checksum,index_checksum,fanout_json,parse_error) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            source_id,
            parsed.version,
            parsed.entries.len() as i64,
            oid_hex(&parsed.pack_checksum),
            oid_hex(&parsed.index_checksum),
            serde_json::to_string(&parsed.fanout).unwrap_or_default(),
            (!fanout_valid).then(|| "fanout table is inconsistent with sorted entries"),
        ],
    )?;
    let index_id = tx.last_insert_rowid();
    for entry in &parsed.entries {
        tx.execute(
            "INSERT INTO index_entries(index_id,oid,offset,crc32) VALUES(?1,?2,?3,?4)",
            params![
                index_id,
                oid_hex(&entry.oid),
                entry.offset as i64,
                entry.crc32.map(|value| value as i64),
            ],
        )?;
    }
    let mut matched = 0usize;
    let mut reason_parts = vec![if parsed.checksum_valid {
        "pack sha1 matches".to_string()
    } else if pack_bytes.is_some() {
        "pack sha1 mismatch".to_string()
    } else {
        "external pack missing".to_string()
    }];
    let pack_id = if let Some((pack_id, _)) = candidate_pack {
        if fanout_valid {
            for entry in &parsed.entries {
                let exists = tx.query_row(
                    "SELECT po.crc32 FROM pack_objects po WHERE po.pack_id=?1 AND po.offset=?2",
                    params![pack_id, entry.offset as i64],
                    |row| row.get::<_, Option<i64>>(0),
                ).optional()?;
                if let Some(Some(actual_crc)) = exists {
                    let crc_ok = entry.crc32.map(|c| c as i64 == actual_crc).unwrap_or(true);
                    if crc_ok {
                        matched += 1;
                    }
                }
            }
        }
        Some(pack_id)
    } else {
        None
    };
    if !fanout_valid {
        reason_parts.push("bad fanout".into());
    }
    if let Some(pack_id) = pack_id {
        let object_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM pack_objects WHERE pack_id=?1",
            params![pack_id],
            |row| row.get(0),
        )?;
        if object_count != parsed.entries.len() as i64 {
            reason_parts.push(format!(
                "entry count {} != pack objects {object_count}",
                parsed.entries.len()
            ));
        }
        tx.execute(
            "INSERT INTO index_matches(index_id,pack_id,matches,reason) VALUES(?1,?2,?3,?4)",
            params![index_id, pack_id, matched as i64, reason_parts.join("; ")],
        )?;
        apply_index_oids(tx, index_id, pack_id)?;
    } else {
        tx.execute(
            "INSERT INTO index_matches(index_id,pack_id,matches,reason) VALUES(?1,NULL,0,?2)",
            params![index_id, reason_parts.join("; ")],
        )?;
    }
    Ok(HashSet::new())
}

fn choose_pack_for_index(
    tx: &Connection,
    filename: &str,
    data: &[u8],
) -> rusqlite::Result<Option<(i64, Vec<u8>)>> {
    let mut packs: Vec<(i64, Vec<u8>)> = tx
        .prepare("SELECT p.id, s.content FROM packs p JOIN sources s ON s.id=p.source_id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    packs.sort_by_key(|(id, _)| *id);
    for (id, bytes) in &packs {
        if bytes.len() >= 20 && data.len() >= 40 {
            let trailer = &bytes[bytes.len() - 20..];
            let checksum = &data[data.len() - 40..data.len() - 20];
            if trailer == checksum {
                return Ok(Some((*id, bytes.clone())));
            }
        }
    }
    if filename.ends_with(".idx") {
        let stem = &filename[..filename.len() - 4];
        if let Some((id, bytes)) = packs.into_iter().find(|(_, bytes)| {
            bytes.starts_with(b"PACK")
        }) {
            let _ = stem;
            return Ok(Some((id, bytes)));
        }
    }
    Ok(packs.into_iter().next())
}

fn validate_fanout(fanout: &[u32], count: usize) -> bool {
    if fanout.len() != 256 || fanout[255] as usize != count {
        return false;
    }
    fanout.windows(2).all(|pair| pair[0] <= pair[1])
}

fn apply_index_oids(
    tx: &mut Connection,
    index_id: i64,
    pack_id: i64,
) -> rusqlite::Result<HashSet<i64>> {
    let mut changed = HashSet::new();
    let mut stmt = tx.prepare("SELECT oid,offset FROM index_entries WHERE index_id=?1")?;
    let entries = stmt
        .query_map(params![index_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Vec<_>>();
    for entry in entries {
        let (oid, offset) = entry?;
        let candidate_id = tx.query_row(
            "UPDATE candidates SET declared_oid=?1 WHERE pack_id=?2 AND offset=?3 RETURNING id",
            params![oid, pack_id, offset],
            |row| row.get::<_, i64>(0),
        ).optional()?;
        if let Some(id) = candidate_id {
            changed.insert(id);
        }
    }
    Ok(changed)
}

fn import_loose(
    tx: &mut Connection,
    source_id: i64,
    filename: &str,
    data: &[u8],
) -> rusqlite::Result<HashSet<i64>> {
    let declared = filename
        .rsplit('/')
        .next()
        .filter(|name| name.len() >= 38)
        .and_then(|_| {
            let clean: String = filename
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .collect();
            parse_oid(&clean)
        });
    match parse_loose(data) {
        Ok((object, consumed)) => {
            let computed = object.git_oid();
            let parse_error = if let Some(expected) = declared {
                (expected != computed).then(|| {
                    format!("declared loose oid {} != computed {}", oid_hex(&expected), oid_hex(&computed))
                })
            } else {
                None
            };
            tx.execute(
                "INSERT INTO loose_objects(source_id,object_type,declared_oid,computed_oid,payload,zlib_consumed,parse_error) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    source_id,
                    object.kind.name(),
                    declared.map(|oid| oid_hex(&oid)),
                    oid_hex(&computed),
                    object.data,
                    consumed as i64,
                    parse_error,
                ],
            )?;
            let loose_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO candidates(origin_kind,source_id,origin_table_id,declared_oid,input_type,payload,parse_error) VALUES('loose',?1,?2,?3,?4,?5,?6)",
                params![
                    source_id,
                    loose_id,
                    declared.map(|oid| oid_hex(&oid)),
                    object.kind.name(),
                    object.data,
                    parse_error,
                ],
            )?;
            Ok(HashSet::from([tx.last_insert_rowid()]))
        }
        Err(err) => {
            tx.execute(
                "INSERT INTO loose_objects(source_id,object_type,declared_oid,computed_oid,payload,zlib_consumed,parse_error) VALUES(?1,NULL,?2,NULL,NULL,NULL,?3)",
                params![source_id, declared.map(|oid| oid_hex(&oid)), err.to_string()],
            )?;
            Ok(HashSet::new())
        }
    }
}

fn attach_existing_indexes_for_pack(
    tx: &mut Connection,
    pack_id: i64,
    pack_source_id: i64,
) -> rusqlite::Result<()> {
    let pack_bytes: Vec<u8> = tx.query_row(
        "SELECT content FROM sources WHERE id=?1",
        params![pack_source_id],
        |row| row.get(0),
    )?;
    let indexes = tx
        .prepare("SELECT id,source_id FROM indexes")?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (index_id, source_id) in indexes {
        let bytes: Vec<u8> = tx.query_row("SELECT content FROM sources WHERE id=?1", params![source_id], |row| row.get(0))?;
        let parsed = match parse_index(&bytes, Some(&pack_bytes)) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        if parsed.checksum_valid && validate_fanout(&parsed.fanout, parsed.entries.len()) {
            tx.execute(
                "INSERT OR IGNORE INTO index_matches(index_id,pack_id,matches,reason) VALUES(?1,?2,?3,'matched after pack import')",
                params![index_id, pack_id, parsed.entries.len() as i64],
            )?;
            apply_index_oids(tx, index_id, pack_id)?;
        }
    }
    Ok(())
}

fn stats(conn: &Connection) -> rusqlite::Result<(usize, usize, bool)> {
    conn.query_row(
        "SELECT SUM(status='resolved'), SUM(status!='resolved' AND status!='pending'), COALESCE(MAX(value='paused'),0) FROM candidates LEFT JOIN state ON key='budget'",
        [],
        |row| Ok((row.get::<_, i64>(0)? as usize, row.get::<_, i64>(1)? as usize, row.get::<_, i64>(2)? != 0)),
    )
}

fn is_budget_paused(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(db::get_state(conn, "budget_paused", "0")? == "1")
}

fn resolve_changed(
    conn: &mut Connection,
    seed_candidates: HashSet<i64>,
    resume: bool,
) -> rusqlite::Result<()> {
    let budget = load_budget(conn)?;
    if budget.paused && !resume {
        return Ok(());
    }
    let mut affected = seed_candidates.clone();
    affected.extend(collect_direct_reverse(conn, &seed_candidates)?);
    let seed_oids = oids_of_candidates(conn, &seed_candidates)?;
    affected.extend(candidates_referring_oids(conn, &seed_oids)?);
    let pinned_oids = pinned_oid_set(conn)?;
    invalidate_candidates(conn, &affected, &pinned_oids)?;
    if resume {
        let paused = paused_candidate_ids(conn)?;
        affected.extend(paused);
    }
    if load_budget(conn)?.paused && !resume {
        return Ok(());
    }
    let candidates = load_candidates(conn)?;
    let start_set = if resume {
        candidates
            .values()
            .filter(|candidate| candidate.status == CandidateStatus::Pending || candidate.status == CandidateStatus::BudgetPaused)
            .map(|candidate| candidate.id)
            .collect()
        } else {
            affected
        };
    let mut solver = Solver {
        conn,
        candidates,
        stack: Vec::new(),
        done: HashMap::new(),
        budget,
        affected: Default::default(),
    };
    let mut order = start_set.into_iter().collect::<Vec<_>>();
    order.sort_by_key(|id| {
        let candidate = solver.candidates.get(id).expect("candidate");
        candidate_rank(candidate)
    });
    for id in order {
        if solver.done.contains_key(&id) {
            continue;
        }
        let result = solver.resolve(id);
        solver.persist(id, result);
    }
    let paused = solver.budget.paused;
    db::set_state(solver.conn, "budget_paused", if paused { "1" } else { "0" })?;
    db::set_state(
        solver.conn,
        "budget_bytes_used",
        &solver.budget.bytes_used.to_string(),
    )?;
    reconcile_objects(&mut solver.conn)?;
    Ok(())
}

fn collect_direct_reverse(
    conn: &Connection,
    seeds: &HashSet<i64>,
) -> rusqlite::Result<HashSet<i64>> {
    let mut result = seeds.clone();
    let mut frontier = seeds.clone();
    loop {
        if frontier.is_empty() {
            return Ok(result);
        }
        let mut next = HashSet::new();
        let mut stmt = conn.prepare("SELECT id FROM candidates WHERE direct_base_candidate_id IN rarray(?1)")?;
        let _ = stmt;
        for base_id in frontier.drain() {
            let mut stmt = conn.prepare(
                "SELECT id FROM candidates WHERE direct_base_candidate_id=?1",
            )?;
            let ids = stmt.query_map(params![base_id], |row| row.get::<_, i64>(0))?;
            for id in ids {
                let id = id?;
                if result.insert(id) {
                    next.insert(id);
                }
            }
        }
        frontier = next;
    }
}

fn oids_of_candidates(
    conn: &Connection,
    ids: &HashSet<i64>,
) -> rusqlite::Result<HashSet<[u8; 20]>> {
    let mut oids = HashSet::new();
    for id in ids {
        let mut stmt = conn.prepare("SELECT declared_oid,resolved_oid FROM candidates WHERE id=?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            for column in 0..2 {
                if let Some(text) = row.get::<_, Option<String>>(column)? {
                    if let Some(oid) = parse_oid(&text) {
                        oids.insert(oid);
                    }
                }
            }
        }
    }
    Ok(oids)
}

fn candidates_referring_oids(
    conn: &Connection,
    oids: &HashSet<[u8; 20]>,
) -> rusqlite::Result<HashSet<i64>> {
    let mut result = HashSet::new();
    for oid in oids {
        let text = oid_hex(oid);
        let mut stmt = conn.prepare(
            "SELECT id FROM candidates WHERE ref_base_oid=?1 OR declared_oid=?1 OR resolved_oid=?1",
        )?;
        let ids = stmt.query_map(params![text], |row| row.get::<_, i64>(0))?;
        for id in ids {
            result.insert(id?);
        }
    }
    Ok(result)
}

fn pinned_oid_set(conn: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT oid FROM pins")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

fn invalidate_candidates(
    conn: &mut Connection,
    ids: &HashSet<i64>,
    pinned_oids: &HashSet<String>,
) -> rusqlite::Result<()> {
    for id in ids {
        let pinned_declared: Option<String> = conn.query_row(
            "SELECT declared_oid FROM candidates WHERE id=?1",
            params![id],
            |row| row.get(0),
        )?;
        if pinned_declared
            .as_deref()
            .map(|oid| pinned_oids.contains(oid))
            .unwrap_or(false)
        {
            continue;
        }
        conn.execute(
            "UPDATE candidates SET status='pending',resolved_oid=NULL,resolved_type=NULL,depth=NULL,expansion_ratio=NULL,chosen_base_candidate_id=NULL,error=NULL,blocking_chain_json=NULL,updated_at=datetime('now') WHERE id=?1",
            params![id],
        )?;
        conn.execute("DELETE FROM delta_steps WHERE candidate_id=?1", params![id])?;
    }
    let oid_texts: HashSet<String> = ids
        .iter()
        .filter_map(|_| None)
        .collect();
    let _ = oid_texts;
    Ok(())
}

fn paused_candidate_ids(conn: &Connection) -> rusqlite::Result<HashSet<i64>> {
    let mut stmt = conn.prepare("SELECT id FROM candidates WHERE status='budget_paused'")?;
    let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
    rows.collect()
}

fn load_budget(conn: &Connection) -> rusqlite::Result<Budget> {
    let mut budget = default_budget();
    budget.max_depth = db::get_state(conn, "max_depth", "16")?.parse().unwrap_or(16);
    budget.max_total_bytes = db::get_state(conn, "max_total_bytes", "268435456")?
        .parse()
        .unwrap_or(256 * 1024 * 1024);
    budget.max_single_ratio = db::get_state(conn, "max_single_ratio", "32")?
        .parse()
        .unwrap_or(32);
    budget.bytes_used = db::get_state(conn, "budget_bytes_used", "0")?
        .parse()
        .unwrap_or(0);
    budget.paused = db::get_state(conn, "budget_paused", "0")? == "1";
    Ok(budget)
}

fn load_candidates(conn: &mut Connection) -> rusqlite::Result<HashMap<i64, CandidateRow>> {
    let mut map = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT c.id,c.origin_kind,c.source_id,s.sha256,s.filename,c.pack_id,c.offset,c.input_type,c.payload,c.direct_base_candidate_id,c.ref_base_oid,c.declared_oid,c.parse_error,c.status,CASE WHEN p.oid IS NULL THEN 0 ELSE 1 END
         FROM candidates c JOIN sources s ON s.id=c.source_id LEFT JOIN pins p ON p.oid=c.declared_oid",
    )?;
    let rows = stmt.query_map([], |row| {
        let ref_base_text: Option<String> = row.get(10)?;
        let declared_text: Option<String> = row.get(11)?;
        Ok(CandidateRow {
            id: row.get(0)?,
            origin_kind: row.get(1)?,
            source_id: row.get(2)?,
            source_sha: row.get(3)?,
            filename: row.get(4)?,
            pack_id: row.get(5)?,
            offset: row.get(6)?,
            input_type: row.get(7)?,
            payload: row.get(8)?,
            direct_base_candidate_id: row.get(9)?,
            ref_base_oid: ref_base_text.and_then(|text| parse_oid(&text)),
            declared_oid: declared_text.and_then(|text| parse_oid(&text)),
            parse_error: row.get(12)?,
            status: CandidateStatus::parse(&row.get::<_, String>(13)?),
            pinned: row.get::<_, i64>(14)? != 0,
        })
    })?;
    for row in rows {
        let candidate = row?;
        map.insert(candidate.id, candidate);
    }
    Ok(map)
}

fn candidate_rank(candidate: &CandidateRow) -> (i64, String, String, i64, i64) {
    (
        if candidate.pinned { 0 } else { 1 },
        candidate.source_sha.clone(),
        candidate.filename.clone(),
        candidate.pack_id.unwrap_or(0),
        candidate.offset.unwrap_or(0),
    )
}

fn parse_input_type(name: &str) -> Option<ObjectType> {
    match name {
        "commit" => Some(ObjectType::Commit),
        "tree" => Some(ObjectType::Tree),
        "blob" => Some(ObjectType::Blob),
        "tag" => Some(ObjectType::Tag),
        _ => None,
    }
}

impl<'a> Solver<'a> {
    fn resolve(&mut self, id: i64) -> Result<Resolved, ResolveError> {
        if let Some(result) = self.done.get(&id) {
            return result.clone();
        }
        if self.stack.contains(&id) {
            return Err(ResolveError::Cycle);
        }
        let candidate = self.candidates.get(&id).cloned().expect("candidate row");
        if let Some(parse_error) = candidate.parse_error.clone() {
            return Err(ResolveError::Bad(parse_error));
        }
        let kind = parse_input_type(&candidate.input_type);
        self.stack.push(id);
        let result = match kind {
            Some(kind) => {
                let object = GitObject::new(kind, candidate.payload.clone());
                let oid = object.git_oid();
                if candidate.declared_oid.is_some_and(|declared| declared != oid) {
                    Err(ResolveError::Bad(format!(
                        "recomputed object id {} differs from indexed/declared id {}",
                        oid_hex(&oid),
                        oid_hex(&candidate.declared_oid.unwrap())
                    )))
                } else {
                    self.charge_output(object.data.len())?;
                    Ok(Resolved {
                        oid,
                        kind,
                        data: object.data,
                        depth: 0,
                        ratio: 1,
                        base_candidate_id: None,
                    })
                }
            }
            None => self.resolve_delta(&candidate),
        };
        self.stack.pop();
        self.done.insert(id, result.clone());
        result
    }

    fn resolve_delta(&mut self, candidate: &CandidateRow) -> Result<Resolved, ResolveError> {
        let depth_hint = self.stack.len();
        if depth_hint + 1 > self.budget.max_depth {
            return Err(ResolveError::Depth);
        }
        let base_id = self.choose_base(candidate)?;
        let base = self.resolve(base_id)?;
        if candidate.input_type == ObjectType::OfsDelta.name()
            && candidate.direct_base_candidate_id != Some(base_id)
        {
            return Err(ResolveError::Bad(
                "ofs-delta must resolve to its object-offset predecessor".into(),
            ));
        }
        let applied = apply_delta(&base.data, &candidate.payload).map_err(|err| {
            if matches!(err, git::GitError::SizeMismatch { .. }) {
                ResolveError::Bad(err.to_string())
            } else {
                ResolveError::Bad(err.to_string())
            }
        })?;
        let ratio = (applied.output.len() + base.data.len().max(1) - 1) / base.data.len().max(1);
        let chain_ratio = base.ratio.max(ratio);
        if chain_ratio > self.budget.max_single_ratio {
            return Err(ResolveError::Ratio);
        }
        self.charge_output(applied.output.len())?;
        let output_type = base.kind;
        let object = GitObject::new(output_type, applied.output.clone());
        let oid = object.git_oid();
        let mut ops_json = Vec::new();
        for op in &applied.ops {
            ops_json.push(serde_json::json!({
                "index": op.index,
                "kind": op.kind,
                "offset": op.offset,
                "length": op.length,
                "src_offset": op.src_offset,
                "dst_offset": op.dst_offset,
                "size": op.size,
            }));
        }
        self.persist_delta_step(
            candidate.id,
            base_id,
            &base,
            candidate.payload.len(),
            applied.output.len(),
            serde_json::to_string(&ops_json).unwrap_or_else(|_| "[]".into()),
            None,
        )?;
        Ok(Resolved {
            oid,
            kind: output_type,
            data: applied.output,
            depth: base.depth + 1,
            ratio: chain_ratio,
            base_candidate_id: Some(base_id),
        })
    }

    fn choose_base(&mut self, candidate: &CandidateRow) -> Result<i64, ResolveError> {
        if let Some(direct) = candidate.direct_base_candidate_id {
            if self.candidates.contains_key(&direct) {
                return Ok(direct);
            }
            return Err(ResolveError::MissingBase(format!(
                "ofs base candidate {direct} is absent"
            )));
        }
        let target = candidate
            .ref_base_oid
            .ok_or_else(|| ResolveError::Bad("delta lacks base reference".into()))?;
        let mut options = self
            .candidates
            .values()
            .filter(|other| other.declared_oid == Some(target))
            .cloned()
            .collect::<Vec<_>>();
        if options.is_empty() {
            return Err(ResolveError::MissingBase(format!(
                "external base {} is unavailable",
                oid_hex(&target)
            )));
        }
        options.sort_by_key(candidate_rank);
        for option in options {
            if self.stack.contains(&option.id) {
                continue;
            }
            match self.resolve(option.id) {
                Ok(_) => return Ok(option.id),
                Err(ResolveError::Cycle) => continue,
                Err(other) => {
                    if option.pinned {
                        return Err(other);
                    }
                    continue;
                }
            }
        }
        Err(ResolveError::MissingBase(format!(
            "no usable duplicate source for {}",
            oid_hex(&target)
        )))
    }

    fn charge_output(&mut self, len: usize) -> Result<(), ResolveError> {
        if self.budget.bytes_used + len > self.budget.max_total_bytes {
            self.budget.paused = true;
            return Err(ResolveError::BudgetBytes);
        }
        self.budget.bytes_used += len;
        Ok(())
    }
}

impl<'a> Solver<'a> {
    fn persist(&mut self, id: i64, result: Result<Resolved, ResolveError>) {
        if self.persist_inner(id, result).is_err() {
            self.budget.paused = true;
        }
    }

    fn persist_inner(
        &mut self,
        id: i64,
        result: Result<Resolved, ResolveError>,
    ) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM delta_steps WHERE candidate_id=?1", params![id])?;
        match result {
            Ok(resolved) => {
                self.conn.execute(
                    "UPDATE candidates SET status='resolved',resolved_oid=?1,resolved_type=?2,depth=?3,expansion_ratio=?4,chosen_base_candidate_id=?5,error=NULL,blocking_chain_json=NULL,updated_at=datetime('now') WHERE id=?6",
                    params![
                        oid_hex(&resolved.oid),
                        resolved.kind.name(),
                        resolved.depth as i64,
                        resolved.ratio as i64,
                        resolved.base_candidate_id,
                        id,
                    ],
                )?;
            }
            Err(error) => {
                let status = match &error {
                    ResolveError::MissingBase(_) => CandidateStatus::MissingBase,
                    ResolveError::Cycle => CandidateStatus::Cycle,
                    ResolveError::BudgetBytes => CandidateStatus::BudgetPaused,
                    ResolveError::Depth => CandidateStatus::BudgetPaused,
                    ResolveError::Ratio => CandidateStatus::BudgetPaused,
                    ResolveError::Bad(_) => CandidateStatus::BadObject,
                };
                let chain = self.blocking_chain(id, &error);
                self.conn.execute(
                    "UPDATE candidates SET status=?1,resolved_oid=NULL,resolved_type=NULL,depth=?2,expansion_ratio=NULL,chosen_base_candidate_id=NULL,error=?3,blocking_chain_json=?4,updated_at=datetime('now') WHERE id=?5",
                    params![
                        status.as_str(),
                        self.stack.len() as i64,
                        error.message(),
                        serde_json::to_string(&chain).unwrap_or_else(|_| "[]".into()),
                        id,
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn blocking_chain(&self, id: i64, error: &ResolveError) -> Vec<BlockedChain> {
        let candidate = self.candidates.get(&id);
        let mut path = self
            .stack
            .iter()
            .filter(|stack_id| **stack_id != id)
            .map(|stack_id| self.describe_candidate(*stack_id))
            .collect::<Vec<_>>();
        if let Some(candidate) = candidate {
            path.push(self.describe_candidate(candidate.id));
            if let Some(base) = candidate.direct_base_candidate_id {
                path.push(format!("ofs:{base}"));
            } else if let Some(oid) = candidate.ref_base_oid {
                path.push(oid_hex(&oid));
            }
        }
        vec![BlockedChain {
            candidate_id: id,
            path,
            reason: error.message().to_string(),
        }]
    }

    fn describe_candidate(&self, id: i64) -> String {
        self.candidates
            .get(&id)
            .map(|candidate| {
                candidate
                    .declared_oid
                    .map(|oid| oid_hex(&oid))
                    .unwrap_or_else(|| {
                        format!(
                            "{}#{}@{}",
                            candidate.filename,
                            candidate.origin_kind,
                            candidate.offset.unwrap_or(0)
                        )
                    })
            })
            .unwrap_or_else(|| format!("candidate:{id}"))
    }

    fn persist_delta_step(
        &mut self,
        candidate_id: i64,
        base_id: i64,
        base: &Resolved,
        delta_len: usize,
        output_len: usize,
        ops_json: String,
        error: Option<String>,
    ) -> rusqlite::Result<()> {
        let seq: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(seq)+1,0) FROM delta_steps WHERE candidate_id=?1",
                params![candidate_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO delta_steps(candidate_id,seq,base_candidate_id,base_oid,base_type,delta_start,delta_end,input_len,output_len,check_valid,ops_json,error) VALUES(?1,?2,?3,?4,?5,0,?6,?7,?8,?9,?10,?11)",
            params![
                candidate_id,
                seq,
                base_id,
                oid_hex(&base.oid),
                base.kind.name(),
                delta_len as i64,
                base.data.len() as i64,
                output_len as i64,
                error.is_none() as i64,
                ops_json,
                error,
            ],
        )?;
        Ok(())
    }
}

impl ResolveError {
    fn message(&self) -> String {
        match self {
            ResolveError::Bad(message) => message.clone(),
            ResolveError::MissingBase(message) => message.clone(),
            ResolveError::Cycle => "delta dependency cycle".into(),
            ResolveError::Depth => "delta depth budget reached".into(),
            ResolveError::BudgetBytes => "total expanded byte budget reached".into(),
            ResolveError::Ratio => "single-object expansion ratio budget reached".into(),
        }
    }
}

fn reconcile_objects(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM resolved_objects", [])?;
    let mut stmt = conn.prepare(
        "SELECT resolved_oid,id,resolved_type,payload,depth,expansion_ratio
         FROM candidates
         WHERE status='resolved' AND resolved_oid IS NOT NULL
         ORDER BY resolved_oid,
                  CASE WHEN declared_oid=resolved_oid THEN 0 ELSE 1 END,
                  (SELECT CASE WHEN pins.oid IS NULL THEN 1 ELSE 0 END FROM pins WHERE pins.oid=resolved_oid),
                  (SELECT s.sha256 FROM sources s WHERE s.id=candidates.source_id),
                  filename, pack_id, offset",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    drop(stmt);
    for (oid, candidate_id, typ, payload, depth, ratio) in entries {
        if seen.insert(oid.clone()) {
            conn.execute(
                "INSERT INTO resolved_objects(oid,candidate_id,object_type,payload,depth,expansion_ratio) VALUES(?1,?2,?3,?4,?5,?6)",
                params![oid, candidate_id, typ, payload, depth, ratio],
            )?;
        }
    }
    Ok(())
}
