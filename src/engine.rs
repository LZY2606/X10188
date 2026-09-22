//! 解析引擎: 在预算约束下还原 delta DAG, 隔离坏对象, 支持暂停/恢复与局部重算。

use crate::delta::{self, DeltaInstr};
use crate::oid;
use crate::store::{self, StepForStore, Store};
use crate::zutil;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_object_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 64,
            max_total_bytes: 64 * 1024 * 1024,
            max_object_ratio: 0.5,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum UnitKey {
    Entry(i64),
    Loose(i64),
}

impl UnitKey {
    fn kind_str(self) -> &'static str {
        match self {
            UnitKey::Entry(_) => "entry",
            UnitKey::Loose(_) => "loose",
        }
    }
    fn id(self) -> i64 {
        match self {
            UnitKey::Entry(v) | UnitKey::Loose(v) => v,
        }
    }
}

#[derive(Clone, Debug)]
struct StepRec {
    base_kind: String,
    base_desc: String,
    base_candidate_id: Option<i64>,
    instrs: Vec<DeltaInstr>,
    input_len: u64,
    output_len: u64,
}

#[derive(Clone)]
struct Resolved {
    oid: oid::Oid,
    kind: String,
    content: Vec<u8>,
    candidate_id: i64,
    steps: Vec<StepRec>,
    depth: u32,
    expanded: u64,
}

enum Block {
    MissingBase(String),
    BaseBlocked(String, Option<i64>),
    Cycle(Vec<i64>),
    Permanent(String, String),
    Budget(String),
}

pub enum RunOutcome {
    Complete,
    Paused(String),
}

pub struct Engine {
    pub store: Store,
    pub budget: Budget,
}

impl Engine {
    pub fn open(data_dir: &Path, budget: Budget) -> Result<Engine, String> {
        let store = Store::open(data_dir)?;
        Ok(Engine { store, budget })
    }

    pub fn import_and_run(&mut self, name: &str, bytes: &[u8]) -> Result<ImportSummary, String> {
        let (source_id, kind) = self.store.add_source(name, bytes)?;
        let run = self.run()?;
        Ok(ImportSummary {
            source_id,
            kind,
            state: match run {
                RunOutcome::Complete => "complete".to_string(),
                RunOutcome::Paused(_) => "paused".to_string(),
            },
        })
    }

    /// 主循环: 只处理 pending/blocked/paused 候选, 已还原对象绝不重算。
    pub fn run(&mut self) -> Result<RunOutcome, String> {
        self.sync_units();
        self.cross_check_indexes();

        let mut expanded_run: u64 = 0;
        let pending = self.store.actionable_candidates();
        let mut pass_cache: HashMap<UnitKey, Resolved> = HashMap::new();
        let mut processed = 0usize;

        for cand in pending {
            let key = UnitKey::from_candidate(&cand);
            let mut visiting = Vec::new();
            let mut object_expanded: u64 = 0;
            match self.resolve(key, &mut visiting, 0, &mut expanded_run, &mut object_expanded, &mut pass_cache) {
                Ok(_) => {
                    processed += 1;
                }
                Err(Block::Budget(reason)) => {
                    self.store.set_candidate_status(
                        key.kind_str(),
                        key.id(),
                        "paused",
                        Some(&reason),
                    );
                    self.store.set_engine_state(
                        "paused",
                        &format!("budget exhausted: {reason} (retry with larger budget)"),
                        expanded_run as i64,
                    );
                    return Ok(RunOutcome::Paused(reason));
                }
                Err(Block::MissingBase(base_oid)) => {
                    self.record_blocked(key, &format!("missing base {base_oid}"),
                        vec![(format!("oid:{base_oid}"), "missing external base".to_string())]);
                }
                Err(Block::BaseBlocked(desc, base_cand)) => {
                    let mut blocks = Vec::new();
                    if let Some(bid) = base_cand {
                        blocks.push((format!("candidate:{bid}"), format!("base blocked: {desc}")));
                    } else {
                        blocks.push((format!("unknown:{desc}"), "base blocked".to_string()));
                    }
                    self.record_blocked(key, &format!("base blocked: {desc}"), blocks);
                }
                Err(Block::Cycle(chain)) => {
                    let chain_hex = chain
                        .iter()
                        .map(|id| {
                            self.store
                                .candidate_by_id(*id)
                                .and_then(|c| c.oid.clone())
                                .unwrap_or_else(|| format!("candidate#{id}"))
                        })
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    let msg = format!("delta cycle detected: {chain_hex}");
                    self.fail(key, "delta_cycle", &msg, &msg);
                }
                Err(Block::Permanent(kind, msg)) => {
                    self.fail(key, &kind, &msg, &msg);
                }
            }
            if expanded_run > self.budget.max_total_bytes {
                let reason = format!(
                    "run expansion budget {} bytes exceeded",
                    self.budget.max_total_bytes
                );
                self.store.set_engine_state(
                    "paused",
                    &format!("budget exhausted: {reason} (retry with larger budget)"),
                    expanded_run as i64,
                );
                return Ok(RunOutcome::Paused(reason));
            }
        }

        self.store
            .set_engine_state("complete", "", expanded_run as i64);
        let _ = processed;
        Ok(RunOutcome::Complete)
    }

    fn sync_units(&self) {
        for e in self.store.all_entries() {
            self.store.ensure_candidate("entry", e.id);
        }
        for l in self.store.all_loose() {
            self.store.ensure_candidate("loose", l.id);
        }
    }

    /// index 与 pack 不配套: idx 中存在但任何 pack 都没有的原始偏移。
    fn cross_check_indexes(&self) {
        self.store.clear_errors_scope("xcheck");
        let offsets: HashSet<i64> = self
            .store
            .all_entries()
            .iter()
            .map(|e| e.offset)
            .collect();
        for (index_id, oid_hex, _crc, offset) in self.store.all_index_entries() {
            if !offsets.contains(&offset) {
                self.store.add_error(
                    "xcheck",
                    index_id,
                    "index_offset_unmatched",
                    &format!("index maps {oid_hex} to offset {offset}, but no pack entry exists there"),
                    &serde_json::json!({"oid": oid_hex, "offset": offset}).to_string(),
                );
            }
        }
    }

    fn record_blocked(&self, key: UnitKey, msg: &str, blocks: Vec<(String, String)>) {
        let cid = self.store.candidate(key.kind_str(), key.id()).map(|c| c.id);
        if let Some(cid) = cid {
            self.store.replace_blocks(cid, &blocks);
            self.store.clear_steps_for(cid);
            self.store
                .conn
            .execute(
                "DELETE FROM errors_log WHERE scope='candidate' AND ref_id=?1",
                rusqlite::params![cid],
            )
            .ok();
        }
        self.store
            .set_candidate_status(key.kind_str(), key.id(), "blocked", Some(msg));
    }

    fn fail(&self, key: UnitKey, kind: &str, msg: &str, evidence: &str) {
        let cid = self.store.candidate(key.kind_str(), key.id()).map(|c| c.id);
        if let Some(cid) = cid {
            self.store.replace_blocks(cid, &[]);
            self.store.clear_steps_for(cid);
            self.store
                .add_error("candidate", cid, kind, msg, evidence);
        }
        self.store
            .set_candidate_status(key.kind_str(), key.id(), "error", Some(msg));
    }
}

#[derive(Clone, Debug)]
pub struct ImportSummary {
    pub source_id: i64,
    pub kind: String,
    pub state: String,
}

impl UnitKey {
    fn from_candidate(c: &store::CandidateRow) -> UnitKey {
        match c.unit_kind.as_str() {
            "loose" => UnitKey::Loose(c.unit_id),
            _ => UnitKey::Entry(c.unit_id),
        }
    }
}

struct Ctx<'a> {
    eng: &'a Engine,
    expanded_run: &'a mut u64,
    object_expanded: &'a mut u64,
    cache: &'a mut HashMap<UnitKey, Resolved>,
}

impl Engine {
    fn resolve(
        &self,
        key: UnitKey,
        visiting: &mut Vec<i64>,
        depth: u32,
        expanded_run: &mut u64,
        object_expanded: &mut u64,
        cache: &mut HashMap<UnitKey, Resolved>,
    ) -> Result<Resolved, Block> {
        let mut ctx = Ctx {
            eng: self,
            expanded_run,
            object_expanded,
            cache,
        };
        self.resolve_in_ctx(key, &mut ctx, visiting, depth)
    }

    fn cid_of(&self, key: UnitKey) -> i64 {
        self.store
            .candidate(key.kind_str(), key.id())
            .map(|c| c.id)
            .unwrap_or_else(|| -(key.id()))
    }

    fn charge(&self, ctx: &mut Ctx, amount: u64, what: &str) -> Result<(), Block> {
        *ctx.expanded_run += amount;
        *ctx.object_expanded += amount;
        if *ctx.expanded_run > self.budget.max_total_bytes {
            return Err(Block::Budget(format!(
                "total expansion budget {} bytes exceeded while {what}",
                self.budget.max_total_bytes
            )));
        }
        let single_limit = (self.budget.max_total_bytes as f64 * self.budget.max_object_ratio) as u64;
        if *ctx.object_expanded > single_limit {
            return Err(Block::Budget(format!(
                "single object expanded {} bytes > ratio limit {} while {what}",
                *ctx.object_expanded, single_limit
            )));
        }
        Ok(())
    }

    fn resolve_in_ctx(
        &self,
        key: UnitKey,
        ctx: &mut Ctx,
        visiting: &mut Vec<i64>,
        depth: u32,
    ) -> Result<Resolved, Block> {
        if let Some(r) = ctx.cache.get(&key) {
            return Ok(r.clone());
        }
        if let Some(c) = self.store.candidate(key.kind_str(), key.id()) {
            if c.status == "ok" {
                return Ok(Resolved {
                    oid: oid::from_hex(c.oid.as_deref().unwrap_or("")).unwrap_or([0u8; 20]),
                    kind: c.kind.unwrap_or_default(),
                    content: c.content.unwrap_or_default(),
                    candidate_id: c.id,
                    steps: Vec::new(),
                    depth: c.depth as u32,
                    expanded: c.expanded as u64,
                });
            }
        }
        if depth > self.budget.max_depth {
            return Err(Block::Budget(format!(
                "delta depth {} exceeds limit {}",
                depth, self.budget.max_depth
            )));
        }
        let cid = self.cid_of(key);
        if visiting.contains(&cid) {
            let mut chain: Vec<i64> = visiting
                .iter()
                .copied()
                .skip_while(|v| *v != cid)
                .collect();
            chain.push(cid);
            return Err(Block::Cycle(chain));
        }
        visiting.push(cid);
        let result = match key {
            UnitKey::Loose(loose_id) => self.resolve_loose(loose_id, ctx, visiting, depth),
            UnitKey::Entry(entry_id) => self.resolve_entry(entry_id, ctx, visiting, depth),
        };
        visiting.pop();
        if let Ok(ref r) = result {
            ctx.cache.insert(key, r.clone());
        }
        result
    }

    fn pack_bytes(&self, source_id: i64, cache: &mut HashMap<i64, Vec<u8>>) -> Result<Vec<u8>, Block> {
        if let Some(b) = cache.get(&source_id) {
            return Ok(b.clone());
        }
        let bytes = self
            .store
            .source_bytes(source_id)
            .map_err(|e| Block::Permanent("source_read".into(), e))?;
        cache.insert(source_id, bytes.clone());
        Ok(bytes)
    }

    fn inflate_entry(
        &self,
        e: &store::EntryRow,
        cache: &mut HashMap<i64, Vec<u8>>,
    ) -> Result<Vec<u8>, Block> {
        let bytes = self.pack_bytes(e.source_id, cache)?;
        let start = e.data_start as usize;
        if start >= bytes.len() {
            return Err(Block::Permanent(
                "offset_out_of_bounds".into(),
                format!("entry data_start {start} beyond pack size {}", bytes.len()),
            ));
        }
        let inf = zutil::inflate_bounded(&bytes[start..])
            .map_err(|err| Block::Permanent("bad_zlib".into(), err))?;
        if inf.consumed as i64 != e.data_len {
            return Err(Block::Permanent(
                "zlib_boundary".into(),
                format!(
                    "zlib consumed {} bytes but index recorded {} at offset {}",
                    inf.consumed, e.data_len, e.offset
                ),
            ));
        }
        Ok(inf.data)
    }

    fn resolve_loose(
        &self,
        loose_id: i64,
        ctx: &mut Ctx,
        _visiting: &mut Vec<i64>,
        depth: u32,
    ) -> Result<Resolved, Block> {
        let loose = self
            .store
            .loose_by_id(loose_id)
            .ok_or_else(|| Block::Permanent("missing_unit".into(), format!("loose {loose_id}")))?;
        let bytes = self
            .store
            .source_bytes(loose.source_id)
            .map_err(|e| Block::Permanent("source_read".into(), e))?;
        let (kind, content) =
            store::parse_loose(&bytes).map_err(|m| Block::Permanent("bad_loose".into(), m))?;
        self.charge(ctx, content.len() as u64, "inflating loose object")?;
        let oid_value = oid::object_id(&kind, &content);
        let cid = self.store.set_candidate_ok(
            "loose",
            loose_id,
            &oid::to_hex(&oid_value),
            &kind,
            &content,
            depth as i64,
            *ctx.object_expanded as i64,
        );
        self.store.replace_steps(cid, &[]);
        Ok(Resolved {
            oid: oid_value,
            kind,
            content,
            candidate_id: cid,
            steps: Vec::new(),
            depth,
            expanded: *ctx.object_expanded,
        })
    }

    fn resolve_entry(
        &self,
        entry_id: i64,
        ctx: &mut Ctx,
        visiting: &mut Vec<i64>,
        depth: u32,
    ) -> Result<Resolved, Block> {
        let e = self
            .store
            .entry_by_id(entry_id)
            .ok_or_else(|| Block::Permanent("missing_unit".into(), format!("entry {entry_id}")))?;

        if !e.size_ok {
            return Err(Block::Permanent(
                "size_spoof".into(),
                format!(
                    "entry @ {} declares size {} but zlib payload has {} bytes",
                    e.offset, e.declared_size, e.data_len
                ),
            ));
        }

        let mut pack_cache: HashMap<i64, Vec<u8>> = HashMap::new();
        let inflated = self.inflate_entry(&e, &mut pack_cache)?;
        self.charge(ctx, inflated.len() as u64, "inflating pack object")?;

        let (kind, content, steps) = match e.kind.as_str() {
            "blob" | "tree" | "commit" | "tag" => (e.kind.clone(), inflated, Vec::new()),
            "ofs_delta" => {
                let outcome = self.resolve_ofs(&e, &inflated, ctx, visiting, depth, &mut pack_cache)?;
                outcome
            }
            "ref_delta" => {
                let outcome = self.resolve_ref(&e, &inflated, ctx, visiting, depth, &mut pack_cache)?;
                outcome
            }
            other => {
                return Err(Block::Permanent(
                    "unknown_type".into(),
                    format!("entry @ {} has unknown type {other}", e.offset),
                ))
            }
        };

        let oid_value = oid::object_id(&kind, &content);
        let oid_hex = oid::to_hex(&oid_value);

        // 用 index 校验: oid 与 CRC32。
        for (idx_oid, idx_crc, _idx_id) in self.store.index_entries_at_offset(e.offset) {
            if idx_oid != oid_hex {
                return Err(Block::Permanent(
                    "oid_mismatch".into(),
                    format!(
                        "entry @ {} recomputed oid {oid_hex} but index claims {idx_oid}",
                        e.offset
                    ),
                ));
            }
            if idx_crc != e.crc32 {
                return Err(Block::Permanent(
                    "crc_mismatch".into(),
                    format!(
                        "entry @ {} CRC32 mismatch: pack bytes {:#010x} vs index {idx_crc:#010x}",
                        e.offset, e.crc32
                    ),
                ));
            }
        }

        let cid = self.store.set_candidate_ok(
            "entry",
            entry_id,
            &oid_hex,
            &kind,
            &content,
            depth as i64,
            *ctx.object_expanded as i64,
        );
        let store_steps: Vec<StepForStore> = steps
            .iter()
            .map(|s| StepForStore {
                base_kind: s.base_kind.clone(),
                base_desc: s.base_desc.clone(),
                base_candidate_id: s.base_candidate_id,
                instr_json: serde_json::to_string(&s.instrs).unwrap_or_default(),
                input_len: s.input_len as i64,
                output_len: s.output_len as i64,
                verified: true,
                error: None,
            })
            .collect();
        self.store.replace_steps(cid, &store_steps);

        Ok(Resolved {
            oid: oid_value,
            kind,
            content,
            candidate_id: cid,
            steps,
            depth,
            expanded: *ctx.object_expanded,
        })
    }

    fn apply_delta_step(
        &self,
        base: &Resolved,
        delta_data: &[u8],
        base_kind: &str,
        base_desc: &str,
        ctx: &mut Ctx,
    ) -> Result<(String, Vec<u8>, StepRec, u32), Block> {
        let applied = delta::apply_delta(&base.content, delta_data)
            .map_err(|m| Block::Permanent("bad_delta".into(), m))?;
        self.charge(ctx, applied.out.len() as u64, "applying delta output")?;
        let own_depth = base.depth + 1;
        let step = StepRec {
            base_kind: base_kind.to_string(),
            base_desc: base_desc.to_string(),
            base_candidate_id: Some(base.candidate_id),
            instrs: applied.instrs,
            input_len: delta_data.len() as u64,
            output_len: applied.out.len() as u64,
        };
        Ok((base.kind.clone(), applied.out, step, own_depth))
    }

    fn resolve_ofs(
        &self,
        e: &store::EntryRow,
        delta_data: &[u8],
        ctx: &mut Ctx,
        visiting: &mut Vec<i64>,
        depth: u32,
        pack_cache: &mut HashMap<i64, Vec<u8>>,
    ) -> Result<(String, Vec<u8>, Vec<StepRec>), Block> {
        let _ = pack_cache;
        let dist = e
            .ofs_dist
            .ok_or_else(|| Block::Permanent("bad_ofs".into(), "ofs-delta without distance".into()))?;
        let base_offset = match e.base_offset {
            Some(v) => v,
            None => {
                return Err(Block::Permanent(
                    "ofs_distance_out_of_bounds".into(),
                    format!(
                        "ofs-delta @ {} points {dist} bytes backwards, before pack start",
                        e.offset
                    ),
                ))
            }
        };
        let base_entry = self
            .store
            .entry_in_pack_at_offset(e.pack_id, base_offset)
            .ok_or_else(|| {
                Block::Permanent(
                    "ofs_distance_out_of_bounds".into(),
                    format!(
                        "ofs-delta @ {} base offset {base_offset} (dist {dist}) has no entry",
                        e.offset
                    ),
                )
            })?;
        let base = self.resolve_in_ctx(
            UnitKey::Entry(base_entry.id),
            ctx,
            visiting,
            depth + 1,
        )?;
        let desc = format!("ofs @{} (-{})", base_offset, dist);
        let (kind, content, step, _own_depth) =
            self.apply_delta_step(&base, delta_data, "ofs", &desc, ctx)?;
        Ok((kind, content, vec![step]))
    }

    fn resolve_ref(
        &self,
        e: &store::EntryRow,
        delta_data: &[u8],
        ctx: &mut Ctx,
        visiting: &mut Vec<i64>,
        depth: u32,
        _pack_cache: &mut HashMap<i64, Vec<u8>>,
    ) -> Result<(String, Vec<u8>, Vec<StepRec>), Block> {
        let base_oid = e
            .base_oid
            .clone()
            .ok_or_else(|| Block::Permanent("bad_ref".into(), "ref-delta without base oid".into()))?;
        let base_oid_hex = oid::to_hex(&base_oid);

        // 1) 已还原的确定性候选 (按来源摘要排序, 与导入顺序无关)。
        if let Some(c) = self.store.ok_candidates_by_oid(&base_oid_hex).into_iter().next() {
            let resolved = Resolved {
                oid: oid::from_hex(&c.oid.unwrap_or_default()).unwrap_or([0u8; 20]),
                kind: c.kind.unwrap_or_default(),
                content: c.content.unwrap_or_default(),
                candidate_id: c.id,
                steps: Vec::new(),
                depth: c.depth as u32,
                expanded: 0,
            };
            let (kind, content, step, _depth) =
                self.apply_delta_step(&resolved, delta_data, "ref", &base_oid_hex, ctx)?;
            return Ok((kind, content, vec![step]));
        }

        // 2) 经 index fanout 表的 oid->offset 映射尝试解析 pack entry。
        let mappings = self.store.index_entries_by_oid(&base_oid_hex);
        if mappings.is_empty() {
            return Err(Block::MissingBase(base_oid_hex));
        }
        let mut last_error: Option<Block> = None;
        for (_index_id, offset, _crc) in mappings {
            for base_entry in self.store.entries_at_offset(offset) {
                match self.resolve_in_ctx(
                    UnitKey::Entry(base_entry.id),
                    ctx,
                    visiting,
                    depth + 1,
                ) {
                    Ok(resolved) => {
                        let (kind, content, step, _depth) = self.apply_delta_step(
                            &resolved,
                            delta_data,
                            "ref",
                            &base_oid_hex,
                            ctx,
                        )?;
                        return Ok((kind, content, vec![step]));
                    }
                    Err(Block::Budget(m)) => return Err(Block::Budget(m)),
                    Err(Block::Cycle(c)) => return Err(Block::Cycle(c)),
                    Err(other) => last_error = Some(other),
                }
            }
        }
        match last_error {
            Some(Block::Permanent(k, m)) => Err(Block::BaseBlocked(
                format!("{base_oid_hex}: {k}: {m}"),
                None,
            )),
            Some(other) => Err(other),
            None => Err(Block::MissingBase(base_oid_hex)),
        }
    }
}
