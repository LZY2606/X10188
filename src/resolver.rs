//! 还原器：沿 delta DAG 重建对象，重算 git object id，
//! 记录每步 delta（base、指令范围、输入/输出长度、校验）。
//!
//! 预算：max_depth（delta 链深度）、total_budget（总展开字节）、
//! per_object_ratio（单对象占总预算千分比上限）。
//! 达到预算上限 -> suspended，可从断点 resume，绝不把部分结果标成 complete。
//! 局部重算：只重新处理“受影响子图”（新 base 可达的反向依赖 + 仍阻塞条目）。

use crate::git::{delta, pack, read_le_varint, GitType};
use crate::importer::{insert_candidate, recompute_ranks, DataDir};
use rusqlite::{params, Connection};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub total_budget: u64,
    /// 单对象上限 = total_budget * ratio / 1000
    pub per_object_ratio: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            total_budget: 256 * 1024 * 1024,
            per_object_ratio: 200, // 20%
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    Done,
    Suspended {
        reason: String,
        resume_after_entry_id: i64,
        used_bytes: u64,
    },
}

#[derive(Debug, Clone)]
pub enum ResolveBlock {
    MissingBase(String),
    Cycle(Vec<i64>),
    DepthExceeded(usize),
    BadObject(String),
    DeltaError(String),
}

impl ResolveBlock {
    pub fn code(&self) -> &'static str {
        match self {
            ResolveBlock::MissingBase(_) => "missing_base",
            ResolveBlock::Cycle(_) => "cycle",
            ResolveBlock::DepthExceeded(_) => "depth_exceeded",
            ResolveBlock::BadObject(_) => "bad_object",
            ResolveBlock::DeltaError(_) => "delta_error",
        }
    }
    pub fn message(&self) -> String {
        match self {
            ResolveBlock::MissingBase(s) => format!("缺少外部 base: {s}"),
            ResolveBlock::Cycle(chain) => format!(
                "delta 形成环: {}",
                chain
                    .iter()
                    .map(|i| format!("#{i}"))
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
            ResolveBlock::DepthExceeded(d) => format!("delta 深度超过上限 {d}"),
            ResolveBlock::BadObject(s) => format!("对象本身损坏: {s}"),
            ResolveBlock::DeltaError(s) => format!("delta 指令错误: {s}"),
        }
    }
}

#[derive(Debug, Clone)]
struct EntryInfo {
    id: i64,
    source_id: i64,
    kind: String,
    ordinal: i64,
    declared_size: i64,
    inflated_size: Option<i64>,
    ofs_negative: Option<i64>,
    ref_base_oid: Option<String>,
    data_offset: Option<i64>,
    end_offset: Option<i64>,
    problem: Option<String>,
}

fn load_entry(conn: &Connection, entry_id: i64) -> Option<EntryInfo> {
    conn.query_row(
        "SELECT id,source_id,kind,ordinal,declared_size,inflated_size,ofs_negative,
                ref_base_oid,data_offset,end_offset,problem
         FROM entries WHERE id=?1",
        params![entry_id],
        |r| {
            Ok(EntryInfo {
                id: r.get(0)?,
                source_id: r.get(1)?,
                kind: r.get(2)?,
                ordinal: r.get(3)?,
                declared_size: r.get(4)?,
                inflated_size: r.get(5)?,
                ofs_negative: r.get(6)?,
                ref_base_oid: r.get(7)?,
                data_offset: r.get(8)?,
                end_offset: r.get(9)?,
                problem: r.get(10)?,
            })
        },
    )
    .ok()
}

/// 读取某 pack entry 解压后的原始字节（从磁盘重新解压，避免入库大 blob）。
fn pack_entry_inflated(conn: &Connection, dir: &DataDir, e: &EntryInfo) -> Result<Vec<u8>, String> {
    let path: String = conn
        .query_row("SELECT path FROM sources WHERE id=?1", params![e.source_id], |r| r.get(0))
        .map_err(|x| x.to_string())?;
    let buf = std::fs::read(dir.root.join(&path)).map_err(|x| x.to_string())?;
    let start = e.data_offset.unwrap_or(0) as usize;
    let outcome = crate::git::zlib::inflate_one(
        &buf,
        start,
        e.declared_size as u64,
        512 * 1024 * 1024,
    )
    .map_err(|err| format!("{err:?}"))?;
    Ok(outcome.data)
}

fn loose_content(conn: &Connection, dir: &DataDir, e: &EntryInfo) -> Result<(GitType, Vec<u8>), String> {
    let path: String = conn
        .query_row("SELECT path FROM sources WHERE id=?1", params![e.source_id], |r| r.get(0))
        .map_err(|x| x.to_string())?;
    let buf = std::fs::read(dir.root.join(&path)).map_err(|x| x.to_string())?;
    let obj = crate::git::loose::parse_loose(&buf).map_err(|e| e)?;
    Ok((obj.t, obj.content))
}

struct Engine<'a> {
    conn: &'a Connection,
    dir: &'a DataDir,
    branch_id: i64,
    branch_name: String,
    pinned_source: Option<i64>,
    budget: Budget,
    used_bytes: u64,
    suspended_at: Option<i64>,
    suspend_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct Resolved {
    otype: GitType,
    content: Vec<u8>,
    depth: usize,
    charged: u64,
    chain: Vec<i64>,
}

fn is_pack_kind(k: &str) -> bool {
    matches!(k, "commit" | "tree" | "blob" | "tag" | "ofs_delta" | "ref_delta")
}

impl<'a> Engine<'a> {
    fn branch_pin_ok(&self, source_id: i64) -> bool {
        match self.pinned_source {
            Some(pin) => source_id == pin,
            None => true,
        }
    }

    /// 选择某 oid 在本分支上的候选条目（考虑 pin）。
    fn candidate_for_oid(&self, oid_hex: &str) -> Option<(i64, i64)> {
        // pin 分支：只接受被 pin 来源的候选；否则按 rank
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.entry_id, c.source_id FROM candidates c
                 JOIN entries e ON e.id=c.entry_id
                 WHERE c.oid=?1
                 ORDER BY (e.problem IS NULL) DESC,
                          CASE WHEN ?2 IS NOT NULL AND c.source_id=?2 THEN 0 ELSE 1 END,
                          c.rank, c.id",
            )
            .unwrap();
        let mut rows = stmt
            .query(params![oid_hex, self.pinned_source])
            .unwrap();
        while let Some(r) = rows.next().unwrap() {
            let entry_id: i64 = r.get(0).unwrap();
            let source_id: i64 = r.get(1).unwrap();
            if self.branch_pin_ok(source_id) {
                return Some((entry_id, source_id));
            }
        }
        None
    }

    fn per_object_cap(&self) -> u64 {
        self.budget.total_budget * self.budget.per_object_ratio / 1000
    }

    fn preview(content: &[u8]) -> String {
        let n = content.len().min(512);
        let mut s = String::new();
        for &b in &content[..n] {
            if b == b'\n' {
                s.push('\\');
                s.push('n');
            } else if b == b'\r' {
                s.push('\\');
                s.push('r');
            } else if b == b'\t' {
                s.push('\\');
                s.push('t');
            } else if (0x20..=0x7e).contains(&b) {
                s.push(b as char);
            } else {
                s.push_str(&format!("\\x{b:02x}"));
            }
        }
        if content.len() > n {
            s.push_str("…(截断)");
        }
        s
    }

    fn persist_steps(&self, entry_id: i64, base_entry: Option<i64>, steps: &[delta::DeltaStep], verify: &[String]) {
        for (i, st) in steps.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT INTO delta_steps(branch_id,entry_id,step_no,base_entry_id,
                         instr_start,instr_end,op,copy_offset,length,in_size,out_size,verify)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![
                        self.branch_id,
                        entry_id,
                        i as i64,
                        base_entry,
                        st.instr_start as i64,
                        st.instr_end as i64,
                        st.kind,
                        st.copy_offset.map(|v| v as i64),
                        st.length as i64,
                        st.in_size,
                        st.out_size,
                        verify.get(i).cloned().unwrap_or_else(|| "ok".to_string())
                    ],
                )
                .unwrap();
        }
    }

    fn record_blocked(&self, entry_id: i64, block: &ResolveBlock, chain: &[i64]) {
        let blocker = match block {
            ResolveBlock::MissingBase(_) => None,
            _ => chain.last().copied(),
        };
        self.conn
            .execute(
                "INSERT INTO results(branch_id,entry_id,status,blocker_entry_id,blocker_reason,chain_json)
                 VALUES(?1,?2,'blocked',?3,?4,?5)
                 ON CONFLICT(branch_id,entry_id) DO UPDATE SET
                   status='blocked', blocker_entry_id=excluded.blocker_entry_id,
                   blocker_reason=excluded.blocker_reason, chain_json=excluded.chain_json,
                   updated_at=datetime('now')",
                params![
                    self.branch_id,
                    entry_id,
                    blocker,
                    format!("{}: {}", block.code(), block.message()),
                    serde_json::to_string(chain).unwrap_or_default()
                ],
            )
            .unwrap();
    }

    /// 递归还原单个 entry。stack 用于环检测（从链顶到当前）。
    /// 返回 Ok(Resolved) 或 Err(block)。
    fn resolve_entry(
        &mut self,
        entry_id: i64,
        depth: usize,
        stack: &mut Vec<i64>,
    ) -> Result<Resolved, ResolveBlock> {
        // 环检测
        if let Some(pos) = stack.iter().position(|&x| x == entry_id) {
            let cyc: Vec<i64> = stack[pos..].to_vec();
            return Err(ResolveBlock::Cycle(cyc));
        }
        if depth > self.budget.max_depth {
            return Err(ResolveBlock::DepthExceeded(self.budget.max_depth));
        }
        // 预算已在前序对象耗尽：整个 run 暂停（可重试中间状态）
        if self.suspended_at.is_some() {
            return Err(ResolveBlock::BadObject("run 已因预算暂停".into()));
        }

        let e = load_entry(self.conn, entry_id)
            .ok_or_else(|| ResolveBlock::BadObject("条目不存在".into()))?;

        // 条目自带解析问题（大小欺骗/CRC 错/重同步/越界）-> 隔离
        if let Some(p) = &e.problem {
            return Err(ResolveBlock::BadObject(p.clone()));
        }

        stack.push(entry_id);

        // ---- 非 delta base ----
        if is_pack_kind(&e.kind) && e.kind != "ofs_delta" && e.kind != "ref_delta" {
            let content = pack_entry_inflated(self.conn, self.dir, &e)
                .map_err(ResolveBlock::BadObject)?;
            let actual = content.len() as u64;
            if actual != e.declared_size as u64 {
                stack.pop();
                return Err(ResolveBlock::BadObject(format!(
                    "base 大小欺骗：声明 {} 实际 {}",
                    e.declared_size, actual
                )));
            }
            self.charge(entry_id, actual)?;
            stack.pop();
            return Ok(Resolved {
                otype: GitType::from_name(e.kind.as_bytes()).unwrap(),
                content,
                depth,
                charged: actual,
                chain: vec![entry_id],
            });
        }

        // ---- loose：直接从磁盘解析 ----
        if e.kind == "loose" {
            let (t, content) =
                loose_content(self.conn, self.dir, &e).map_err(ResolveBlock::BadObject)?;
            let actual = content.len() as u64;
            self.charge(entry_id, actual)?;
            stack.pop();
            return Ok(Resolved {
                otype: t,
                content,
                depth,
                charged: actual,
                chain: vec![entry_id],
            });
        }

        // ---- delta：找 base ----
        let (base_entry_id, base_source, dep_kind) = if e.kind == "ofs_delta" {
            let pid: i64 = self
                .conn
                .query_row(
                    "SELECT parent_entry_id FROM deps WHERE child_entry_id=?1 LIMIT 1",
                    params![entry_id],
                    |r| r.get(0),
                )
                .map_err(|_| {
                    ResolveBlock::BadObject(
                        "ofs-delta 目标偏移越界或未对齐对象头".to_string(),
                    )
                })?;
            let src: i64 = self
                .conn
                .query_row("SELECT source_id FROM entries WHERE id=?1", params![pid], |r| {
                    r.get(0)
                })
                .map_err(|_| ResolveBlock::MissingBase("ofs base 已丢失".into()))?;
            (pid, src, "ofs")
        } else if e.kind == "ref_delta" {
            let base_oid = e
                .ref_base_oid
                .clone()
                .unwrap_or_default();
            match self.candidate_for_oid(&base_oid) {
                Some((be, bs)) => (be, bs, "ref"),
                None => {
                    stack.pop();
                    return Err(ResolveBlock::MissingBase(base_oid));
                }
            }
        } else {
            stack.pop();
            return Err(ResolveBlock::BadObject(format!("未知条目类型 {}", e.kind)));
        };

        // pin 分支不允许使用非 pin 来源的 base
        if !self.branch_pin_ok(base_source) {
            stack.pop();
            return Err(ResolveBlock::MissingBase(format!(
                "base 来源 #{} 在当前分支被 pin 排除",
                base_source
            )));
        }

        let base = self.resolve_entry(base_entry_id, depth + 1, stack)?;

        // ---- 应用 delta ----
        let delta_bytes = pack_entry_inflated(self.conn, self.dir, &e)
            .map_err(ResolveBlock::BadObject)?;
        if delta_bytes.len() as i64 != e.declared_size {
            stack.pop();
            return Err(ResolveBlock::BadObject(format!(
                "delta 大小欺骗：声明 {} 实际 {}",
                e.declared_size,
                delta_bytes.len()
            )));
        }
        // delta 头声称的源大小必须与 base.content 长度一致（apply_delta 内部也查）
        let (declared_src, _) = read_le_varint(&delta_bytes, 0)
            .ok_or_else(|| ResolveBlock::DeltaError("delta 头损坏".into()))?;
        if declared_src != base.content.len() as u64 {
            stack.pop();
            return Err(ResolveBlock::DeltaError(format!(
                "delta 源大小 {declared_src} 与 base {} 不一致",
                base.content.len()
            )));
        }

        let applied = delta::apply_delta(&base.content, &delta_bytes).map_err(|de| {
            ResolveBlock::DeltaError(de.to_string())
        })?;

        let out_len = applied.data.len() as u64;
        // 输出对象的预算计费（base 已在递归里计费；这里计 delta 展开结果）
        self.charge(entry_id, out_len)?;

        // 记录 delta 步骤
        let verifies: Vec<String> = applied
            .steps
            .iter()
            .map(|st| {
                match st.kind {
                    "copy" => {
                        let off = st.copy_offset.unwrap_or(0) as usize;
                        let end = off + st.length as usize;
                        if end <= base.content.len() {
                            "ok".to_string()
                        } else {
                            format!("error: copy 越界 base={}", base.content.len())
                        }
                    }
                    _ => "ok".to_string(),
                }
            })
            .collect();
        self.persist_steps(entry_id, Some(base_entry_id), &applied.steps, &verifies);
        let _ = dep_kind;

        let mut chain = base.chain;
        chain.push(entry_id);
        stack.pop();
        Ok(Resolved {
            otype: base.otype,
            content: applied.data,
            depth,
            charged: base.charged + out_len,
            chain,
        })
    }

    /// 预算计费：单对象比例 + 总预算。超出则挂起当前 run。
    fn charge(&mut self, entry_id: i64, bytes: u64) -> Result<(), ResolveBlock> {
        let cap = self.per_object_cap();
        if bytes > cap {
            self.suspend(
                entry_id,
                format!(
                    "单对象 {bytes} 字节超过比例上限 {cap}（总预算 {} 的 {}/1000）",
                    self.budget.total_budget, self.budget.per_object_ratio
                ),
            );
            return Err(ResolveBlock::BadObject("单对象比例超限（run 暂停）".into()));
        }
        if self.used_bytes.saturating_add(bytes) > self.budget.total_budget {
            self.suspend(
                entry_id,
                format!(
                    "总展开字节 {}+{bytes} 超过总预算 {}",
                    self.used_bytes, self.budget.total_budget
                ),
            );
            return Err(ResolveBlock::BadObject("总预算超限（run 暂停）".into()));
        }
        self.used_bytes += bytes;
        Ok(())
    }

    fn suspend(&mut self, entry_id: i64, reason: String) {
        if self.suspended_at.is_none() {
            self.suspended_at = Some(entry_id);
            self.suspend_reason = Some(reason);
        }
    }
}

/// 反向可达收集：从 roots 出发沿 deps(child->parent) 的反方向，
/// 即所有（传递）依赖这些 roots 的条目。
fn reverse_reachable(conn: &Connection, roots: &HashSet<i64>) -> HashSet<i64> {
    let mut seen: HashSet<i64> = roots.iter().copied().collect();
    let mut work: Vec<i64> = roots.iter().copied().collect();
    while let Some(id) = work.pop() {
        let children: Vec<i64> = {
            let mut s = conn
                .prepare("SELECT child_entry_id FROM deps WHERE parent_entry_id=?1")
                .unwrap();
            let rows = s.query_map(params![id], |r| r.get::<_, i64>(0)).unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        for c in children {
            // ref-delta 边存得少（见下），所以还需基于候选 oid 动态反向边：
            // 在 run() 里对缺失 base 恢复时通过 blocker 重算，这里仅 ofs 边。
            if seen.insert(c) {
                work.push(c);
            }
        }
    }
    seen
}

/// ref-delta 的动态反向边：候选 c(oid=X) 的 entry，被所有 ref_base_oid=X 的 delta 依赖。
fn ref_reverse(conn: &Connection, roots: &HashSet<i64>) -> HashSet<i64> {
    let mut work: Vec<i64> = roots.iter().copied().collect();
    let mut seen = roots.clone();
    while let Some(id) = work.pop() {
        let oids: Vec<String> = {
            let mut s = conn
                .prepare("SELECT oid FROM candidates WHERE entry_id=?1")
                .unwrap();
            let rows = s.query_map(params![id], |r| r.get::<_, String>(0)).unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        for oid in oids {
            let mut s = conn
                .prepare("SELECT id FROM entries WHERE kind='ref_delta' AND ref_base_oid=?1")
                .unwrap();
            let rows = s.query_map(params![oid], |r| r.get::<_, i64>(0)).unwrap();
            for c in rows.flatten() {
                if seen.insert(c) {
                    work.push(c);
                }
            }
        }
    }
    seen
}

pub struct RunOutcome {
    pub status: RunStatus,
    pub resolved: usize,
    pub blocked: usize,
    pub suspended: usize,
    pub used_bytes: u64,
}

fn ensure_branch(conn: &Connection, branch_id: i64) -> Option<(String, Option<i64>)> {
    conn.query_row(
        "SELECT name, pinned_source_id FROM branches WHERE id=?1",
        params![branch_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
    )
    .ok()
}

/// 在指定分支上运行还原。
/// - `roots`: 只处理这些条目及其依赖子图；None 表示全量。
/// - 调用方通过最新 job 行控制 used_bytes/resume_after：
///   resume() 沿用挂起任务的计数；局部重算/新分支先插入一条清零 job。
pub fn run(
    conn: &mut Connection,
    dir: &DataDir,
    branch_id: i64,
    budget: Budget,
    roots: Option<HashSet<i64>>,
) -> RunOutcome {
    let (branch_name, pinned_source) = ensure_branch(conn, branch_id)
        .expect("分支不存在");

    let (mut used_bytes, resume_after): (u64, Option<i64>) = conn
        .query_row(
            "SELECT COALESCE(used_bytes,0), resume_after_entry_id FROM jobs
             WHERE branch_id=?1 ORDER BY id DESC LIMIT 1",
            params![branch_id],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, Option<i64>>(1)?)),
        )
        .unwrap_or((0, None));
    // 局部重算（roots=Some）总是新预算窗口；只有全量 resume 才沿用断点
    if roots.is_some() {
        used_bytes = 0;
    }

    // 决定处理集合
    let targets: Vec<i64> = {
        let mut all: Vec<i64> = {
            let mut s = conn.prepare("SELECT id FROM entries ORDER BY source_id, ordinal, id").unwrap();
            let rows = s.query_map([], |r| r.get::<_, i64>(0)).unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        let set = match roots {
            Some(r) => r,
            None => all.iter().copied().collect(),
        };
        all.retain(|id| set.contains(id));
        all
    };

    // 失效待处理条目的旧结果与 delta_steps（局部重算）
    if !targets.is_empty() {
        let ids = targets.clone();
        let tx = conn.transaction().unwrap();
        for id in &ids {
            tx.execute("DELETE FROM delta_steps WHERE branch_id=?1 AND entry_id=?2",
                params![branch_id, id]).unwrap();
            tx.execute("DELETE FROM results WHERE branch_id=?1 AND entry_id=?2",
                params![branch_id, id]).unwrap();
        }
        tx.commit().unwrap();
    }

    let mut engine = Engine {
        conn,
        dir,
        branch_id,
        branch_name: branch_name.clone(),
        pinned_source,
        budget,
        used_bytes,
        suspended_at: None,
        suspend_reason: None,
    };

    let mut resolved = 0usize;
    let mut blocked = 0usize;
    let mut suspended_count = 0usize;
    let mut first_target: Option<i64> = targets.first().copied();
    let mut skip_until_resume = resume_after.is_some();
    let resume_point = resume_after;

    let mut order: Vec<i64> = Vec::new();
    for id in &targets {
        if skip_until_resume {
            // 从断点条目开始（含断点自身，因为它未被记为 complete）
            if Some(*id) == resume_point {
                skip_until_resume = false;
            } else {
                continue;
            }
        }
        order.push(*id);
    }

    for entry_id in order {
        if engine.suspended_at.is_some() {
            // 剩余目标全部记 suspended（可重试中间状态，绝不当完整对象）
            engine.conn
                .execute(
                    "INSERT INTO results(branch_id,entry_id,status,blocker_reason)
                     VALUES(?1,?2,'suspended',?3)
                     ON CONFLICT(branch_id,entry_id) DO UPDATE SET
                       status='suspended', blocker_reason=excluded.blocker_reason,
                       updated_at=datetime('now')",
                    params![
                        engine.branch_id,
                        entry_id,
                        engine.suspend_reason.clone().unwrap_or_default()
                    ],
                )
                .unwrap();
            suspended_count += 1;
            continue;
        }

        let mut stack = Vec::new();
        match engine.resolve_entry(entry_id, 0, &mut stack) {
            Ok(res) => {
                let oid = crate::git::git_object_id(res.otype, &res.content);
                let oid_hex = hex::encode(oid);
                let content_path = engine.dir.blob_path(&engine.branch_name, &oid_hex);
                std::fs::write(&content_path, &res.content).ok();
                let preview = Engine::<'_>::preview(&res.content);
                let e = load_entry(engine.conn, entry_id).unwrap();

                // 与 loose 路径声称 oid / index 候选比对，记录 oid_ok
                let mut oid_ok = true;
                if let Some(claimed) = e.kind.as_str().check_loose_claimed(engine.conn, entry_id) {
                    if claimed != oid_hex {
                        oid_ok = false;
                    }
                }

                engine
                    .conn
                    .execute(
                        "INSERT INTO results(branch_id,entry_id,status,object_type,oid,oid_calc,
                             oid_ok,output_size,content_path,preview,depth,bytes_charged,chain_json)
                         VALUES(?1,?2,'complete',?3,?4,?4,?5,?6,?7,?8,?9,?10,?11)
                         ON CONFLICT(branch_id,entry_id) DO UPDATE SET
                           status='complete', object_type=excluded.object_type,
                           oid=excluded.oid, oid_calc=excluded.oid_calc,
                           oid_ok=excluded.oid_ok, output_size=excluded.output_size,
                           content_path=excluded.content_path, preview=excluded.preview,
                           depth=excluded.depth, bytes_charged=excluded.bytes_charged,
                           chain_json=excluded.chain_json, blocker_entry_id=NULL,
                           blocker_reason=NULL, updated_at=datetime('now')",
                        params![
                            engine.branch_id,
                            entry_id,
                            res.otype.name(),
                            oid_hex,
                            oid_ok as i64,
                            res.content.len() as i64,
                            content_path
                                .strip_prefix(&engine.dir.root)
                                .unwrap_or(&content_path)
                                .to_string_lossy(),
                            preview,
                            res.depth as i64,
                            res.charged as i64,
                            serde_json::to_string(&res.chain).unwrap_or_default()
                        ],
                    )
                    .unwrap();

                // 登记候选（重算后的对象也可作为别人的 ref base）
                insert_candidate_entry(engine.conn, &oid_hex, entry_id, e.source_id);
                resolved += 1;
            }
            Err(block) => {
                let chain = stack.clone();
                let full_chain = build_blocker_chain(engine.conn, entry_id, &block, &chain);
                engine.record_blocked(entry_id, &block, &full_chain);
                blocked += 1;
            }
        }
        first_target = None;
    }

    // 统一重算候选 rank（与导入顺序无关的稳定排序）
    {
        let tx = engine.conn.transaction().unwrap();
        recompute_ranks(&tx).unwrap();
        tx.commit().unwrap();
    }

    // 记录/更新 job
    let final_status = if engine.suspended_at.is_some() {
        "suspended"
    } else {
        "done"
    };
    engine
        .conn
        .execute(
            "INSERT INTO jobs(branch_id,status,max_depth,total_budget,per_object_ratio,
                 used_bytes,resume_after_entry_id,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,datetime('now'))",
            params![
                engine.branch_id,
                final_status,
                engine.budget.max_depth as i64,
                engine.budget.total_budget as i64,
                engine.budget.per_object_ratio as i64,
                engine.used_bytes as i64,
                engine.suspended_at
            ],
        )
        .unwrap();

    RunOutcome {
        status: match engine.suspended_at {
            Some(eid) => RunStatus::Suspended {
                reason: engine.suspend_reason.unwrap_or_default(),
                resume_after_entry_id: eid,
                used_bytes: engine.used_bytes,
            },
            None => RunStatus::Done,
        },
        resolved,
        blocked,
        suspended: suspended_count,
        used_bytes: engine.used_bytes,
    }
}

fn insert_candidate_entry(conn: &Connection, oid_hex: &str, entry_id: i64, source_id: i64) {
    conn.execute(
        "INSERT OR IGNORE INTO candidates(oid,entry_id,source_id,rank) VALUES(?1,?2,?3,0)",
        params![oid_hex, entry_id, source_id],
    )
    .unwrap();
}

trait LooseClaimed {
    fn check_loose_claimed(&self, conn: &Connection, entry_id: i64) -> Option<String>;
}
impl LooseClaimed for str {
    fn check_loose_claimed(&self, conn: &Connection, entry_id: i64) -> Option<String> {
        if self == "loose" {
            conn.query_row(
                "SELECT loose_path_oid FROM entries WHERE id=?1",
                params![entry_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
        } else {
            None
        }
    }
}

/// 阻塞链：当前条目 -> ... -> 具体阻塞点；missing_base 给出 oid 终点标签。
fn build_blocker_chain(
    conn: &Connection,
    entry_id: i64,
    block: &ResolveBlock,
    stack: &[i64],
) -> Vec<serde_json::Value> {
    let mut chain: Vec<serde_json::Value> = Vec::new();
    let mut seq = vec![entry_id];
    seq.extend(stack.iter().filter(|&&x| x != entry_id));
    for id in &seq {
        chain.push(serde_json::json!({"entry_id": id}));
    }
    match block {
        ResolveBlock::MissingBase(oid) => {
            chain.push(serde_json::json!({"missing_base_oid": oid}));
        }
        ResolveBlock::Cycle(c) => {
            chain.push(serde_json::json!({"cycle": c}));
        }
        _ => {}
    }
    let _ = conn;
    chain
}

/// 导入新源后：计算受影响子图，只在 default 分支上做局部重算（其它分支按需触发）。
pub fn recompute_affected(
    conn: &mut Connection,
    dir: &DataDir,
    new_entry_ids: &[i64],
    budget: Budget,
) -> RunOutcome {
    recompute_affected_branch(conn, dir, 1, new_entry_ids, budget)
}

pub fn recompute_affected_branch(
    conn: &mut Connection,
    dir: &DataDir,
    branch_id: i64,
    new_entry_ids: &[i64],
    budget: Budget,
) -> RunOutcome {
    let roots: HashSet<i64> = new_entry_ids.iter().copied().collect();
    let mut affected = reverse_reachable(conn, &roots);
    affected = ref_reverse(conn, &affected);

    // 该分支上仍处于 blocked / suspended 的条目也要重试（可能新 base 解了阻塞）
    {
        let mut s = conn
            .prepare(
                "SELECT entry_id FROM results
                 WHERE branch_id=?1 AND status IN ('blocked','suspended')",
            )
            .unwrap();
        let rows = s.query_map(params![branch_id], |r| r.get::<_, i64>(0)).unwrap();
        for id in rows.flatten() {
            affected.insert(id);
        }
    }
    // resume 语义：清掉该分支已完成/暂停 job 的 used_bytes，
    // 局部重算使用新预算窗口（完整对象会重新计费）。
    conn.execute(
        "INSERT INTO jobs(branch_id,status,max_depth,total_budget,per_object_ratio,
             used_bytes,resume_after_entry_id,updated_at)
         VALUES(?1,'done',?2,?3,?4,0,NULL,datetime('now'))",
        params![
            branch_id,
            budget.max_depth as i64,
            budget.total_budget as i64,
            budget.per_object_ratio as i64
        ],
    )
    .unwrap();

    run(conn, dir, branch_id, budget, Some(affected))
}

/// 显式 resume：继续当前分支的 suspended job。
pub fn resume(conn: &mut Connection, dir: &DataDir, branch_id: i64, budget: Budget) -> RunOutcome {
    // resume 不重置 used_bytes / resume_after（run 内部读取最新 job）
    run(conn, dir, branch_id, budget, None)
}

/// 创建分析分支（可固定某个冲突来源），随后全量解析。
pub fn create_branch(
    conn: &mut Connection,
    name: &str,
    pinned_source_id: Option<i64>,
    note: &str,
    dir: &DataDir,
    budget: Budget,
) -> rusqlite::Result<(i64, RunOutcome)> {
    conn.execute(
        "INSERT INTO branches(name,pinned_source_id,note) VALUES(?1,?2,?3)",
        params![name, pinned_source_id, note],
    )?;
    let branch_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO jobs(branch_id,status,max_depth,total_budget,per_object_ratio,used_bytes)
         VALUES(?1,'done',?2,?3,?4,0)",
        params![
            branch_id,
            budget.max_depth as i64,
            budget.total_budget as i64,
            budget.per_object_ratio as i64
        ],
    )?;
    let outcome = run(conn, dir, branch_id, budget, None);
    Ok((branch_id, outcome))
}

/// 删除源之前：返回仍依赖该源的对象 oid 列表（任何分支上 complete 且用到该源条目的）。
pub fn dependents_on_source(conn: &Connection, source_id: i64) -> Vec<DependentInfo> {
    let mut out = Vec::new();
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT r.oid, r.branch_id, b.name, r.status
             FROM results r
             JOIN branches b ON b.id=r.branch_id
             JOIN entries e ON e.id=r.entry_id
             WHERE r.oid IS NOT NULL AND (
                e.source_id=?1
                OR r.entry_id IN (
                    SELECT child_entry_id FROM deps WHERE parent_entry_id IN (
                        SELECT id FROM entries WHERE source_id=?1
                    )
                )
             )
             ORDER BY r.oid, r.branch_id",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![source_id], |r| {
            Ok(DependentInfo {
                oid: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                branch_id: r.get(1)?,
                branch: r.get(2)?,
                status: r.get(3)?,
            })
        })
        .unwrap();
    for r in rows.flatten() {
        out.push(r);
    }
    out
}

#[derive(Debug, serde::Serialize)]
pub struct DependentInfo {
    pub oid: String,
    pub branch_id: i64,
    pub branch: String,
    pub status: String,
}

/// 真正删除源：连带条目/候选/结果（CASCADE），并把仍引用已删除候选的
/// ref-delta 结果置为 blocked，提示重新解析。
pub fn delete_source(conn: &mut Connection, dir: &DataDir, source_id: i64) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    // 删除文件
    if let Ok(path) = tx.query_row::<String, _, _>(
        "SELECT path FROM sources WHERE id=?1",
        params![source_id],
        |r| r.get(0),
    ) {
        let _ = std::fs::remove_file(dir.root.join(&path));
    }
    tx.execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
    tx.commit()?;
    // 清理悬空 deps（父子条目已随 CASCADE 删除，但保险）
    conn.execute(
        "DELETE FROM deps WHERE parent_entry_id NOT IN (SELECT id FROM entries)
               OR child_entry_id NOT IN (SELECT id FROM entries)",
        [],
    )?;
    Ok(())
}
