// 还原引擎:delta 链解析、预算、环检测、阻塞链、局部重算。
use crate::gitobj::{self, ObjType};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub max_depth: i64,
    pub max_total_bytes: i64,
    pub max_ratio: f64,
    pub used_bytes: i64,
}

pub fn get_budget(conn: &Connection) -> rusqlite::Result<Budget> {
    conn.query_row(
        "SELECT max_depth, max_total_bytes, max_ratio, used_bytes FROM budget WHERE id=1",
        [],
        |r| {
            Ok(Budget {
                max_depth: r.get(0)?,
                max_total_bytes: r.get(1)?,
                max_ratio: r.get(2)?,
                used_bytes: r.get(3)?,
            })
        },
    )
}

pub fn set_budget(
    conn: &Connection,
    max_depth: i64,
    max_total_bytes: i64,
    max_ratio: f64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE budget SET max_depth=?1, max_total_bytes=?2, max_ratio=?3 WHERE id=1",
        params![max_depth, max_total_bytes, max_ratio],
    )?;
    Ok(())
}

#[derive(Default, Clone, Debug)]
pub struct RunStats {
    pub resolved: usize,
    pub blocked: usize,
    pub paused: usize,
    pub errors: usize,
}

#[derive(PartialEq, Eq)]
enum Out {
    Ok(String),
    Blocked,
    Paused,
    Error,
    Cycle,
}

struct Ctx<'a> {
    conn: &'a Connection,
    data_dir: &'a Path,
    budget: Budget,
    used: i64,
    stats: RunStats,
    file_cache: HashMap<i64, Rc<Vec<u8>>>,
}

impl<'a> Ctx<'a> {
    fn evidence(&self, file_id: Option<i64>, object_id: Option<i64>, level: &str, msg: &str) {
        self.conn
            .execute(
                "INSERT INTO evidence(file_id, object_id, level, message) VALUES (?1,?2,?3,?4)",
                params![file_id, object_id, level, msg],
            )
            .ok();
    }

    fn file_bytes(&mut self, file_id: i64) -> Result<Rc<Vec<u8>>, String> {
        if let Some(b) = self.file_cache.get(&file_id) {
            return Ok(b.clone());
        }
        let rel: String = self
            .conn
            .query_row("SELECT path FROM files WHERE id=?1", [file_id], |r| r.get(0))
            .map_err(|e| format!("无法定位源文件 {file_id}: {e}"))?;
        let bytes = std::fs::read(self.data_dir.join(&rel))
            .map_err(|e| format!("读取源文件 {rel} 失败: {e}"))?;
        Ok(self
            .file_cache
            .entry(file_id)
            .or_insert_with(|| Rc::new(bytes))
            .clone())
    }

    fn set_error(&mut self, id: i64, msg: &str) {
        self.conn
            .execute(
                "UPDATE objects SET status='error', error=?1 WHERE id=?2",
                params![msg, id],
            )
            .ok();
        self.conn
            .execute("DELETE FROM blocking WHERE object_id=?1", [id])
            .ok();
        self.evidence(None, Some(id), "error", msg);
        self.stats.errors += 1;
    }

    fn set_paused(&mut self, id: i64, msg: &str) {
        // 中间状态:不写 content/oid,绝不把部分输出当成完整对象。
        self.conn
            .execute(
                "UPDATE objects SET status='paused', error=?1, content=NULL, oid=NULL, final_type=NULL WHERE id=?2",
                params![msg, id],
            )
            .ok();
        self.conn
            .execute("DELETE FROM blocking WHERE object_id=?1", [id])
            .ok();
        self.stats.paused += 1;
    }

    fn set_blocked(&mut self, id: i64, deps: &[(&str, String)], msg: &str) {
        self.conn
            .execute("DELETE FROM blocking WHERE object_id=?1", [id])
            .ok();
        for (kind, val) in deps {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO blocking(object_id, dep, note) VALUES (?1,?2,?3)",
                    params![id, format!("{kind}:{val}"), msg],
                )
                .ok();
        }
        self.conn
            .execute(
                "UPDATE objects SET status='blocked', error=?1 WHERE id=?2",
                params![msg, id],
            )
            .ok();
        self.stats.blocked += 1;
    }

    fn store_ok(&mut self, id: i64, oid: &str, final_type: &str, content: &[u8]) {
        self.conn
            .execute(
                "UPDATE objects SET status='ok', oid=?1, final_type=?2, content=?3, error=NULL, gen=gen+1 WHERE id=?4",
                params![oid, final_type, content, id],
            )
            .ok();
        self.conn
            .execute("DELETE FROM blocking WHERE object_id=?1", [id])
            .ok();
        self.stats.resolved += 1;
        // 若 index 声明了该对象的 oid,核对还原结果。
        let claimed: Option<String> = self
            .conn
            .query_row(
                "SELECT oid FROM idx_entries WHERE object_id=?1 LIMIT 1",
                [id],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        if let Some(claimed) = claimed {
            if claimed != oid {
                let msg = format!(
                    "oid 与 index 声明不符: index={claimed}, 重新计算={oid}"
                );
                self.evidence(None, Some(id), "error", &msg);
            }
        }
    }

    fn record_step(
        &self,
        id: i64,
        base_desc: &str,
        instr_start: i64,
        instr_end: i64,
        in_len: i64,
        out_len: i64,
        ok: bool,
        note: &str,
    ) {
        self.conn
            .execute(
                "INSERT INTO delta_steps(object_id, step, base_desc, instr_start, instr_end, in_len, out_len, ok, note)
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![id, base_desc, instr_start, instr_end, in_len, out_len, ok as i64, note],
            )
            .ok();
    }

    /// 返回 true 表示可以接受该输出并记账;false 表示预算暂停。
    fn budget_check(&mut self, id: i64, out_len: i64, in_len: i64) -> bool {
        if self.used.saturating_add(out_len) > self.budget.max_total_bytes {
            let msg = format!(
                "总展开字节预算耗尽: 已用 {} + 需要 {} > 上限 {}",
                self.used, out_len, self.budget.max_total_bytes
            );
            self.set_paused(id, &msg);
            return false;
        }
        if in_len > 0 && (out_len as f64) > self.budget.max_ratio * in_len as f64 {
            let msg = format!(
                "单对象展开比例超限: base {} 字节 -> {} 字节, 上限比例 {}",
                in_len, out_len, self.budget.max_ratio
            );
            self.set_paused(id, &msg);
            return false;
        }
        self.used += out_len;
        true
    }

    fn resolve_obj(
        &mut self,
        id: i64,
        depth: i64,
        visiting: &mut Vec<i64>,
    ) -> Out {
        let row: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT status, otype, oid FROM objects WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        let (status, otype, oid) = match row {
            Some(v) => v,
            None => return Out::Error,
        };
        if status == "ok" {
            return Out::Ok(oid.unwrap_or_default());
        }
        if status == "error" {
            return Out::Error;
        }
        if status == "paused" {
            return Out::Paused;
        }
        if let Some(pos) = visiting.iter().position(|&x| x == id) {
            for &member in &visiting[pos..] {
                self.set_error(member, "delta 环: 依赖形成循环, 无法还原");
            }
            return Out::Cycle;
        }
        if depth > self.budget.max_depth {
            self.set_paused(
                id,
                &format!("超过 delta 深度预算 {}", self.budget.max_depth),
            );
            return Out::Paused;
        }
        visiting.push(id);
        let out = if otype == "ofs_delta" || otype == "ref_delta" {
            self.resolve_delta(id, &otype, depth, visiting)
        } else {
            self.resolve_full(id, &otype)
        };
        visiting.pop();
        out
    }

    fn resolve_full(&mut self, id: i64, otype: &str) -> Out {
        let row: Option<(i64, i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT file_id, comp_start, comp_len, hdr_size FROM objects WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .ok();
        let (file_id, comp_start, comp_len, hdr_size) = match row {
            Some(v) => v,
            None => return Out::Error,
        };
        let bytes = match self.file_bytes(file_id) {
            Ok(b) => b,
            Err(e) => {
                self.set_error(id, &e);
                return Out::Error;
            }
        };
        let start = comp_start as usize;
        let end = start + comp_len as usize;
        if end > bytes.len() {
            self.set_error(
                id,
                &format!("压缩数据越界: [{start}..{end}] 超过源文件 {} 字节", bytes.len()),
            );
            return Out::Error;
        }
        let content = match gitobj::inflate(&bytes[start..end]) {
            Ok((c, _)) => c,
            Err(e) => {
                self.set_error(id, &e);
                return Out::Error;
            }
        };
        if content.len() as i64 != hdr_size {
            let msg = format!(
                "大小欺骗: 头部声明 {hdr_size} 字节, 实际解压 {} 字节",
                content.len()
            );
            self.evidence(Some(file_id), Some(id), "error", &msg);
            self.set_error(id, &msg);
            return Out::Error;
        }
        if !self.budget_check(id, content.len() as i64, 0) {
            return Out::Paused;
        }
        let oid = gitobj::git_oid(otype, &content);
        self.store_ok(id, &oid, otype, &content);
        Out::Ok(oid)
    }
}

impl<'a> Ctx<'a> {
    /// ref-delta base 候选:按(源文件摘要, pack 内偏移, 对象 id)排序,
    /// 与导入顺序无关。pin 优先。
    fn ref_candidates(&self, base_oid: &str) -> Vec<i64> {
        let pinned: Option<i64> = self
            .conn
            .query_row("SELECT object_id FROM pins WHERE oid=?1", [base_oid], |r| {
                r.get(0)
            })
            .ok()
            .flatten();
        if let Some(p) = pinned {
            return vec![p];
        }
        let sql = "SELECT o.id FROM objects o JOIN files f ON f.id = o.file_id
                 WHERE o.id IN (
                    SELECT id FROM objects WHERE oid = ?1 AND status = 'ok'
                    UNION
                    SELECT object_id FROM idx_entries WHERE oid = ?1 AND object_id IS NOT NULL
                 )
                 ORDER BY f.digest, o.offset, o.id";
        let ids: Vec<i64> = self
            .conn
            .prepare(sql)
            .expect("prepare candidates")
            .query_map([base_oid], |r| r.get::<_, i64>(0))
            .expect("query candidates")
            .filter_map(|r| r.ok())
            .collect();
        ids
    }

    fn dep_failure(&mut self, id: i64, dep_id: i64, note: &str, outcome: Out) -> Out {
        match outcome {
            Out::Cycle => {
                let now_error: bool = self
                    .conn
                    .query_row("SELECT status='error' FROM objects WHERE id=?1", [id], |r| {
                        r.get(0)
                    })
                    .unwrap_or(false);
                if now_error {
                    Out::Cycle
                } else {
                    self.set_blocked(id, &[("obj", dep_id.to_string())], note);
                    Out::Blocked
                }
            }
            Out::Paused => {
                self.set_paused(id, &format!("{note}: base 对象 {dep_id} 被预算暂停"));
                Out::Paused
            }
            _ => {
                self.set_blocked(id, &[("obj", dep_id.to_string())], note);
                Out::Blocked
            }
        }
    }

    fn resolve_delta(
        &mut self,
        id: i64,
        otype: &str,
        depth: i64,
        visiting: &mut Vec<i64>,
    ) -> Out {
        let meta: Option<(i64, i64, i64, i64, Option<i64>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT file_id, offset, comp_start, comp_len, base_ofs, base_oid FROM objects WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok();
        let (file_id, offset, comp_start, comp_len, base_ofs, base_oid) = match meta {
            Some(v) => v,
            None => return Out::Error,
        };

        // 该对象作为 delta,其链上至少存在一层 base;即便 base 已缓存也要计入深度。
        if depth + 1 > self.budget.max_depth {
            self.set_paused(
                id,
                &format!("超过 delta 深度预算 {}", self.budget.max_depth),
            );
            return Out::Paused;
        }
        let (base_id, base_desc, link_oid): (i64, String, Option<String>) = if otype == "ofs_delta" {
            let base_ofs = base_ofs.unwrap_or(i64::MIN);
            if base_ofs < 0 || base_ofs >= offset {
                let msg = format!(
                    "ofs 距离越界: 基偏移 {base_ofs} 无效(当前对象偏移 {offset})"
                );
                self.evidence(Some(file_id), Some(id), "error", &msg);
                self.set_error(id, &msg);
                return Out::Error;
            }
            let found: Option<i64> = self
                .conn
                .query_row(
                    "SELECT id FROM objects WHERE file_id=?1 AND offset=?2",
                    params![file_id, base_ofs],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let base_id = match found {
                Some(b) => b,
                None => {
                    let msg = format!("ofs 基偏移 {base_ofs} 处没有对象, 可能 pack 损坏");
                    self.evidence(Some(file_id), Some(id), "error", &msg);
                    self.set_error(id, &msg);
                    return Out::Error;
                }
            };
            (base_id, format!("ofs@{base_ofs}"), None)
        } else {
            let base_oid = base_oid.unwrap_or_default();
            let candidates = self.ref_candidates(&base_oid);
            if candidates.is_empty() {
                self.set_blocked(
                    id,
                    &[("oid", base_oid.clone())],
                    &format!("缺少外部 base: oid {base_oid}"),
                );
                return Out::Blocked;
            }
            let mut chosen = None;
            let mut last = Out::Blocked;
            for cand in &candidates {
                let res = self.resolve_obj(*cand, depth + 1, visiting);
                if let Out::Ok(oid) = res {
                    chosen = Some((*cand, oid));
                    break;
                }
                last = res;
                if last == Out::Cycle || last == Out::Paused {
                    break;
                }
            }
            match chosen {
                Some((cid, _oid)) => {
                    let short = &base_oid[..base_oid.len().min(12)];
                    (cid, format!("oid {short}"), Some(base_oid.clone()))
                }
                None => {
                    return self.dep_failure(id, candidates[0], "候选 base 均不可用", last);
                }
            }
        };

        let base_outcome = self.resolve_obj(base_id, depth + 1, visiting);
        if let Out::Ok(_) = base_outcome {
            // 候选循环里可能已经解析成功;ofs 分支在此解析。
        } else {
            return self.dep_failure(id, base_id, "base 未还原", base_outcome);
        }

        let base_row: Option<(Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT content, final_type FROM objects WHERE id=?1 AND status='ok'",
                [base_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let (base_content, final_type) = match base_row {
            Some(v) => v,
            None => {
                self.set_blocked(id, &[("obj", base_id.to_string())], "base 缺少内容");
                return Out::Blocked;
            }
        };

        let bytes = match self.file_bytes(file_id) {
            Ok(b) => b,
            Err(e) => {
                self.set_error(id, &e);
                return Out::Error;
            }
        };
        let start = comp_start as usize;
        let end = start + comp_len as usize;
        if end > bytes.len() {
            self.set_error(id, "delta 压缩数据越界");
            return Out::Error;
        }
        let delta_plain = match gitobj::inflate(&bytes[start..end]) {
            Ok((d, _)) => d,
            Err(e) => {
                self.set_error(id, &e);
                return Out::Error;
            }
        };

        let in_len = base_content.len() as i64;
        match gitobj::apply_delta(&base_content, &delta_plain) {
            Ok(outcome) => {
                let out_len = outcome.result.len() as i64;
                let note = format!(
                    "base_size={} result_size={}",
                    outcome.base_size, outcome.result_size
                );
                self.record_step(
                    id,
                    &base_desc,
                    outcome.instr_start as i64,
                    outcome.instr_end as i64,
                    in_len,
                    out_len,
                    true,
                    &note,
                );
                if !self.budget_check(id, out_len, in_len) {
                    return Out::Paused;
                }
                let oid = gitobj::git_oid(&final_type, &outcome.result);
                self.store_ok(id, &oid, &final_type, &outcome.result);
                self.conn
                    .execute(
                        "INSERT OR REPLACE INTO links(object_id, base_object_id, base_oid) VALUES (?1,?2,?3)",
                        params![id, base_id, link_oid],
                    )
                    .ok();
                Out::Ok(oid)
            }
            Err(e) => {
                self.record_step(id, &base_desc, 0, 0, in_len, 0, false, &e);
                self.evidence(Some(file_id), Some(id), "error", &e);
                self.set_error(id, &e);
                Out::Error
            }
        }
    }
}

/// 不动点式还原:每轮只扫描 pending/blocked;ok 对象直接复用缓存,
/// 因此补入 base 后只有受影响的依赖子图会被重新计算。
pub fn resolve_all(conn: &Connection, data_dir: &Path) -> rusqlite::Result<RunStats> {
    let budget = get_budget(conn)?;
    let mut ctx = Ctx {
        conn,
        data_dir,
        budget,
        used: budget.used_bytes,
        stats: RunStats::default(),
        file_cache: HashMap::new(),
    };
    loop {
        let ids: Vec<i64> = {
            let mut stmt =
                conn.prepare("SELECT id FROM objects WHERE status IN ('pending','blocked') ORDER BY id")?;
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if ids.is_empty() {
            break;
        }
        let mut progress = false;
        for id in ids {
            let mut visiting = Vec::new();
            if let Out::Ok(_) = ctx.resolve_obj(id, 0, &mut visiting) {
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    conn.execute(
        "UPDATE budget SET used_bytes=?1 WHERE id=1",
        params![ctx.used],
    )?;
    Ok(ctx.stats)
}

/// 预算恢复:paused 对象回到 pending,用量清零,再跑到下一个不动点。
pub fn resume(conn: &Connection, data_dir: &Path) -> rusqlite::Result<RunStats> {
    conn.execute(
        "UPDATE objects SET status='pending', error=NULL WHERE status='paused'",
        [],
    )?;
    conn.execute("UPDATE budget SET used_bytes=0 WHERE id=1", [])?;
    resolve_all(conn, data_dir)
}

pub fn reset_object(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE objects SET status='pending', error=NULL, oid=NULL, final_type=NULL, content=NULL WHERE id=?1",
        [id],
    )?;
    conn.execute("DELETE FROM links WHERE object_id=?1", [id])?;
    conn.execute("DELETE FROM blocking WHERE object_id=?1", [id])?;
    conn.execute("DELETE FROM delta_steps WHERE object_id=?1", [id])?;
    Ok(())
}

/// 文件删除前/删除时需要连带失效的对象(通过 links 传递闭包)。
pub fn dependents_of_file(conn: &Connection, file_id: i64) -> rusqlite::Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE deps(id) AS (
            SELECT id FROM objects WHERE file_id = ?1
            UNION
            SELECT l.object_id FROM links l JOIN deps d ON l.base_object_id = d.id
         )
         SELECT DISTINCT id FROM deps ORDER BY id",
    )?;
    let rows = stmt.query_map([file_id], |r| r.get::<_, i64>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

fn dependents_of_objects(conn: &Connection, seed: &[i64]) -> rusqlite::Result<Vec<i64>> {
    if seed.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = seed.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "WITH RECURSIVE deps(id) AS (
            SELECT * FROM (VALUES {vals})
            UNION
            SELECT l.object_id FROM links l JOIN deps d ON l.base_object_id = d.id
         )
         SELECT DISTINCT id FROM deps ORDER BY id",
        vals = placeholders.replace("?", "(?)")
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(seed.iter()), |r| {
        r.get::<_, i64>(0)
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn delete_file(conn: &Connection, data_dir: &Path, file_id: i64) -> rusqlite::Result<()> {
    for dep in dependents_of_file(conn, file_id)? {
        reset_object(conn, dep)?;
    }
    conn.execute(
        "DELETE FROM links WHERE object_id IN (SELECT id FROM objects WHERE file_id=?1)
            OR base_object_id IN (SELECT id FROM objects WHERE file_id=?1)",
        [file_id],
    )?;
    conn.execute(
        "DELETE FROM blocking WHERE object_id IN (SELECT id FROM objects WHERE file_id=?1)",
        [file_id],
    )?;
    conn.execute(
        "DELETE FROM delta_steps WHERE object_id IN (SELECT id FROM objects WHERE file_id=?1)",
        [file_id],
    )?;
    conn.execute("DELETE FROM evidence WHERE file_id=?1", [file_id])?;
    let rel: Option<String> = conn
        .query_row("SELECT path FROM files WHERE id=?1", [file_id], |r| r.get(0))
        .optional()?;
    conn.execute("DELETE FROM files WHERE id=?1", [file_id])?;
    if let Some(rel) = rel {
        std::fs::remove_file(data_dir.join(rel)).ok();
    }
    resolve_all(conn, data_dir)?;
    Ok(())
}

/// 固定/取消某个冲突来源,只重算引用该 base oid 的子图(形成分析分支)。
pub fn pin_oid(
    conn: &Connection,
    data_dir: &Path,
    oid: &str,
    object_id: Option<i64>,
) -> rusqlite::Result<()> {
    match object_id {
        Some(id) => conn.execute(
            "INSERT OR REPLACE INTO pins(oid, object_id) VALUES (?1,?2)",
            params![oid, id],
        )?,
        None => conn.execute("DELETE FROM pins WHERE oid=?1", [oid])?,
    };
    let seed: Vec<i64> = conn
        .prepare("SELECT object_id FROM links WHERE base_oid=?1")?
        .query_map([oid], |r| r.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let affected = dependents_of_objects(conn, &seed)?;
    for id in affected {
        reset_object(conn, id)?;
    }
    resolve_all(conn, data_dir)?;
    Ok(())
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn evidence(
    conn: &Connection,
    file_id: Option<i64>,
    object_id: Option<i64>,
    level: &str,
    msg: &str,
) {
    conn.execute(
        "INSERT INTO evidence(file_id, object_id, level, message) VALUES (?1,?2,?3,?4)",
        params![file_id, object_id, level, msg],
    )
    .ok();
}

fn detect_kind(name: &str, bytes: &[u8]) -> &'static str {
    if name.ends_with(".pack") {
        "pack"
    } else if name.ends_with(".idx") {
        "idx"
    } else if gitobj::parse_loose(bytes).is_ok() {
        "loose"
    } else {
        "unknown"
    }
}

/// index ↔ pack 交叉校验:按文件名 stem 配对,核对对象存在性与 CRC。
fn cross_check_all(conn: &Connection, data_dir: &Path) {
    let idxs: Vec<(i64, String)> = conn
        .prepare("SELECT id, name FROM files WHERE kind='idx' ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    for (idx_id, idx_name) in idxs {
        conn.execute(
            "DELETE FROM evidence WHERE file_id=?1 AND
                (message LIKE '%CRC%' OR message LIKE '%不配套%' OR message LIKE '%找不到同 stem%')",
            [idx_id],
        ).ok();
        let stem = idx_name.trim_end_matches(".idx").to_string();
        let pack: Option<(i64, String)> = conn
            .prepare(
                "SELECT id, path FROM files WHERE kind='pack' AND (name=?1 OR name=?2) ORDER BY digest LIMIT 1",
            )
            .unwrap()
            .query_map(
                params![format!("{stem}.pack"), format!("{stem}.PACK")],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .unwrap()
            .filter_map(|r| r.ok())
            .next();
        let Some((pack_id, pack_rel)) = pack else {
            evidence(
                conn,
                Some(idx_id),
                None,
                "warn",
                &format!("index {idx_name} 找不到同 stem 的 .pack, 跳过 CRC 核对"),
            );
            continue;
        };
        let pack_bytes = match std::fs::read(data_dir.join(&pack_rel)) {
            Ok(b) => b,
            Err(e) => {
                evidence(conn, Some(idx_id), None, "error", &format!("读取 pack 失败: {e}"));
                continue;
            }
        };
        let entries: Vec<(i64, String, u32, i64)> = conn
            .prepare("SELECT id, oid, crc32, offset FROM idx_entries WHERE file_id=?1 ORDER BY id")
            .unwrap()
            .query_map([idx_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for (entry_id, oid, idx_crc, off) in entries {
            let obj: Option<(i64, i64, i64)> = conn
                .query_row(
                    "SELECT id, comp_start, comp_len FROM objects WHERE file_id=?1 AND offset=?2",
                    params![pack_id, off],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .ok();
            let Some((obj_id, comp_start, comp_len)) = obj else {
                evidence(
                    conn,
                    Some(idx_id),
                    None,
                    "error",
                    &format!("index 与 pack 不配套: oid {oid} 偏移 {off} 在 pack 中无对象"),
                );
                continue;
            };
            let end = (comp_start + comp_len) as usize;
            if end > pack_bytes.len() {
                evidence(conn, Some(idx_id), Some(obj_id), "error", "CRC 核对时压缩数据越界");
                continue;
            }
            let real_crc = crc32fast::hash(&pack_bytes[off as usize..end]);
            conn.execute(
                "UPDATE idx_entries SET object_id=?1 WHERE id=?2",
                params![obj_id, entry_id],
            )
            .ok();
            conn.execute(
                "UPDATE objects SET idx_crc=?1, data_crc=?2 WHERE id=?3",
                params![idx_crc as i64, real_crc as i64, obj_id],
            )
            .ok();
            if real_crc != idx_crc {
                evidence(
                    conn,
                    Some(idx_id),
                    Some(obj_id),
                    "error",
                    &format!(
                        "错误 CRC: oid {oid} 偏移 {off}, index 声明 {:08x}, 实际 {:08x}",
                        idx_crc, real_crc
                    ),
                );
            }
        }
    }
}

/// 导入文件:落盘到项目数据目录,保留内容摘要与原始偏移,解析后跑还原。
/// 同内容文件去重,重复导入返回已有 file id。
pub fn import_bytes(
    conn: &Connection,
    data_dir: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<i64, String> {
    let name = sanitize_name(name);
    let digest = gitobj::digest_hex(bytes);
    if let Some(id) = conn
        .query_row("SELECT id FROM files WHERE digest=?1", [&digest], |r| {
            r.get::<_, i64>(0)
        })
        .optional()
        .map_err(|e| e.to_string())?
    {
        return Ok(id);
    }
    let rel = format!("incoming/{}_{}", &digest[..10], name);
    let full = data_dir.join(&rel);
    std::fs::create_dir_all(full.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&full, bytes).map_err(|e| e.to_string())?;
    let kind = detect_kind(&name, bytes);
    conn.execute(
        "INSERT INTO files(name, path, kind, digest, size) VALUES (?1,?2,?3,?4,?5)",
        params![name, rel, kind, digest, bytes.len() as i64],
    )
    .map_err(|e| e.to_string())?;
    let file_id = conn.last_insert_rowid();
    evidence(conn, Some(file_id), None, "info", &format!(
        "导入 {name}: kind={kind}, {} 字节, digest={digest}",
        bytes.len()
    ));

    match kind {
        "pack" => match gitobj::parse_pack(bytes) {
            Ok(info) => {
                evidence(
                    conn,
                    Some(file_id),
                    None,
                    "info",
                    &format!(
                        "pack header: 版本 {} 对象数 {} (声明 {})",
                        info.version,
                        info.objects.len(),
                        info.count
                    ),
                );
                if info.objects.len() as u32 != info.count {
                    evidence(conn, Some(file_id), None, "error", &format!(
                        "pack 对象数欺骗: 头部声明 {}, 实际解析 {}",
                        info.count, info.objects.len()
                    ));
                }
                if info.trailer_ok {
                    evidence(conn, Some(file_id), None, "info", "pack 尾部 SHA-1 校验和 OK");
                } else {
                    evidence(conn, Some(file_id), None, "error",
                        "pack 尾部 SHA-1 校验和不匹配或长度未对齐");
                }
                for o in &info.objects {
                    conn.execute(
                        "INSERT INTO objects(file_id, offset, otype, hdr_size, base_ofs, base_oid, comp_start, comp_len)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                        params![
                            file_id,
                            o.offset as i64,
                            o.otype.name(),
                            o.hdr_size as i64,
                            o.base_ofs,
                            o.base_oid,
                            o.comp_start as i64,
                            o.comp_len as i64
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            Err(e) => evidence(conn, Some(file_id), None, "error", &format!("pack 解析失败: {e}")),
        },
        "idx" => match gitobj::parse_idx(bytes) {
            Ok(info) => {
                let head: Vec<String> = info.fanout[..8].iter().map(|v| v.to_string()).collect();
                evidence(conn, Some(file_id), None, "info", &format!(
                    "index fanout: fanout[0..8]=[{}], fanout[255]={}",
                    head.join(","),
                    info.fanout[255]
                ));
                if !info.fanout_ok {
                    evidence(conn, Some(file_id), None, "error", "index fanout 非单调递增");
                }
                if info.fanout[255] as usize != info.entries.len() {
                    evidence(conn, Some(file_id), None, "error",
                        "index fanout 总数与条目数不一致");
                }
                for e in &info.entries {
                    conn.execute(
                        "INSERT INTO idx_entries(file_id, oid, offset, crc32) VALUES (?1,?2,?3,?4)",
                        params![file_id, e.oid, e.offset as i64, e.crc32 as i64],
                    )
                    .map_err(|e2| e2.to_string())?;
                }
            }
            Err(e) => evidence(conn, Some(file_id), None, "error", &format!("idx 解析失败: {e}")),
        },
        "loose" => match gitobj::parse_loose(bytes) {
            Ok((otype, content, consumed)) => {
                let oid = gitobj::git_oid(&otype, &content);
                conn.execute(
                    "INSERT INTO objects(file_id, offset, otype, hdr_size, comp_start, comp_len,
                        status, oid, final_type, content, gen)
                     VALUES (?1,0,?2,?3,0,?4,'ok',?5,?6,?7,1)",
                    params![file_id, otype, content.len() as i64, consumed as i64, oid, otype, content],
                )
                .map_err(|e| e.to_string())?;
            }
            Err(e) => evidence(conn, Some(file_id), None, "error", &format!("loose 解析失败: {e}")),
        },
        other => evidence(
            conn,
            Some(file_id),
            None,
            "error",
            &format!("无法识别的文件类型 {other}: 既不是 pack/index 也不是 loose object"),
        ),
    }

    cross_check_all(conn, data_dir);
    resolve_all(conn, data_dir).map_err(|e| e.to_string())?;
    Ok(file_id)
}

/// 统计所有同一 oid 有多个已还原候选的来源(导入顺序无关,按源摘要排序)。
pub fn conflicting_oids(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT oid FROM objects WHERE status='ok' AND oid IS NOT NULL
         GROUP BY oid HAVING COUNT(*) > 1 ORDER BY oid",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

#[allow(dead_code)]
fn assert_type_codes() {
    let _ = ObjType::Blob;
}
