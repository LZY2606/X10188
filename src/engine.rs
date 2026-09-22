use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::params;

use crate::db::Db;
use crate::import::ImportReport;

pub struct Engine {
    pub db: Mutex<Db>,
}

#[derive(Debug, Clone)]
pub struct ImportOutcome {
    pub report: ImportReport,
    pub warnings: Vec<String>,
}

impl Engine {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        Ok(Engine {
            db: Mutex::new(Db::open(data_dir)?),
        })
    }

    pub fn data_dir(&self) -> PathBuf {
        self.db.lock().unwrap().data_dir.clone()
    }

    fn files_dir_of(db: &Db) -> PathBuf {
        db.files_dir()
    }

    pub fn import_bytes(&self, filename: &str, buf: &[u8], oid_hint: Option<&str>) -> Result<ImportOutcome, String> {
        let mut db = self.db.lock().unwrap();
        let kind = crate::import::sniff_kind(buf);
        let fp = crate::db::fingerprint_hex(buf);
        let rel = crate::import::store_file(&Self::files_dir_of(&db), &fp, filename, buf)
            .map_err(|e| e.to_string())?;
        let dir = db.data_dir.clone();
        let tx = db.conn.transaction().map_err(|e| e.to_string())?;
        let mut warnings: Vec<String> = Vec::new();

        let report = match kind {
            "pack" => import_pack(&tx, filename, &rel, buf, &fp, &mut warnings)?,
            "index" => import_index(&tx, filename, &rel, buf, &fp, &mut warnings)?,
            _ => import_loose(&tx, filename, &rel, buf, &fp, oid_hint, &mut warnings)?,
        };

        // 任意导入后，尝试把“未附着的 index”与“checksum 相等的 pack”配对
        attach_pending(&tx, &dir, &mut warnings);

        tx.commit().map_err(|e| e.to_string())?;
        Ok(ImportOutcome { report, warnings })
    }
}

fn import_pack(
    tx: &rusqlite::Transaction,
    filename: &str,
    rel: &str,
    buf: &[u8],
    fp: &str,
    warnings: &mut Vec<String>,
) -> Result<ImportReport, String> {
    let parsed = crate::pack::parse_pack(buf);
    let source_id = crate::import::insert_source(&**tx, "pack", filename, rel, buf.len(), fp)
        .map_err(|e| e.to_string())?;

    crate::import::persist_pack(&**tx, source_id, &parsed, None);

    if let Some(f) = &parsed.fatal {
        warnings.push(format!("pack 包级问题：{}", f));
    }
    if !parsed.checksum_ok {
        warnings.push(format!(
            "pack SHA-1 校验失败：期望 {}，实际 {}",
            parsed.trailer_sha.hex(),
            parsed.computed_sha.hex()
        ));
    }

    Ok(ImportReport {
        source_id,
        kind: "pack".to_string(),
        candidates: parsed.entries.len(),
        fatal: parsed.fatal.as_ref().map(|e| e.to_string()),
        note: None,
    })
}

fn import_index(
    tx: &rusqlite::Transaction,
    filename: &str,
    rel: &str,
    buf: &[u8],
    fp: &str,
    warnings: &mut Vec<String>,
) -> Result<ImportReport, String> {
    let parsed = crate::index::parse_index(buf);
    let source_id = crate::import::insert_source(&**tx, "index", filename, rel, buf.len(), fp)
        .map_err(|e| e.to_string())?;

    let (status, fatal_s) = match &parsed.fatal {
        Some(e) => ("fatal", Some(e.to_string())),
        None => ("ok", None),
    };
    tx.execute(
        "UPDATE sources SET idx_pack_checksum=?1, status=?2, note=?3 WHERE id=?4",
        params![parsed.pack_checksum.hex(), status, fatal_s, source_id],
    )
    .map_err(|e| e.to_string())?;

    crate::import::persist_index_fanout(&**tx, source_id, &parsed);
    if !parsed.idx_checksum_ok && parsed.fatal.is_none() {
        warnings.push(format!(
            "index#{} 自身 SHA-1 校验失败：期望 {}，实际 {}",
            source_id,
            parsed.idx_trailer.hex(),
            parsed.idx_computed.hex()
        ));
    }
    if let Some(f) = &parsed.fatal {
        warnings.push(format!("index 解析失败：{}", f));
    }

    Ok(ImportReport {
        source_id,
        kind: "index".to_string(),
        candidates: parsed.entries.len(),
        fatal: parsed.fatal.as_ref().map(|e| e.to_string()),
        note: None,
    })
}

fn import_loose(
    tx: &rusqlite::Transaction,
    filename: &str,
    rel: &str,
    buf: &[u8],
    fp: &str,
    oid_hint: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<ImportReport, String> {
    let source_id = crate::import::insert_source(&**tx, "loose", filename, rel, buf.len(), fp)
        .map_err(|e| e.to_string())?;
    match crate::loose::parse_loose(buf) {
        Ok(pl) => {
            if let Some(hint) = oid_hint {
                if hint != pl.computed_oid.hex() {
                    warnings.push(format!(
                        "loose 路径 oid {} 与内容重算 oid {} 不一致",
                        hint,
                        pl.computed_oid.hex()
                    ));
                    tx.execute(
                        "UPDATE sources SET status='fatal', note=?1 WHERE id=?2",
                        params![
                            format!("loose oid 不匹配：路径 {}，内容 {}", hint, pl.computed_oid.hex()),
                            source_id
                        ],
                    )
                    .ok();
                }
            }
            crate::import::persist_loose(&**tx, source_id, &pl, oid_hint);
            Ok(ImportReport {
                source_id,
                kind: "loose".to_string(),
                candidates: 1,
                fatal: None,
                note: Some(pl.computed_oid.hex()),
            })
        }
        Err(e) => {
            tx.execute(
                "UPDATE sources SET status='fatal', note=?1 WHERE id=?2",
                params![e.to_string(), source_id],
            )
            .map_err(|e2| e2.to_string())?;
            warnings.push(format!("loose 解析失败：{}", e));
            Ok(ImportReport {
                source_id,
                kind: "loose".to_string(),
                candidates: 0,
                fatal: Some(e.to_string()),
                note: None,
            })
        }
    }
}


/// 配对：对每个未附着 index，找 pack_checksum 相等的 pack；
/// 找到后给该 pack 的候选回填 claim oid / crc，并做 CRC 取证。
fn attach_pending(tx: &rusqlite::Transaction, dir: &Path, warnings: &mut Vec<String>) {
    crate::attach::attach_all(tx, dir, warnings);
}

// ================= 分析入口 =================

use crate::resolve::{affected_subgraph, Resolver, RunStats};
use crate::types::Budget;

impl Engine {
    /// 全量分析（可给自定义预算；分支可固定冲突来源 source）。
    pub fn analyze(&self, budget: Option<Budget>, pinned_source: Option<i64>) -> Result<RunStats, String> {
        let mut db = self.db.lock().unwrap();
        let tx = db.conn.transaction().map_err(|e| e.to_string())?;
        let mut resolver = Resolver::new(&tx, budget.unwrap_or_default(), pinned_source);
        let stats = resolver.run(None);
        tx.commit().map_err(|e| e.to_string())?;
        Ok(stats)
    }

    /// 仅重试当前处于可重试状态的对象（预算放开后的“恢复”）。
    pub fn resume(&self, budget: Option<Budget>, pinned_source: Option<i64>) -> Result<RunStats, String> {
        let mut db = self.db.lock().unwrap();
        let tx = db.conn.transaction().map_err(|e| e.to_string())?;
        let ids: Vec<i64> = {
            let mut stmt = tx
                .prepare("SELECT id, status FROM candidates")
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            while let Some(r) = rows.next().map_err(|e| e.to_string())? {
                let id: i64 = r.get(0).map_err(|e| e.to_string())?;
                let st: String = r.get(1).map_err(|e| e.to_string())?;
                if crate::types::status::retriable(&st) {
                    out.push(id);
                }
            }
            out
        };
        let mut resolver = Resolver::new(&tx, budget.unwrap_or_default(), pinned_source);
        let stats = resolver.run(Some(ids));
        tx.commit().map_err(|e| e.to_string())?;
        Ok(stats)
    }

    /// 补入 base 后：仅重算受影响的依赖子图。
    /// `seeds` 为新增/变化候选 id；为空时自动取本次尚未分析(pending)者。
    pub fn analyze_after_import(
        &self,
        seeds: Vec<i64>,
        budget: Option<Budget>,
        pinned_source: Option<i64>,
    ) -> Result<RunStats, String> {
        let mut db = self.db.lock().unwrap();
        let tx = db.conn.transaction().map_err(|e| e.to_string())?;

        // 先把 seed 中新候选（pending）以及此前 missing/paused 的对象状态重置，
        // 这样 affected_subgraph 可基于最新 edges（旧 ref 缺失边可能 to 为 NULL）。
        let seeds = if seeds.is_empty() {
            let mut stmt = tx
                .prepare("SELECT id FROM candidates WHERE status='pending'")
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            let mut v = Vec::new();
            while let Some(r) = rows.next().map_err(|e| e.to_string())? {
                v.push(r.get::<_, i64>(0).map_err(|e| e.to_string())?);
            }
            v
        } else {
            seeds
        };

        // 需要先有边：对所有未解析 delta 重建一次边信息（用一次临时 resolver 的定位结果落库）
        {
            let pre = Resolver::new(&tx, budget.unwrap_or_default(), pinned_source);
            pre.rebuild_edges_public(&seeds);
        }

        let mut targets = affected_subgraph(&tx, &seeds);
        targets.sort();

        // 重置 targets 中非终态坏对象为 pending，保证被重新评估
        for &id in &targets {
            tx.execute(
                "UPDATE candidates SET status='pending'
                 WHERE id=?1 AND status IN ('missing_base','paused','depth_limit','pending','resolving')",
                params![id],
            )
            .map_err(|e| e.to_string())?;
        }

        let mut resolver = Resolver::new(&tx, budget.unwrap_or_default(), pinned_source);
        let stats = resolver.run(Some(targets));
        tx.commit().map_err(|e| e.to_string())?;
        Ok(stats)
    }
}
