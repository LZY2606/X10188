//! 文件导入：保存到数据目录，解析 pack / index / loose object，写入 SQLite，
//! 随后执行 index↔pack 配套核对与受影响依赖子图重算。

use crate::gitcore::{
    git_oid, inflate_zlib, is_full_type, oid_hex, parse_index, parse_loose, parse_pack,
    DeltaBase, OBJ_OFS_DELTA, OBJ_REF_DELTA,
};
use crate::resolve;
use crate::store::{self, Budgets};
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub source_id: Option<i64>,
    pub kind: String,
    pub deduped: bool,
    pub objects: i64,
    pub message: String,
}

fn detect_kind(name: &str, data: &[u8]) -> String {
    let lower = name.to_ascii_lowercase();
    if data.starts_with(b"PACK") {
        "pack".to_string()
    } else if data.starts_with(b"\xfftOc") {
        "index".to_string()
    } else if lower.ends_with(".pack") {
        "pack".to_string()
    } else if lower.ends_with(".idx") {
        "index".to_string()
    } else {
        // loose object 无法从魔数识别，统一作为 loose 尝试。
        "loose".to_string()
    }
}

fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 从服务端本地路径复制导入（所有输入只留在项目数据目录）。
pub fn import_path(conn: &mut Connection, data_dir: &Path, src: &Path) -> Result<ImportResult> {
    let data = std::fs::read(src)
        .map_err(|e| anyhow!("读取 {} 失败: {e}", src.display()))?;
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "upload".to_string());
    import_bytes(conn, data_dir, &name, data)
}

pub fn import_bytes(
    conn: &mut Connection,
    data_dir: &Path,
    orig_name: &str,
    data: Vec<u8>,
) -> Result<ImportResult> {
    let digest = sha256(&data);
    if let Some(existing) = store::source_exists_by_sha256(conn, &digest)? {
        return Ok(ImportResult {
            source_id: Some(existing),
            kind: "duplicate".to_string(),
            deduped: true,
            objects: 0,
            message: "内容相同的来源已存在，跳过".to_string(),
        });
    }

    let kind = detect_kind(orig_name, &data);
    let tx_holder;
    let saved = {
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir)?;
        let safe = sanitize_name(orig_name);
        let fname = format!("{digest:.16}_{safe}");
        let path = files_dir.join(fname);
        std::fs::write(&path, &data)?;
        path
    };

    let mut parse_error: Option<String> = None;
    let mut object_count = 0i64;

    let source_id = conn.transaction::<i64, anyhow::Error, _>(|tx| {
        tx.execute(
            "INSERT INTO sources (path,orig_name,kind,size,sha256,status,error) \
             VALUES (?1,?2,?3,?4,?5,'ok',NULL)",
            params![path_string(&saved), orig_name, kind, data.len() as i64, digest],
        )?;
        let source_id = tx.last_insert_rowid();

        match kind.as_str() {
            "pack" => {
                if let Err(e) = insert_pack(tx, source_id, &data) {
                    parse_error = Some(e.to_string());
                    tx.execute(
                        "UPDATE sources SET status='error',error=?1 WHERE id=?2",
                        params![e.to_string(), source_id],
                    )?;
                    tx.execute(
                        "INSERT INTO packs (source_id,error) VALUES (?1,?2)",
                        params![source_id, e.to_string()],
                    )?;
                } else {
                    object_count = tx.query_row(
                        "SELECT COUNT(*) FROM objects WHERE source_id=?1",
                        params![source_id],
                        |r| r.get(0),
                    )?;
                }
            }
            "index" => {
                if let Err(e) = insert_index(tx, source_id, &data) {
                    parse_error = Some(e.to_string());
                    tx.execute(
                        "UPDATE sources SET status='error',error=?1 WHERE id=?2",
                        params![e.to_string(), source_id],
                    )?;
                }
            }
            _ => {
                if let Err(e) = insert_loose(tx, source_id, &data) {
                    parse_error = Some(e.to_string());
                    tx.execute(
                        "UPDATE sources SET status='error',error=?1 WHERE id=?2",
                        params![e.to_string(), source_id],
                    )?;
                } else {
                    object_count = 1;
                }
            }
        }
        Ok(source_id)
    });

    let source_id = source_id?;

    // 导入后：index 配套核对（全部重算一次，成本极低）。
    reconcile_indexes(conn)?;
    // 只重算受影响的依赖子图。
    let budgets = store::get_budgets(conn)?;
    let report = resolve::recompute_affected(conn, data_dir, &budgets)?;

    let message = match parse_error {
        Some(e) => format!("{kind} 已隔离为坏来源：{e}"),
        None if report.budget_exhausted => format!("{kind} 导入完成，但预算耗尽，部分对象暂停可重试"),
        None => format!("{kind} 导入完成，{object_count} 个对象已登记"),
    };

    Ok(ImportResult {
        source_id: Some(source_id),
        kind,
        deduped: false,
        objects: object_count,
        message,
    })
}

fn path_string(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if matches!(c, '/' | '\\' | ':' | ' ') { '_' } else { c })
        .collect()
}
