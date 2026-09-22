use std::path::Path;

use crc32fast::Hasher as CrcHasher;
use rusqlite::params;

/// 配对所有“未附着 index”与“checksum 相等 pack”，回填 claim oid 与 CRC 取证。
pub fn attach_all(tx: &rusqlite::Transaction, data_dir: &Path, warnings: &mut Vec<String>) {
    // 收集所有 pack：(id, stored_rel, computed_checksum)
    let packs: Vec<(i64, String, String)> = tx
        .prepare("SELECT id, stored_path, pack_checksum FROM sources WHERE kind='pack'")
        .into_iter()
        .flat_map(|mut stmt| {
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .into_iter()
            .flat_map(|rows| rows.flatten())
            .filter_map(|(id, rel, cs)| cs.map(|c| (id, rel, c)))
            .collect::<Vec<_>>()
        })
        .collect();

    // 收集所有未附着 index
    let idxs: Vec<(i64, String, String)> = tx
        .prepare(
            "SELECT id, stored_path, idx_pack_checksum FROM sources
             WHERE kind='index' AND attached_pack_id IS NULL",
        )
        .into_iter()
        .flat_map(|mut stmt| {
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .into_iter()
            .flat_map(|rows| rows.flatten())
            .collect::<Vec<_>>()
        })
        .collect();

    for (idx_id, idx_rel, idx_cs) in idxs {
        let idx_path = data_dir.join("files").join(&idx_rel);
        let idx_bytes = match std::fs::read(&idx_path) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("读取 index#{} 失败：{}", idx_id, e));
                continue;
            }
        };
        let parsed_idx = crate::index::parse_index(&idx_bytes);
        if parsed_idx.fatal.is_some() {
            continue;
        }

        // 找 checksum 相等的 pack；选择“还没有任何 index 附着”或按稳定顺序的一个。
        let mut matching: Vec<&(i64, String, String)> =
            packs.iter().filter(|(_, _, cs)| *cs == idx_cs).collect();
        matching.sort_by_key(|(id, _, _)| *id);

        // 已被（其它）index 占用的 pack 集合
        let occupied: std::collections::BTreeSet<i64> = tx
            .prepare("SELECT attached_pack_id FROM sources WHERE kind='index' AND attached_pack_id IS NOT NULL")
            .into_iter()
            .flat_map(|mut st| {
                st.query_map([], |r| r.get::<_, i64>(0))
                    .into_iter()
                    .flat_map(|rows| rows.flatten())
                    .collect::<Vec<_>>()
            })
            .collect();

        let chosen = matching
            .iter()
            .copied()
            .find(|(id, _, _)| !occupied.contains(id))
            .or_else(|| matching.first().copied());

        let (pack_id, pack_rel) = match chosen {
            Some((id, rel, _)) => (*id, rel.clone()),
            None => {
                tx.execute(
                    "UPDATE sources SET status='mismatch', note=?1 WHERE id=?2",
                    params![
                        format!("找不到 pack_checksum={} 的 pack（index 与 pack 不配套/缺 pack）", idx_cs),
                        idx_id
                    ],
                )
                .ok();
                warnings.push(format!("index#{} 找不到配套 pack（{}）", idx_id, idx_cs));
                continue;
            }
        };
        let pack_bytes = match std::fs::read(data_dir.join("files").join(&pack_rel)) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("读取 pack#{} 失败：{}", pack_id, e));
                continue;
            }
        };
        let parsed_pack = crate::pack::parse_pack(&pack_bytes);

        attach_one(
            tx,
            pack_id,
            idx_id,
            &parsed_pack,
            &parsed_idx,
            warnings,
        );
    }
}

fn attach_one(
    tx: &rusqlite::Transaction,
    pack_id: i64,
    idx_id: i64,
    pack: &crate::pack::ParsedPack,
    idx: &crate::index::ParsedIndex,
    warnings: &mut Vec<String>,
) {
    // index fanout 与对象数一致性
    let fan_n = idx.fanout.cumulative[255] as usize;
    if fan_n != pack.entries.len() {
        warnings.push(format!(
            "index#{} fanout 对象数 {} 与 pack#{} 解析对象数 {} 不一致（index 与 pack 不配套）",
            idx_id, fan_n, pack_id, pack.entries.len()
        ));
    }

    tx.execute(
        "UPDATE sources SET attached_pack_id=?1 WHERE id=?2",
        params![pack_id, idx_id],
    )
    .ok();

    let mut by_offset: std::collections::BTreeMap<u64, &crate::pack::ParsedEntry> =
        std::collections::BTreeMap::new();
    for e in &pack.entries {
        by_offset.insert(e.offset, e);
    }

    for ie in &idx.entries {
        // 按偏移定位候选并回填 claim oid + CRC 校验
        let cand_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM candidates WHERE source_id=?1 AND pack_offset=?2",
                params![pack_id, ie.offset as i64],
                |r| r.get(0),
            )
            .ok();
        let cand_id = match cand_id {
            Some(c) => c,
            None => {
                warnings.push(format!(
                    "index#{} 记录偏移 {} 在 pack#{} 中找不到对象（不配套）",
                    idx_id, ie.offset, pack_id
                ));
                continue;
            }
        };

        tx.execute(
            "UPDATE candidates SET claim_oid=?1, idx_crc=?2 WHERE id=?3",
            params![ie.oid.hex(), ie.crc32.map(|c| c as i64), cand_id],
        )
        .ok();

        // CRC32 取证：对该偏移对象的压缩数据重新计算
        if let Some(expected) = ie.crc32 {
            if let Some(entry) = by_offset.get(&ie.offset) {
                let mut h = CrcHasher::new();
                h.update(&entry.compressed);
                let actual = h.finalize();
                let ok = actual == expected;
                tx.execute(
                    "UPDATE candidates SET crc_ok=?1 WHERE id=?2",
                    params![ok as i64, cand_id],
                )
                .ok();
                if !ok && entry.error.is_none() {
                    // 坏 CRC：隔离该对象
                    let msg = crate::error::PError::CrcMismatch {
                        offset: ie.offset,
                        expected,
                        actual,
                    }
                    .to_string();
                    tx.execute(
                        "UPDATE candidates SET status='bad', parse_error_code='crc_mismatch', parse_error=?1 WHERE id=?2",
                        params![msg, cand_id],
                    )
                    .ok();
                    warnings.push(format!("candidate#{} {}", cand_id, msg));
                }
            }
        }
    }
}
