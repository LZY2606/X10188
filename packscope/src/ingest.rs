//! Ingestion: classify imported files, parse pack/idx structure, pair indexes
//! with packs, verify per-entry CRC32, and index loose objects.

use anyhow::Result;
use rusqlite::params;
use serde::Serialize;
use std::collections::HashMap;

use crate::db::{next_seq, Db};
use crate::gitfmt::{git_oid, inflate_zlib, parse_loose_body, type_from_name, ObjType};
use crate::pack::{crc32_of_span, parse_idx, parse_pack, IdxSummary, PackSummary};

#[derive(Debug, Clone, Serialize, Default)]
pub struct IngestReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub duplicate: bool,
    pub entries: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

/// Classify by magic bytes first, falling back to filename conventions.
pub fn classify(filename: &str, data: &[u8]) -> FileKind {
    if data.len() >= 4 && &data[0..4] == b"PACK" {
        return FileKind::Pack;
    }
    if data.len() >= 4 && &data[0..4] == b"\xfftOc" {
        return FileKind::Idx;
    }
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") {
        return FileKind::Pack;
    }
    if lower.ends_with(".idx") {
        return FileKind::Idx;
    }
    // Loose objects live at xx/38hex (40 hex chars total).
    if let Some(name) = lower.rsplit('/').next() {
        if let Some(parent) = lower.rsplit('/').nth(1) {
            if parent.len() == 2
                && name.len() == 38
                && parent.chars().all(|c| c.is_ascii_hexdigit())
                && name.chars().all(|c| c.is_ascii_hexdigit())
            {
                return FileKind::Loose;
            }
        }
    }
    FileKind::Unknown
}

impl Db {
    /// Import one file: bytes are copied into the data dir and indexed.
    /// Returns a report (structural parse errors become warnings, never aborts
    /// the whole import).
    pub fn ingest_file(&self, filename: &str, data: &[u8]) -> Result<IngestReport> {
        let kind = classify(filename, data);
        let (_, rel) = self.store_import(filename, data)?;
        let sha = hex::encode(crate::gitfmt::sha1_bytes(data));
        let mut report = IngestReport {
            kind: format!("{kind:?}").to_ascii_lowercase(),
            filename: filename.to_string(),
            ..Default::default()
        };

        {
            let conn = self.conn.lock().unwrap();
            if let Ok(id) = conn.query_row(
                "SELECT id FROM sources WHERE rel_path=?1",
                [&rel],
                |r| r.get::<_, i64>(0),
            ) {
                report.source_id = id;
                report.duplicate = true;
                return Ok(report);
            }
        }

        match kind {
            FileKind::Pack => self.ingest_pack(filename, data, &rel, &sha, &mut report)?,
            FileKind::Idx => self.ingest_idx(filename, data, &rel, &sha, &mut report)?,
            FileKind::Loose => self.ingest_loose(filename, data, &rel, &sha, &mut report)?,
            FileKind::Unknown => {
                self.insert_source("unknown", filename, data, &rel, &sha, "", &mut report)?;
                report.warnings.push("无法识别的文件类型（既不是 pack/idx，也不是 loose 路径 xx/38hex）".into());
            }
        }
        // New evidence may change resolutions for every branch.
        self.invalidate_branches();
        Ok(report)
    }

    fn insert_source(
        &self,
        kind: &str,
        filename: &str,
        data: &[u8],
        rel: &str,
        sha: &str,
        trailer: &str,
        report: &mut IngestReport,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let seq = next_seq(&conn)?;
        conn.execute(
            "INSERT INTO sources(kind,filename,rel_path,bytes,sha1,import_seq,note,trailer_oid)
             VALUES(?1,?2,?3,?4,?5,?6,'',?7)",
            params![kind, filename, rel, data.len() as i64, sha, seq, trailer],
        )?;
        let id = conn.last_insert_rowid();
        report.source_id = id;
        Ok(id)
    }
}

impl Db {
    fn ingest_pack(
        &self,
        filename: &str,
        data: &[u8],
        rel: &str,
        sha: &str,
        report: &mut IngestReport,
    ) -> Result<()> {
        let inflate_cap: usize = self.setting("parse_inflate_cap")?.parse().unwrap_or(256 << 20);
        let source_id = self.insert_source("pack", filename, data, rel, sha, "", report)?;
        let summary: PackSummary = match parse_pack(data, inflate_cap) {
            Ok(s) => s,
            Err(e) => {
                report.warnings.push(format!("pack 结构解析失败：{e}"));
                {
                    let conn = self.conn.lock().unwrap();
                    conn.execute("UPDATE sources SET note=?1 WHERE id=?2",
                        params![format!("fatal: {e}"), source_id])?;
                }
                return Ok(());
            }
        };
        {
            let conn = self.conn.lock().unwrap();
            conn.execute("UPDATE sources SET trailer_oid=?1, note=?2 WHERE id=?3",
                params![summary.trailer_oid, summary.errors.join("; "), source_id])?;
        }
        for w in &summary.errors {
            report.warnings.push(w.clone());
        }

        // Find a paired idx (same pack checksum), mapping oid+crc by offset.
        let idx = self.find_idx_for_pack(&summary.trailer_oid);
        let mut idx_oid_by_off: HashMap<u64, String> = HashMap::new();
        let mut idx_crc_by_off: HashMap<u64, u32> = HashMap::new();
        let mut idx_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut idx_pack_sum = String::new();
        if let Some((isum, _sid)) = &idx {
            idx_pack_sum = isum.pack_checksum.clone();
            for row in &isum.entries {
                idx_oid_by_off.insert(row.offset, row.oid.clone());
                if let Some(crc) = row.crc32 {
                    idx_crc_by_off.insert(row.offset, crc);
                }
                idx_offsets.insert(row.offset);
            }
        }

        let mut conn = self.conn.lock().unwrap();
        let mut seq = 0i64;
        for ent in &summary.entries {
            seq = next_seq(&conn)?;
            let claimed = idx_oid_by_off.get(&ent.offset).cloned();
            let crc_expected = idx_crc_by_off.get(&ent.offset).copied();
            let crc_actual = if ent.inflate_ok {
                Some(crc32_of_span(data, ent.offset, ent.data_end))
            } else {
                None
            };
            if let Some(exp) = crc_expected {
                if crc_actual.map(|a| a != exp).unwrap_or(true) {
                    report.warnings.push(format!(
                        "CRC32 不匹配 @offset {}: idx 记录 {:08x}，实算 {}",
                        ent.offset,
                        exp,
                        crc_actual.map(|c| format!("{c:08x}")).unwrap_or_else(|| "失败".into())
                    ));
                }
            }
            conn.execute(
                "INSERT INTO entries(source_id,entry_kind,claimed_oid,obj_type,declared_size,
                   raw_offset,data_start,data_end,ofs_base_offset,ofs_distance,ref_base_oid,
                   crc32_expected,crc32_actual,inflate_ok,inflate_size,parse_error,parse_seq)
                 VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    source_id,
                    claimed,
                    ent.type_name,
                    ent.declared_size as i64,
                    ent.offset as i64,
                    ent.data_start as i64,
                    ent.data_end as i64,
                    ent.ofs_base_offset.map(|v| v as i64),
                    ent.ofs_distance.map(|v| v as i64),
                    ent.ref_base_oid,
                    crc_expected.map(|c| c as i64),
                    crc_actual.map(|c| c as i64),
                    ent.inflate_ok as i64,
                    ent.inflated_size.map(|v| v as i64),
                    ent.error,
                    seq
                ],
            )?;
            report.entries += 1;
        }
        drop(conn);

        // Offset mismatch diagnostics between idx and pack.
        if let Some((isum, _)) = &idx {
            let pack_offsets: std::collections::HashSet<u64> =
                summary.entries.iter().map(|e| e.offset).collect();
            for off in &idx_offsets {
                if !pack_offsets.contains(off) {
                    report.warnings.push(format!(
                        "idx/pack 不配套：idx 中 offset {off} 在 pack 内不存在"
                    ));
                }
            }
            for e in &summary.entries {
                if !idx_offsets.contains(&e.offset) {
                    report.warnings.push(format!(
                        "idx/pack 不配套：pack offset {} 未出现在 idx 中",
                        e.offset
                    ));
                }
            }
            for w in &isum.errors {
                report.warnings.push(format!("idx 校验：{w}"));
            }
        }
        let _ = idx_pack_sum;
        Ok(())
    }
}

impl Db {
    fn ingest_idx(
        &self,
        filename: &str,
        data: &[u8],
        rel: &str,
        sha: &str,
        report: &mut IngestReport,
    ) -> Result<()> {
        let isum: IdxSummary = match parse_idx(data) {
            Ok(s) => s,
            Err(e) => {
                self.insert_source("idx", filename, data, rel, sha, "", report)?;
                report.warnings.push(format!("idx 结构解析失败：{e}"));
                let sid = report.source_id;
                let conn = self.conn.lock().unwrap();
                conn.execute("UPDATE sources SET note=?1 WHERE id=?2",
                    params![format!("fatal: {e}"), sid])?;
                return Ok(());
            }
        };
        for w in &isum.errors {
            report.warnings.push(w.clone());
        }
        self.insert_source("idx", filename, data, rel, sha, &isum.pack_checksum, report)?;

        // Re-validate CRC/offset pairing if the matching pack is already present.
        if let Some((pack_bytes, pack_source_id)) = self.find_pack_bytes(&isum.pack_checksum) {
            if let Ok(ps) = parse_pack(&pack_bytes, usize::MAX) {
                let conn = self.conn.lock().unwrap();
                for row in &isum.entries {
                    let ent = ps.entries.iter().find(|e| e.offset == row.offset);
                    let (oid_match, crc) = match ent {
                        Some(e) => {
                            let actual = crc32_of_span(&pack_bytes, e.offset, e.data_end);
                            let oid_ok = true; // oid checked after materialization
                            (oid_ok, Some(actual))
                        }
                        None => (false, None),
                    };
                    if !oid_match {
                        report.warnings.push(format!(
                            "idx/pack 不配套：offset {} 在 pack 内不存在", row.offset
                        ));
                    }
                    if let Some(exp) = row.crc32 {
                        if crc.map(|a| a != exp).unwrap_or(true) {
                            report
                                .warnings
                                .push(format!("CRC32 不匹配 @offset {}（oid {})", row.offset, row.oid));
                        }
                    }
                    // Backfill claimed oids/crc onto already-imported pack entries.
                    if let Some(e) = ent {
                        conn.execute(
                            "UPDATE entries SET claimed_oid=?1, crc32_expected=?2, crc32_actual=?3
                             WHERE source_id=?4 AND raw_offset=?5 AND claimed_oid IS NULL",
                            params![
                                row.oid,
                                exp_i64(row.crc32),
                                crc.map(|c| c as i64),
                                pack_source_id,
                                e.offset as i64
                            ],
                        )?;
                    }
                }
                drop(conn);
            }
        } else {
            report.warnings.push(format!(
                "idx 引用的 pack（checksum {}）尚未导入，{} 个条目暂时悬空",
                isum.pack_checksum,
                isum.entries.len()
            ));
        }
        report.entries = isum.entries.len();
        Ok(())
    }

    fn ingest_loose(
        &self,
        filename: &str,
        data: &[u8],
        rel: &str,
        sha: &str,
        report: &mut IngestReport,
    ) -> Result<()> {
        let claimed = claimed_loose_oid(filename);
        let source_id = self.insert_source("loose", filename, data, rel, sha, "", report)?;

        // Loose objects are a single zlib stream covering the whole file.
        let body_r = inflate_zlib(data, self.setting("parse_inflate_cap")?.parse().unwrap_or(256 << 20));
        let mut conn = self.conn.lock().unwrap();
        let seq = next_seq(&conn)?;
        match body_r {
            Ok(out) => {
                let parsed = parse_loose_body(&out.data);
                match parsed {
                    Ok((kind, payload)) => {
                        let computed = hex::encode(git_oid(kind, payload));
                        let err = if let Some(claim) = &claimed {
                            if claim != &computed {
                                Some(format!(
                                    "loose oid 不匹配：路径声明 {claim}，实算 {computed}"
                                ))
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if let Some(m) = &err {
                            report.warnings.push(m.clone());
                        }
                        conn.execute(
                            "INSERT INTO entries(source_id,entry_kind,claimed_oid,obj_type,
                               declared_size,raw_offset,data_start,data_end,inflate_ok,inflate_size,
                               parse_error,parse_seq)
                             VALUES(?1,'loose',?2,?3,?4,0,0,?5,1,?6,?7,?8)",
                            params![
                                source_id,
                                claimed,
                                kind.name(),
                                payload.len() as i64,
                                data.len() as i64,
                                payload.len() as i64,
                                err,
                                seq
                            ],
                        )?;
                        report.entries = 1;
                    }
                    Err(e) => {
                        let msg = format!("loose 对象头解析失败：{e}");
                        report.warnings.push(msg.clone());
                        conn.execute(
                            "INSERT INTO entries(source_id,entry_kind,claimed_oid,obj_type,
                               declared_size,raw_offset,data_start,data_end,inflate_ok,inflate_size,
                               parse_error,parse_seq)
                             VALUES(?1,'loose',?2,'unknown',NULL,0,0,?3,1,NULL,?4,?5)",
                            params![source_id, claimed, data.len() as i64, msg, seq],
                        )?;
                        report.entries = 1;
                    }
                }
            }
            Err(e) => {
                let msg = format!("loose zlib 解压失败：{e}");
                report.warnings.push(msg.clone());
                conn.execute(
                    "INSERT INTO entries(source_id,entry_kind,claimed_oid,obj_type,
                       declared_size,raw_offset,data_start,data_end,inflate_ok,inflate_size,
                       parse_error,parse_seq)
                     VALUES(?1,'loose',?2,'unknown',NULL,0,0,?3,0,NULL,?4,?5)",
                    params![source_id, claimed, data.len() as i64, msg, seq],
                )?;
                report.entries = 1;
            }
        }
        Ok(())
    }

    /// Locate an imported idx whose pack checksum matches; returns parsed idx
    /// and the idx source id.
    fn find_idx_for_pack(&self, pack_checksum: &str) -> Option<(IdxSummary, i64)> {
        if pack_checksum.is_empty() {
            return None;
        }
        let (rel, sid) = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT rel_path,id FROM sources WHERE kind='idx' AND trailer_oid=?1
                 ORDER BY id LIMIT 1",
                [pack_checksum],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok()?
        };
        let bytes = self.read_source_bytes(&rel).ok()?;
        parse_idx(&bytes).ok().map(|s| (s, sid))
    }

    /// Locate the bytes of a pack whose trailer matches `checksum`.
    fn find_pack_bytes(&self, checksum: &str) -> Option<(Vec<u8>, i64)> {
        if checksum.is_empty() {
            return None;
        }
        let (rel, sid) = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT rel_path,id FROM sources WHERE kind='pack' AND trailer_oid=?1
                 ORDER BY id LIMIT 1",
                [checksum],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .ok()?
        };
        let bytes = self.read_source_bytes(&rel).ok()?;
        Some((bytes, sid))
    }

    /// Mark all branches as needing reanalysis after new evidence arrives.
    pub fn invalidate_branches(&self) {
        let mut conn = self.conn.lock().unwrap();
        let _ = conn.execute_batch(
            "DELETE FROM results; DELETE FROM steps; DELETE FROM contents;
             INSERT OR IGNORE INTO analysis_meta(branch_id,analysis_seq)
               SELECT id,0 FROM branches;",
        );
    }
}

fn exp_i64(v: Option<u32>) -> Option<i64> {
    v.map(|x| x as i64)
}

fn claimed_loose_oid(filename: &str) -> Option<String> {
    let lower = filename.replace('\\', "/");
    let mut parts: Vec<&str> = lower.split('/').collect();
    if parts.len() >= 2 {
        let name = parts.pop().unwrap();
        let parent = parts.pop().unwrap();
        if parent.len() == 2
            && name.len() == 38
            && parent.chars().all(|c| c.is_ascii_hexdigit())
            && name.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some(format!("{parent}{name}"));
        }
    }
    None
}
