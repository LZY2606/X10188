use std::path::PathBuf;

use rusqlite::params;

use crate::engine::{candidate_rank_key, sha256_hex, kind_str, HARD_INFLATE_CAP};
use crate::engine::Engine;
use crate::git::{self, loose, pack, idx, ObjType};

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub nodes_added: usize,
    pub linked_source_id: Option<i64>,
    pub warnings: Vec<String>,
    pub deduped: bool,
}

fn detect_kind(data: &[u8], filename: &str) -> &'static str {
    if data.len() >= 8 && &data[0..4] == b"PACK" {
        "pack"
    } else if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        "idx"
    } else if filename.contains('/') || filename.contains('\\') {
        "loose"
    } else {
        "unknown"
    }
}

impl Engine {
    pub fn import_path(&self, path: &std::path::Path) -> Result<ImportReport, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload".into());
        self.import_bytes_impl(&name, &data)
    }

    fn import_bytes_impl(&self, filename: &str, data: &[u8]) -> Result<ImportReport, String> {
        let kind = detect_kind(data, filename);
        if kind == "unknown" {
            return Err("unrecognized file (not a pack, v2 idx or loose object path)".into());
        }
        let digest = sha256_hex(data);
        let mut db = self.conn.lock().unwrap();
        if let Ok(existing) = db.query_row(
            "SELECT id FROM sources WHERE sha256=?1",
            params![digest],
            |r| r.get::<_, i64>(0),
        ) {
            return Ok(ImportReport {
                source_id: existing,
                kind: kind.into(),
                filename: filename.into(),
                nodes_added: 0,
                linked_source_id: None,
                warnings: vec!["identical file already imported".into()],
                deduped: true,
            });
        }
        let stored = self.store_file(&digest, data);
        let stored_str = stored.to_string_lossy().to_string();
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sources(kind,filename,stored_path,sha256,byte_len)
             VALUES(?1,?2,?3,?4,?5)",
            params![kind, filename, stored_str, digest, data.len() as i64],
        )
        .map_err(|e| e.to_string())?;
        let source_id = tx.last_insert_rowid();

        let mut report = ImportReport {
            source_id,
            kind: kind.into(),
            filename: filename.into(),
            nodes_added: 0,
            linked_source_id: None,
            warnings: Vec::new(),
            deduped: false,
        };

        match kind {
            "pack" => self.import_pack(&tx, source_id, data, &mut report)?,
            "idx" => self.import_idx(&tx, source_id, data, &mut report)?,
            "loose" => self.import_loose(&tx, source_id, filename, data, &mut report)?,
            _ => unreachable!(),
        }
        tx.commit().map_err(|e| e.to_string())?;
        drop(db);
        // After commit, settle everything that can now make progress.
        self.settle_branch(1).map_err(|e| e.to_string())?;
        Ok(report)
    }

    fn store_file(&self, digest: &str, data: &[u8]) -> PathBuf {
        let p = self.files_dir.join(format!("{digest}.bin"));
        if !p.exists() {
            std::fs::write(&p, data).expect("write stored file");
        }
        p
    }
}

impl Engine {
    fn import_pack(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        let mut parsed = pack::parse_pack(data, HARD_INFLATE_CAP).map_err(|e| e.to_string())?;
        let idx_source: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, stored_path FROM sources
                 WHERE kind='idx' AND json_extract(detail,'$.pack_sha')=?1",
                params![hex::encode(parsed.pack_sha)],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .ok();

        let mut idx_entries: Vec<idx::IdxEntry> = Vec::new();
        let mut idx_present = false;
        if let Some((idx_id, idx_path)) = &idx_source {
            let idata = std::fs::read(idx_path).map_err(|e| e.to_string())?;
            if let Ok(pidx) = idx::parse_idx(&idata) {
                idx_present = true;
                report.linked_source_id = Some(*idx_id);
                tx.execute(
                    "UPDATE sources SET linked_pack_source_id=?1 WHERE id=?2",
                    params![source_id, idx_id],
                )
                .map_err(|e| e.to_string())?;
                tx.execute(
                    "UPDATE sources SET linked_pack_source_id=?1 WHERE id=?2",
                    params![idx_id, source_id],
                )
                .map_err(|e| e.to_string())?;
                if !pidx.checksum_ok {
                    report.warnings.push("index SHA1 checksum mismatch".into());
                }
                for e in &parsed.entries {
                    if let Some(ie) = pidx
                        .entries
                        .iter()
                        .find(|ie| ie.offset as usize == e.header_start)
                    {
                        // Safe: parsed entries iterated mutably below.
                        idx_entries.push(ie.clone());
                    }
                }
            }
        }

        for e in parsed.entries.iter_mut() {
            let matching = idx_entries
                .iter()
                .find(|ie| ie.offset as usize == e.header_start);
            if let Some(ie) = matching {
                e.crc_from_index = Some(ie.crc32);
            }
        }
        parsed.compute_crcs(data);

        let detail = serde_json::json!({
            "pack_sha": hex::encode(parsed.pack_sha),
            "trailer_sha": hex::encode(parsed.trailer_sha),
            "checksum_ok": parsed.checksum_ok,
            "object_count": parsed.object_count,
            "idx_present": idx_present,
            "parse_errors": parsed.parse_errors.iter().map(|(o,m)| format!("[{o}] {m}")).collect::<Vec<_>>(),
        });
        tx.execute(
            "UPDATE sources SET detail=?1 WHERE id=?2",
            params![detail.to_string(), source_id],
        )
        .map_err(|e| e.to_string())?;
        if !parsed.checksum_ok {
            report.warnings.push("pack SHA1 trailer mismatch".into());
        }
        for (o, m) in &parsed.parse_errors {
            if *o != usize::MAX {
                report.warnings.push(format!("entry {o}: {m}"));
            }
        }

        for e in &parsed.entries {
            let (status, perr) = match &e.inflate_error {
                None => ("ok", None::<String>),
                Some(m) => ("inflate_error", Some(m.clone())),
            };
            let (zstart, zend, zout) = match &e.zlib {
                Some(z) => (
                    Some(z.compressed_start as i64),
                    Some(z.compressed_end as i64),
                    Some(z.output_len as i64),
                ),
                None => (None, None, None),
            };
            let locator = format!("pack:{source_id}:{}", e.header_start);
            tx.execute(
                "INSERT INTO nodes(source_id,locator,kind,declared_size,pack_offset,
                   header_start,header_end,zlib_start,zlib_end,zlib_out_len,
                   ofs_base_offset,ref_base_oid,raw,content_size,parse_status,parse_error,
                   crc_expected,crc_actual,crc_ok)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![
                    source_id,
                    locator,
                    kind_str(e.obj_type),
                    e.declared_size as i64,
                    e.header_start as i64,
                    e.header_start as i64,
                    e.header_end as i64,
                    zstart,
                    zend,
                    zout,
                    e.ofs_base_offset.map(|v| v as i64),
                    e.ref_base_oid.as_ref().map(|o| o.to_vec()),
                    e.inflated,
                    e.inflated.as_ref().map(|v| v.len() as i64),
                    status,
                    perr,
                    e.crc_from_index.map(|v| v as i64),
                    e.crc_actual.map(|v| v as i64),
                    e.crc_ok.map(|v| v as i64),
                ],
            )
            .map_err(|e2| e2.to_string())?;
            let node_id = tx.last_insert_rowid();
            report.nodes_added += 1;

            // Index-declared candidate, even if CRC is bad (shown as suspect).
            if let Some(ie) = idx_entries
                .iter()
                .find(|ie| ie.offset as usize == e.header_start)
            {
                let rank = candidate_rank_key(
                    "index",
                    true,
                    e.crc_ok,
                    source_id,
                    Some(e.header_start as i64),
                );
                tx.execute(
                    "INSERT INTO oid_candidates(oid,node_id,origin,idx_present,crc_ok,checksum_ok,rank_key)
                     VALUES(?1,?2,'index',1,?3,?4,?5)",
                    params![
                        ie.oid.to_vec(),
                        node_id,
                        e.crc_ok.map(|v| v as i64),
                        parsed.checksum_ok as i64,
                        rank
                    ],
                )
                .map_err(|e2| e2.to_string())?;
            }
        }
        Ok(())
    }
}

impl Engine {
    fn import_idx(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        let parsed = idx::parse_idx(data).map_err(|e| e.to_string())?;
        let detail = serde_json::json!({
            "pack_sha": hex::encode(parsed.pack_sha),
            "idx_sha": hex::encode(parsed.idx_sha),
            "trailer_sha": hex::encode(parsed.trailer_sha),
            "checksum_ok": parsed.checksum_ok,
            "object_count": parsed.entries.len(),
        });
        tx.execute(
            "UPDATE sources SET detail=?1 WHERE id=?2",
            params![detail.to_string(), source_id],
        )
        .map_err(|e| e.to_string())?;
        if !parsed.checksum_ok {
            report.warnings.push("index SHA1 checksum mismatch".into());
        }
        for (bucket, value) in parsed.fanout.iter().enumerate() {
            tx.execute(
                "INSERT INTO fanout(source_id,bucket,value) VALUES(?1,?2,?3)",
                params![source_id, bucket as i64, *value as i64],
            )
            .map_err(|e| e.to_string())?;
        }

        // Is a matching pack already present?
        let pack_source: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, stored_path FROM sources
                 WHERE kind='pack' AND json_extract(detail,'$.pack_sha')=?1",
                params![hex::encode(parsed.pack_sha)],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .ok();

        let mut node_by_offset: std::collections::HashMap<u64, i64> = std::collections::HashMap::new();
        let mut pparsed: Option<pack::ParsedPack> = None;
        let mut pack_bytes: Vec<u8> = Vec::new();
        if let Some((pack_id, pack_path)) = &pack_source {
            report.linked_source_id = Some(*pack_id);
            pack_bytes = std::fs::read(pack_path).map_err(|e| e.to_string())?;
            let mut pp = pack::parse_pack(&pack_bytes, HARD_INFLATE_CAP).map_err(|e| e.to_string())?;
            for e in pp.entries.iter_mut() {
                if let Some(ie) = parsed
                    .entries
                    .iter()
                    .find(|ie| ie.offset as usize == e.header_start)
                {
                    e.crc_from_index = Some(ie.crc32);
                }
            }
            pp.compute_crcs(&pack_bytes);
            tx.execute(
                "UPDATE sources SET linked_pack_source_id=?1,detail=json_set(detail,'$.idx_present','true') WHERE id=?2",
                params![source_id, pack_id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE sources SET linked_pack_source_id=?1 WHERE id=?2",
                params![*pack_id, source_id],
            )
            .map_err(|e| e.to_string())?;
            for e in &pp.entries {
                if node_by_offset.contains_key(&(e.header_start as u64)) {
                    continue;
                }
                // If pack already imported (nodes exist) reuse them.
                if let Ok(nid) = tx.query_row(
                    "SELECT id FROM nodes WHERE source_id=?1 AND pack_offset=?2",
                    params![pack_id, e.header_start as i64],
                    |r| r.get::<_, i64>(0),
                ) {
                    node_by_offset.insert(e.header_start as u64, nid);
                    // Backfill CRC columns.
                    tx.execute(
                        "UPDATE nodes SET crc_expected=?1,crc_actual=?2,crc_ok=?3 WHERE id=?4",
                        params![
                            e.crc_from_index.map(|v| v as i64),
                            e.crc_actual.map(|v| v as i64),
                            e.crc_ok.map(|v| v as i64),
                            nid
                        ],
                    )
                    .map_err(|e2| e2.to_string())?;
                }
            }
            pparsed = Some(pp);
        }

        for ie in &parsed.entries {
            let node_id = if let Some(nid) = node_by_offset.get(&ie.offset) {
                *nid
            } else {
                // Placeholder node: index exists but its pack is missing/mismatched.
                let locator = format!("idx:{source_id}:{}", ie.offset);
                tx.execute(
                    "INSERT INTO nodes(source_id,locator,kind,declared_size,pack_offset,
                       parse_status,parse_error)
                     VALUES(?1,?2,'idx_placeholder',0,?3,'missing_base','index without matching pack')",
                    params![source_id, locator, ie.offset as i64],
                )
                .map_err(|e| e.to_string())?;
                report.nodes_added += 1;
                tx.last_insert_rowid()
            };
            let crc_ok: Option<i64> = pparsed.as_ref().and_then(|pp| {
                pp.entries.iter().find(|e| e.header_start as u64 == ie.offset)
                  .and_then(|e| e.crc_ok.map(|v| v as i64))
            });
            let checksum_ok = parsed.checksum_ok as i64;
            let rank = candidate_rank_key(
                "index",
                pack_source.is_some(),
                crc_ok.map(|v| v == 1),
                source_id,
                Some(ie.offset as i64),
            );
            tx.execute(
                "INSERT INTO oid_candidates(oid,node_id,origin,idx_present,crc_ok,checksum_ok,rank_key)
                 VALUES(?1,?2,'index',?3,?4,?5,?6)",
                params![
                    ie.oid.to_vec(),
                    node_id,
                    pack_source.is_some() as i64,
                    crc_ok,
                    checksum_ok,
                    rank
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn import_loose(
        &self,
        tx: &rusqlite::Transaction,
        source_id: i64,
        filename: &str,
        data: &[u8],
        report: &mut ImportReport,
    ) -> Result<(), String> {
        // Normalize a path like ab/cdef... into the 40-hex oid.
        let cleaned = filename.replace('\\', "/");
        let oid_hex = match cleaned.rsplit_once('/') {
            Some((dir, name)) if dir.len() == 2 => format!("{dir}{name}"),
            _ => cleaned.clone(),
        };
        let parsed = loose::parse_loose(&oid_hex, data, HARD_INFLATE_CAP)
            .map_err(|e| format!("{}: {}", e.code, e.message))?;
        let oid = git::object_id::hex20(&oid_hex).ok_or("bad loose oid")?;
        let detail = serde_json::json!({
            "oid": oid_hex,
            "zlib_start": parsed.zlib_start,
            "zlib_end": parsed.zlib_end,
            "header_len": parsed.header_len,
        });
        tx.execute(
            "UPDATE sources SET detail=?1 WHERE id=?2",
            params![detail.to_string(), source_id],
        )
        .map_err(|e| e.to_string())?;
        let locator = format!("loose:{source_id}");
        tx.execute(
            "INSERT INTO nodes(source_id,locator,kind,declared_size,
               zlib_start,zlib_end,zlib_out_len,raw,content_size,parse_status,
               computed_oid,pack_offset)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'ok',?10,NULL)",
            params![
                source_id,
                locator,
                kind_str(parsed.obj_type),
                parsed.content.len() as i64,
                parsed.zlib_start as i64,
                parsed.zlib_end as i64,
                parsed.content.len() as i64,
                parsed.content,
                parsed.content.len() as i64,
                oid.to_vec()
            ],
        )
        .map_err(|e| e.to_string())?;
        let node_id = tx.last_insert_rowid();
        report.nodes_added += 1;
        let rank = candidate_rank_key("index", true, Some(true), source_id, None);
        tx.execute(
            "INSERT INTO oid_candidates(oid,node_id,origin,idx_present,crc_ok,checksum_ok,rank_key)
             VALUES(?1,?2,'loose',1,1,1,?3)",
            params![oid.to_vec(), node_id, rank],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
