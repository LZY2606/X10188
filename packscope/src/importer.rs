use crate::gitobj::{hash_object, ObjType};
use crate::loose;
use crate::pack::{self, ParsedIdx, ParsedPack};
use crate::store::Store;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportReport {
    pub source_id: String,
    pub kind: String,
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub candidates: i64,
    pub paired_pack: Option<String>,
    pub notices: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn detect_kind(data: &[u8], filename: &str) -> &'static str {
    if data.len() >= 4 && &data[..4] == b"PACK" {
        return "pack";
    }
    if data.len() >= 8 && &data[..4] == b"\xfftOc" {
        return "idx";
    }
    if filename.ends_with(".idx") {
        return "idx";
    }
    if filename.ends_with(".pack") {
        return "pack";
    }
    "loose"
}

pub struct Importer<'a> {
    pub store: &'a Store,
}

impl<'a> Importer<'_> {
    pub fn new(store: &'a Store) -> Importer<'a> {
        Importer { store }
    }

    fn next_order(&self) -> i64 {
        let c = self.store.conn.lock().unwrap();
        c.query_row("SELECT COALESCE(MAX(imported_order),0)+1 FROM sources", [], |r| {
            r.get(0)
        })
        .unwrap()
    }

    pub fn import(&self, filename: &str, data: &[u8]) -> ImportReport {
        let kind = detect_kind(data, filename).to_string();
        let id = format!(
            "{}-{}",
            crate::store::now_ms(),
            &sha256_hex(data)[..12]
        );
        let order = self.next_order();
        let sha = sha256_hex(data);

        let dir = self.store.data_dir.join("sources");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&id), data).unwrap();

        {
            let c = self.store.conn.lock().unwrap();
            c.execute(
                "INSERT INTO sources(id, kind, filename, imported_order, size, sha256)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![id, kind, filename, order, data.len() as i64, sha],
            )
            .unwrap();
        }

        let mut report = ImportReport {
            source_id: id.clone(),
            kind: kind.clone(),
            filename: filename.to_string(),
            size: data.len() as u64,
            sha256: sha,
            candidates: 0,
            paired_pack: None,
            notices: vec![],
        };

        match kind.as_str() {
            "pack" => {
                self.rebuild_pack(&id, data, &mut report);
            }
            "idx" => {
                let idx = pack::parse_idx(data);
                for e in &idx.errors {
                    self.evidence(None, None, None, "error", "idx_parse", e, filename);
                    report.notices.push(e.clone());
                }
                // Try to pair with any stored pack.
                if let Some((pack_id, pack_data)) = self.find_pack_for_idx(&idx) {
                    self.rebuild_pack(&pack_id, &pack_data, &mut report);
                    report.paired_pack = Some(pack_id);
                } else {
                    self.evidence(
                        None,
                        None,
                        None,
                        "warn",
                        "idx_orphan",
                        "imported index has no matching pack yet",
                        filename,
                    );
                    report.notices.push("no matching pack yet".into());
                }
            }
            _ => {
                self.import_loose(&id, data, filename, &mut report);
            }
        }

        // New inputs may unblock dependencies in every branch.
        self.relink_ref_edges();
        crate::engine::Engine::new(self.store).invalidate_affected(&[]);
        report
    }

    fn evidence(
        &self,
        branch: Option<i64>,
        cid: Option<i64>,
        oid: Option<&str>,
        level: &str,
        code: &str,
        msg: &str,
        ctx: &str,
    ) {
        let c = self.store.conn.lock().unwrap();
        c.execute(
            "INSERT INTO evidence(branch_id,cid,oid,level,code,message,context,created_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![branch, cid, oid, level, code, msg, ctx, crate::store::now_ms()],
        )
        .unwrap();
    }

    fn find_pack_for_idx(&self, idx: &ParsedIdx) -> Option<(String, Vec<u8>)> {
        let want = idx.pack_sha?;
        let c = self.store.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT id FROM sources WHERE kind='pack'").unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        drop(c);
        for id in ids {
            let data = std::fs::read(self.store.source_path(&id)).ok()?;
            let parsed = pack::parse_pack(&data, Some(idx));
            if let Some(ok) = parsed.header.trailer_ok {
                if ok && parsed.header.trailer_sha == Some(want) {
                    return Some((id, data));
                }
            }
            // Also match by idx+pack consistency even if trailer fails:
            if let Some(stored) = parsed.header.trailer_sha {
                if stored == want {
                    return Some((id, data));
                }
            }
        }
        None
    }

    /// Remove and recreate candidates belonging to a pack source, parsing it
    /// with its best-matching idx (if any).
    fn rebuild_pack(&self, pack_id: &str, data: &[u8], report: &mut ImportReport) {
        let idx_data = self.find_idx_for_pack(pack_id, data);
        let idx = idx_data.as_ref().map(|(_, d)| pack::parse_idx(d));
        let parsed: ParsedPack = pack::parse_pack(data, idx.as_ref());

        for e in &parsed.errors {
            self.evidence(None, None, None, "error", "pack_parse", e, &report.filename);
            report.notices.push(e.clone());
        }

        {
            let c = self.store.conn.lock().unwrap();
            c.execute("DELETE FROM candidates WHERE source_id=?1", params![pack_id])
                .unwrap();
        }

        // Insert candidates.
        for (i, ent) in parsed.entries.iter().enumerate() {
            let payload = parsed.payloads.get(i).and_then(|p| p.as_ref());
            let payload_key = payload.map(|p| {
                let mut h = Sha256::new();
                h.update(p);
                let key = format!("payload/{}", hex::encode(h.finalize()));
                self.store.write_blob(&key, p).ok();
                key
            });
            let (declared_oid, actual_oid) = if let Some(ix) = idx.as_ref() {
                let pos = ent.idx_position.and_then(|p| ix.entries.get(p - 1));
                                let declared = pos.map(|e| e.oid.hex());
                let actual = if !ent.kind.is_delta() && payload.is_some() && ent.error.is_none() {
                    Some(hash_object(ent.kind, payload.unwrap()).hex())
                } else {
                    None
                };
                (declared, actual)
            } else {
                let actual = if !ent.kind.is_delta() && payload.is_some() && ent.error.is_none() {
                    Some(hash_object(ent.kind, payload.unwrap()).hex())
                } else {
                    None
                };
                (None, actual)
            };

            let c = self.store.conn.lock().unwrap();
            c.execute(
                "INSERT INTO candidates(source_id,source_kind,entry_index,offset,kind,
                   declared_oid,actual_oid,payload_key,declared_size,payload_len,parse_error,quality)
                 VALUES(?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    pack_id,
                    ent.index as i64,
                    ent.offset as i64,
                    ent.kind.name(),
                    declared_oid,
                    actual_oid,
                    payload_key,
                    ent.declared_size as i64,
                    ent.payload_len as i64,
                    ent.error,
                    quality_score(ent.kind.name(), ent.error.is_some(), idx.is_some())
                ],
            )
            .unwrap();
        }

        // ofs edges: resolve within this same pack.
        let cids: Vec<(i64, i64, i64)> = {
            let c = self.store.conn.lock().unwrap();
            let mut st = c
                .prepare(
                    "SELECT cid, COALESCE(offset,-1), COALESCE(entry_index,-1)
                     FROM candidates WHERE source_id=?1 ORDER BY cid",
                )
                .unwrap();
            st.query_map(params![pack_id], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        for ent in &parsed.entries {
            if let Some(base_off) = ent.ofs_base_offset {
                let from_cid = cids.iter().find(|(_, _, ei)| *ei as usize == ent.index).map(|x| x.0);
                let base_cid = cids
                    .iter()
                    .find(|(_, off, _)| *off as u64 == base_off)
                    .map(|x| x.0);
                let c = self.store.conn.lock().unwrap();
                c.execute(
                    "INSERT INTO edges(from_cid,base_kind,base_cid,base_offset,base_oid)
                     VALUES(?1,'ofs',?2,?3,NULL)",
                    params![from_cid, base_cid, base_off as i64],
                )
                .unwrap();
                if base_cid.is_none() {
                    self.evidence(
                        None,
                        from_cid,
                        None,
                        "error",
                        "ofs_oob",
                        &format!(
                            "ofs-delta distance {} points to offset {} with no entry",
                            ent.ofs_distance.unwrap_or(0),
                            base_off
                        ),
                        &report.filename,
                    );
                }
            }
            if let Some(oid) = ent.ref_base_oid {
                let from_cid = cids.iter().find(|(_, _, ei)| *ei as usize == ent.index).map(|x| x.0);
                let c = self.store.conn.lock().unwrap();
                c.execute(
                    "INSERT INTO edges(from_cid,base_kind,base_cid,base_offset,base_oid)
                     VALUES(?1,'ref',NULL,NULL,?2)",
                    params![from_cid, oid.hex()],
                )
                .unwrap();
            }
        }

        report.candidates = parsed.entries.len() as i64;
    }

    fn find_idx_for_pack(&self, pack_id: &str, data: &[u8]) -> Option<(String, Vec<u8>)> {
        let trailer = if data.len() >= 20 {
            Some(crate::oid::Oid::from_bytes(&data[data.len() - 20..]).unwrap())
        } else {
            None
        };
        let c = self.store.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT id FROM sources WHERE kind='idx'").unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        drop(c);
        for id in ids {
            let d = std::fs::read(self.store.source_path(&id)).ok()?;
            let ix = pack::parse_idx(&d);
            let matches = match (ix.pack_sha, trailer) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if matches {
                return Some((id, d));
            }
        }
        let _ = pack_id;
        None
    }

    fn import_loose(&self, id: &str, data: &[u8], filename: &str, report: &mut ImportReport) {
        match loose::parse_loose(data, 512 * 1024 * 1024) {
            Ok(obj) => {
                let oid = hash_object(obj.kind, &obj.body);
                let declared = crate::oid::Oid::from_hex(
                    filename
                        .split('/')
                        .last()
                        .unwrap_or("")
                        .trim_end_matches(".gz"),
                )
                .or_else(|| {
                    // two-shard loose path: <dir>/ab/cdef...
                    let parts: Vec<&str> = filename.split('/').collect();
                    if parts.len() >= 2 {
                        crate::oid::Oid::from_hex(
                            &format!("{}{}", parts[parts.len() - 2], parts[parts.len() - 1]),
                        )
                    } else {
                        None
                    }
                });
                let key = format!("loose/{}", oid.hex());
                self.store.write_blob(&key, &obj.body).ok();
                let mut quality = 100;
                let mut parse_error: Option<String> = None;
                if let Some(d) = declared {
                    if d != oid {
                        quality = 20;
                        parse_error = Some(format!(
                            "loose filename says {} but content hashes to {}",
                            d.short(),
                            oid.short()
                        ));
                        self.evidence(
                            None, None, None, "error", "loose_oid_mismatch",
                            parse_error.as_ref().unwrap(), filename,
                        );
                    }
                }
                let c = self.store.conn.lock().unwrap();
                c.execute(
                    "INSERT INTO candidates(source_id,source_kind,entry_index,offset,kind,
                       declared_oid,actual_oid,payload_key,declared_size,payload_len,parse_error,quality)
                     VALUES(?1,'loose',NULL,NULL,?2,?3,?4,?5,?6,?6,?7,?8)",
                    params![
                        id,
                        obj.kind.name(),
                        declared.map(|o| o.hex()),
                        oid.hex(),
                        key,
                        obj.body.len() as i64,
                        parse_error,
                        quality
                    ],
                )
                .unwrap();
                report.candidates = 1;
            }
            Err(e) => {
                self.evidence(None, None, None, "error", "loose_parse", &e, filename);
                let c = self.store.conn.lock().unwrap();
                c.execute(
                    "INSERT INTO candidates(source_id,source_kind,kind,declared_size,payload_len,
                       parse_error,quality)
                     VALUES(?1,'loose','blob',0,0,?2,0)",
                    params![id, e],
                )
                .unwrap();
                report.notices.push(e);
            }
        }
    }

    /// Resolve ref-delta edges to concrete base candidates when new objects
    /// arrive (or new sources change things).
    fn relink_ref_edges(&self) {
        let c = self.store.conn.lock().unwrap();
        let unresolved: Vec<(i64, String)> = {
            let mut st = c
                .prepare("SELECT from_cid, base_oid FROM edges WHERE base_kind='ref'")
                .unwrap();
            st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        for (from_cid, oid_hex) in unresolved {
            let best: Option<i64> = c
                .query_row(
                    "SELECT cid FROM candidates
                     WHERE (actual_oid=?1 OR declared_oid=?1)
                     ORDER BY quality DESC, cid ASC LIMIT 1",
                    params![oid_hex],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            c.execute(
                "UPDATE edges SET base_cid=?1 WHERE from_cid=?2 AND base_kind='ref'",
                params![best, from_cid],
            )
            .unwrap();
        }
    }
}

fn quality_score(_kind: &str, has_error: bool, has_idx: bool) -> i64 {
    if has_error {
        10
    } else if has_idx {
        60
    } else {
        40
    }
}
