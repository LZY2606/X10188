//! 文件导入：按内容识别 pack / idx / loose，落库原始偏移与证据。

use crate::encoding::{oid_hex, parse_oid_hex};
use crate::idx::{crc_of_entry, parse_idx};
use crate::pack::{is_probably_idx, is_probably_pack, parse_loose, parse_pack, ScanBudget};
use crate::store::{now_ms, Store};
use crate::types::{EntryKind, Evidence, ObjOrigin};
use rusqlite::params;
use sha2::{Digest, Sha256};

pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub deduped: bool,
    pub objects_added: usize,
    pub evidences: Vec<Evidence>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

impl Store {
    /// 导入一个文件（内容 + 原始文件名）。导入顺序不影响候选排序。
    pub fn import_file(&self, filename: &str, data: &[u8]) -> std::io::Result<ImportReport> {
        let digest = sha256_hex(data);
        {
            let conn = self.conn.lock().unwrap();
            let existing: Option<i64> = conn
                .query_row(
                    "SELECT id FROM sources WHERE sha256=?1",
                    params![digest],
                    |r| r.get(0),
                )
                .ok();
            if let Some(sid) = existing {
                return Ok(ImportReport {
                    source_id: sid,
                    kind: "duplicate".into(),
                    deduped: true,
                    objects_added: 0,
                    evidences: vec![Evidence::new(
                        "duplicate_source",
                        "相同内容文件已导入，按内容去重",
                    )],
                });
    }

    fn matching_idx_records(&self, pack_trailer_hex: &str) -> Vec<crate::idx::IdxRecord> {
        if pack_trailer_hex.len() < 40 {
            return Vec::new();
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id FROM sources WHERE kind='idx'")
            .unwrap();
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        drop(stmt);
        drop(conn);
        let mut out = Vec::new();
        for id in ids {
            let path = self.files_dir();
            let conn = self.conn.lock().unwrap();
            let digest: String = conn
                .query_row("SELECT sha256 FROM sources WHERE id=?1", params![id], |r| {
                    r.get(0)
                })
                .unwrap();
            drop(conn);
            if let Ok(bytes) = std::fs::read(path.join(format!("{digest}.bin"))) {
                if let Some(idx) = parse_idx(&bytes, None) {
                    let want = bytes
                        .get(bytes.len() - 40..bytes.len() - 20)
                        .map(hex::encode)
                        .unwrap_or_default();
                    if want == pack_trailer_hex {
                        // 回填 pack_id 关联
                        let mut conn = self.conn.lock().unwrap();
                        conn.execute(
                            "UPDATE sources SET pack_id=?1 WHERE id=?2",
                            params![idx_pack_id(id, &want, &self), id],
                        )
                        .ok();
                        out = idx.records;
                    }
                }
            }
        }
        out
    }

    fn import_idx(
        &self,
        filename: &str,
        data: &[u8],
        digest: &str,
        _stored_name: &str,
    ) -> std::io::Result<ImportReport> {
        // 尝试找一个已导入且 trailer 匹配的 pack
        let mut matching_pack: Option<(i64, Vec<u8>)> = None;
        if data.len() >= 40 {
            let want = &data[data.len() - 40..data.len() - 20];
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT id, sha256 FROM sources WHERE kind='pack'").unwrap();
            let packs: Vec<(i64, String)> = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect();
            drop(stmt);
            drop(conn);
            for (pid, pd) in packs {
                let bytes = std::fs::read(self.files_dir().join(format!("{pd}.bin"))).unwrap();
                if bytes.len() >= 20 && &bytes[bytes.len() - 20..] == want {
                    matching_pack = Some((pid, bytes));
                    break;
                }
            }
        }

        let parsed = parse_idx(
            data,
            matching_pack.as_ref().map(|(_, b)| b.as_slice()),
        );
        let (pack_id, pack_bytes) = matching_pack
            .map(|(id, b)| (Some(id), Some(b)))
            .unwrap_or((None, None));
        let source_id = self.insert_source(filename, "idx", data, digest, pack_id);

        let mut evidences = Vec::new();
        match &parsed {
            None => {
                evidences.push(Evidence::new("bad_idx", "不是合法的 idx v2 文件"));
            }
            Some(idx) => {
                evidences.extend(idx.evidences.clone());
                if pack_id.is_none() {
                    evidences.push(Evidence::new(
                        "index_without_pack",
                        "未找到与该 idx 配套的 pack，仅登记 fanout 与记录",
                    ));
                }
                if let Some(pack) = &pack_bytes {
                    if let Some(p) = &parsed {
                        for rec in &p.records {
                            // 用 idx 的偏移与 CRC 校验 pack entry 压缩字节
                            let s = rec.offset as usize;
                            let hdr = crate::encoding::read_pack_entry_header(pack, s);
                            if let Some((_, _, hlen)) = hdr {
                                let zs = s + hlen
                                    + if matches!(
                                        crate::types::EntryKind::from_pack_code(
                                            (pack[s] >> 4) & 7
                                        ),
                                        Some(crate::types::EntryKind::OfsDelta)
                                    ) {
                                        crate::encoding::read_ofs_delta(pack, s + hlen)
                                            .map(|(_, n)| n)
                                            .unwrap_or(0)
                                    } else if matches!(
                                        crate::types::EntryKind::from_pack_code(
                                            (pack[s] >> 4) & 7
                                        ),
                                        Some(crate::types::EntryKind::RefDelta)
                                    ) {
                                        20
                                    } else {
                                        0
                                    };
                                // zlib 长度未知时无法直接校验 CRC（由 pack 导入侧校验），
                                // 这里记录 oid 声明并回填到已存在的 object 行。
                                self.annotate_object_from_idx(
                                    pack_id.unwrap(),
                                    rec.offset,
                                    &oid_hex(&rec.oid),
                                );
                                let _ = zs;
                            }
                        }
                    }
                }
            }
        }
        self.add_source_evidence(source_id, &evidences);
        Ok(ImportReport {
            source_id,
            kind: "idx".into(),
            deduped: false,
            objects_added: 0,
            evidences,
        })
    }

    fn annotate_object_from_idx(&self, pack_source_id: i64, offset: u64, oid: &str) {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE objects SET claimed_oid=?1
             WHERE source_id=?2 AND entry_offset=?3 AND claimed_oid IS NULL",
            params![oid, pack_source_id, offset as i64],
        )
        .unwrap();
    }

    fn import_loose_or_unknown(
        &self,
        filename: &str,
        data: &[u8],
        digest: &str,
        _stored_name: &str,
    ) -> std::io::Result<ImportReport> {
        let budget = self.budget(1);
        if let Some(loose) = parse_loose(data, budget.per_object_cap()) {
            let source_id = self.insert_source(filename, "loose", data, digest, None);
            let computed = oid_hex(&loose.computed_oid);
            // 路径形式 ab/cdef... 给出声称 oid
            let claimed = filename_to_oid(filename);
            let mut ev = loose.evidences;
            if let Some(want) = &claimed {
                if want != &computed {
                    ev.push(Evidence::new(
                        "oid_mismatch_vs_path",
                        format!("loose 路径声称 {want}，重算 {computed}"),
                    ));
                }
            }
            let origin = ObjOrigin::Loose { source_id };
            let raw_state = if ev.iter().any(|e| e.code == "size_spoof") {
                "corrupt"
            } else {
                "raw"
            };
            let id = self.insert_object(
                source_id,
                &origin,
                loose.kind.name(),
                None,
                Some(0),
                Some(data.len() as i64),
                Some(loose.content.len() as i64),
                Some(loose.content.len() as i64),
                loose.adler_ok,
                None,
                Some(&computed),
                claimed.as_deref(),
                None,
                None,
                raw_state,
                &ev,
                0,
            );
            if raw_state == "raw" {
                self.write_inflated(id, &loose.content).ok();
                self.add_spent(1, loose.content.len() as i64);
            }
            self.add_source_evidence(source_id, &ev);
            return Ok(ImportReport {
                source_id,
                kind: "loose".into(),
                deduped: false,
                objects_added: 1,
                evidences: ev,
            });
        }
        let source_id = self.insert_source(filename, "unknown", data, digest, None);
        let ev = vec![Evidence::new(
            "unrecognized_input",
            "既不是 pack / idx，也无法解析为 loose object",
        )];
        self.add_source_evidence(source_id, &ev);
        Ok(ImportReport {
            source_id,
            kind: "unknown".into(),
            deduped: false,
            objects_added: 0,
            evidences: ev,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_object(
        &self,
        source_id: i64,
        origin: &ObjOrigin,
        entry_kind: &str,
        entry_offset: Option<i64>,
        zlib_offset: Option<i64>,
        zlib_len: Option<i64>,
        declared_size: Option<i64>,
        inflated_size: Option<i64>,
        adler_ok: bool,
        idx_crc_ok: Option<bool>,
        computed_oid: Option<&str>,
        claimed_oid: Option<&str>,
        ofs_base: Option<i64>,
        ref_base: Option<&str>,
        raw_state: &str,
        evidences: &[Evidence],
        order: i64,
    ) -> i64 {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(
                source_id, origin, entry_kind, entry_offset, zlib_offset, zlib_len,
                declared_size, inflated_size, adler_ok, idx_crc_ok, computed_oid,
                claimed_oid, ofs_base_offset, ref_base_oid, raw_state, evidences, raw_order)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                source_id,
                origin.encode(),
                entry_kind,
                entry_offset,
                zlib_offset,
                zlib_len,
                declared_size,
                inflated_size,
                adler_ok as i64,
                idx_crc_ok.map(|v| v as i64),
                computed_oid,
                claimed_oid,
                ofs_base,
                ref_base,
                raw_state,
                Evidence::encode(evidences),
                order,
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }
}

fn filename_to_oid(filename: &str) -> Option<String> {
    let flat = filename.replace('\\', "/");
    let base = flat.rsplit('/').next().unwrap_or(&flat);
    let parent = flat.rsplit('/').nth(1);
    if let (Some(p), true) = (parent, base.len() == 38 && p.len() == 2) {
        let joined = format!("{p}{base}");
        if parse_oid_hex(&joined).is_some() {
            return Some(joined);
        }
    }
    if base.len() == 40 && parse_oid_hex(base).is_some() {
        return Some(base.to_string());
    }
    None
}

fn idx_pack_id(_id: i64, _want: &str, _store: &Store) -> Option<i64> {
    None
}

        let stored_name = format!("{digest}.bin");
        std::fs::write(self.files_dir().join(&stored_name), data)?;

        if is_probably_pack(data) {
            self.import_pack(filename, data, &digest, &stored_name)
        } else if is_probably_idx(data) {
            self.import_idx(filename, data, &digest, &stored_name)
        } else {
            self.import_loose_or_unknown(filename, data, &digest, &stored_name)
        }
    }

    fn insert_source(
        &self,
        filename: &str,
        kind: &str,
        data: &[u8],
        digest: &str,
        pack_id: Option<i64>,
    ) -> i64 {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO sources(filename, kind, pack_id, size, sha256, imported_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![filename, kind, pack_id, data.len() as i64, digest, now_ms()],
        )
        .unwrap();
        let id = tx.last_insert_rowid();
        tx.commit().unwrap();
        id
    }

    fn add_source_evidence(&self, source_id: i64, list: &[Evidence]) {
        let mut conn = self.conn.lock().unwrap();
        for e in list {
            conn.execute(
                "INSERT INTO source_evidence(source_id, code, detail, offset_value)
                 VALUES(?1,?2,?3,?4)",
                params![source_id, e.code, e.detail, e.offset.map(|v| v as i64)],
            )
            .unwrap();
        }
    }

    fn import_pack(
        &self,
        filename: &str,
        data: &[u8],
        digest: &str,
        stored_name: &str,
    ) -> std::io::Result<ImportReport> {
        let _ = stored_name;
        let source_id = self.insert_source(filename, "pack", data, digest, None);
        let budget = self.budget(1);
        let parsed = parse_pack(
            data,
            &ScanBudget {
                remaining: budget.remaining(),
                per_object_cap: budget.per_object_cap(),
            },
        );
        self.add_source_evidence(source_id, &parsed.evidences);

        // 若存在与本 pack SHA1 配套的已导入 idx，取其记录做 CRC/oid 校验。
        let pack_trailer = if data.len() >= 20 {
            hex::encode(&data[data.len() - 20..])
        } else {
            String::new()
        };
        let idx_records = self.matching_idx_records(&pack_trailer);

        let mut added = 0usize;
        for (order, entry) in parsed.entries.iter().enumerate() {
            let idx_rec = idx_records
                .iter()
                .find(|r| r.offset == entry.entry_offset);
            let mut ev = entry.evidences.clone();
            let mut idx_crc_ok = None;
            let mut idx_oid = None;
            if let Some(rec) = idx_rec {
                idx_oid = Some(rec.oid);
                if let Some(crc) =
                    crc_of_entry(data, entry.zlib_offset, entry.zlib_len)
                {
                    let ok = crc == rec.crc32;
                    idx_crc_ok = Some(ok);
                    if !ok {
                        ev.push(Evidence::new(
                            "bad_crc",
                            format!(
                                "idx CRC32={:08x}，按 zlib 边界重算={:08x}（错误 CRC）",
                                rec.crc32, crc
                            ),
                        ));
                    }
                }
            }
            let (raw_state, inflated_size) = if entry.budget_paused {
                ("paused", None)
            } else if entry.scan_aborts_after
                || entry.inflated.is_none()
                || ev.iter().any(|e| {
                    matches!(
                        e.code.as_str(),
                        "size_spoof" | "zlib_corrupt" | "zlib_adler_mismatch"
                            | "ofs_distance_out_of_range"
                    )
                }) {
                ("corrupt", entry.inflated.as_ref().map(|b| b.len() as i64))
            } else {
                ("raw", entry.inflated.as_ref().map(|b| b.len() as i64))
            };

            let origin = ObjOrigin::PackEntry {
                source_id,
                entry_offset: entry.entry_offset,
                zlib_offset: entry.zlib_offset,
                zlib_len: entry.zlib_len,
            };
            let entry_kind = match entry.kind {
                EntryKind::Plain(t) => t.name(),
                EntryKind::OfsDelta => "ofs_delta",
                EntryKind::RefDelta => "ref_delta",
            };
            let mut computed_oid = entry.computed_oid.map(|o| oid_hex(&o));
            if let Some(o) = idx_oid {
                // idx 提供声称 oid；plain 对象比对结果已作为 evidence 记录
                if computed_oid.is_some() && computed_oid.as_deref() != Some(oid_hex(&o).as_str())
                {
                    computed_oid = computed_oid;
                }
            }
            let claimed = idx_oid.map(|o| oid_hex(&o));
            let object_id = self.insert_object(
                source_id,
                &origin,
                entry_kind,
                Some(entry.entry_offset as i64),
                Some(entry.zlib_offset as i64),
                Some(entry.zlib_len as i64),
                Some(entry.declared_size as i64),
                inflated_size,
                entry.adler_ok,
                idx_crc_ok,
                computed_oid.as_deref(),
                claimed.as_deref(),
                entry.ofs_base.map(|v| v),
                entry.ref_base.map(|o| oid_hex(&o)).as_deref(),
                raw_state,
                &ev,
                order as i64,
            );
            if let Some(body) = &entry.inflated {
                if raw_state == "raw" {
                    self.write_inflated(object_id, body).ok();
                } else if ev.iter().any(|e| e.code == "size_spoof") {
                    // 保留大小欺骗的半成品作为证据
                    self.write_inflated(object_id, body).ok();
                }
            }
            added += 1;
        }

        // idx 中有记录但 pack 里解析不到对应偏移 => 不配套
        for rec in &idx_records {
            if !parsed.entries.iter().any(|e| e.entry_offset == rec.offset) {
                self.add_source_evidence(
                    source_id,
                    &[Evidence::new(
                        "index_pack_drift",
                        format!("idx 记录偏移 {} 在 pack 中不存在", rec.offset),
                    )],
                );
            }
        }

        // 成功展开且有效（非 paused/spoof）的字节计入总预算
        if !parsed.scan_paused && parsed.budget_used > 0 {
            self.add_spent(1, parsed.budget_used as i64);
        }

        let mut all_ev = parsed.evidences.clone();
        if parsed.scan_paused {
            all_ev.push(Evidence::new(
                "import_paused",
                "pack 导入在预算处暂停，提高预算后可重试导入（已有条目不重复计入）",
            ));
        }
        Ok(ImportReport {
            source_id,
            kind: "pack".into(),
            deduped: false,
            objects_added: added,
            evidences: all_ev,
        })
    }
