//! File ingestion: bytes stay in the project data directory; sources,
//! candidates and declared delta edges are recorded deterministically.

use super::*;
use crate::git::loose::parse_loose;
use crate::git::pack::attach_idx;
use crate::model::kind as knd;
use rusqlite::params;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportReport {
    pub source_id: Option<i64>,
    pub kind: String,
    pub filename: String,
    pub sha256: String,
    pub parse_status: String,
    pub parse_detail: String,
    pub candidates: usize,
    pub duplicate: bool,
    pub resolve: Option<super::build::ResolveReport>,
}

fn detect_kind(data: &[u8], filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") {
        return knd::PACK;
    }
    if lower.ends_with(".idx") {
        return knd::IDX;
    }
    if data.starts_with(&crate::git::pack::PACK_SIGNATURE) {
        return knd::PACK;
    }
    if data.starts_with(b"\xfftOc") {
        return knd::IDX;
    }
    if looks_like_idx_v1(data) {
        return knd::IDX;
    }
    knd::LOOSE
}

fn looks_like_idx_v1(data: &[u8]) -> bool {
    if data.len() < 256 * 4 + 20 {
        return false;
    }
    let total = u32::from_be_bytes(data[255 * 4..255 * 4 + 4].try_into().unwrap());
    let expected = 256 * 4 + total as usize * 24 + 20;
    let mut monotone = true;
    for w in data.chunks_exact(4).take(256).collect::<Vec<_>>().windows(2) {
        let a = u32::from_be_bytes(w[0].try_into().unwrap());
        let b = u32::from_be_bytes(w[1].try_into().unwrap());
        if b < a {
            monotone = false;
            break;
        }
    }
    monotone && expected == data.len()
}

impl App {
    pub fn import_bytes(&self, filename: &str, data: &[u8]) -> Result<ImportReport> {
        let digest = sha256_hex(data);

        // Duplicate content is de-duplicated by digest; import order has no
        // effect on ordering, but re-importing the same bytes is a no-op.
        if let Some(existing) = self.source_by_digest(&digest)? {
            let count = self.candidates_of_source(existing.id)?.len();
            return Ok(ImportReport {
                source_id: Some(existing.id),
                kind: existing.kind,
                filename: existing.filename,
                sha256: digest,
                parse_status: existing.parse_status,
                parse_detail: existing.parse_detail,
                candidates: count,
                duplicate: true,
                resolve: None,
            });
        }

        let kind = detect_kind(data, filename).to_string();
        std::fs::write(self.files_dir.join(&digest), data)?;

        let report = match kind.as_str() {
            knd::PACK => self.import_pack(filename, &digest, data)?,
            knd::IDX => self.import_idx(filename, &digest, data)?,
            _ => self.import_loose(filename, &digest, data)?,
        };

        // Pairing may attach oid/CRC claims to previously unknown packs.
        self.repair_pairings()?;

        // Resolve anything new, and only recompute the dependency subgraphs
        // that the new source could unblock.
        let resolve = self.resolve_new_and_unblocked()?;
        let mut report = report;
        report.resolve = Some(resolve);
        Ok(report)
    }

    fn resolve_new_and_unblocked(&self) -> Result<super::build::ResolveReport> {
        let new_ids = self.unresolved_candidate_ids()?;
        let mut rt = Runtime::new(self);
        rt.used_seed = self.db.used_bytes()?;
        for id in &new_ids {
            let res = self.resolve_candidate(&mut rt, *id)?;
            self.persist(&mut rt, *id, &res)?;
        }
        // Newly materialised bases may unblock prior missing-base objects.
        self.recompute_consumers(&mut rt, rt.touched.iter().copied().collect())?;
        self.db.set_used_bytes(rt.used_seed)?;
        let mut r = super::build::ResolveReport::default();
        r.summarize(self)?;
        Ok(r)
    }

    fn unresolved_candidate_ids(&self) -> Result<Vec<i64>> {
        let c = self.db.lock();
        let mut stmt = c.prepare(
            "SELECT c.id FROM candidate c
             LEFT JOIN resolution r ON r.candidate_id = c.id
             WHERE r.candidate_id IS NULL ORDER BY c.id",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn source_by_digest(&self, digest: &str) -> Result<Option<SourceRow>> {
        let c = self.db.lock();
        Ok(c
            .query_row(
                "SELECT * FROM source WHERE sha256 = ?1",
                params![digest],
                row_to_source,
            )
            .optional()?)
    }

    // ---- pack ---------------------------------------------------------------

    fn import_pack(
        &self,
        filename: &str,
        digest: &str,
        data: &[u8],
    ) -> Result<ImportReport> {
        let image = parse_pack_image(data);
        let (image, fatal) = match image {
            Ok(img) => (img, None),
            Err(e) => {
                let sid = self.insert_source(
                    knd::PACK, filename, digest, data.len(), None, None, None,
                    "fatal", &e.to_string(),
                )?;
                return Ok(ImportReport {
                    source_id: Some(sid),
                    kind: knd::PACK.into(),
                    filename: filename.into(),
                    sha256: digest.into(),
                    parse_status: "fatal".into(),
                    parse_detail: e.to_string(),
                    candidates: 0,
                    duplicate: false,
                    resolve: None,
                });
            }
        };
        let _ = fatal;

        let status = if image.parse_error.is_some() { "partial" } else { "ok" };
        let detail = image.parse_error.clone().unwrap_or_default();
        let sid = self.insert_source(
            knd::PACK,
            filename,
            digest,
            data.len(),
            Some(image.version as i64),
            Some(image.count as i64),
            Some(hex_id(&image.stored_checksum)),
            if image.checksum_ok { status } else { "checksum_bad" },
            &if image.checksum_ok {
                detail.clone()
            } else {
                let mut d = format!(
                    "pack SHA1 mismatch: stored {} != computed {}",
                    hex_id(&image.stored_checksum),
                    hex_id(&image.computed_checksum)
                );
                if !detail.is_empty() {
                    d.push_str("; ");
                    d.push_str(&detail);
                }
                d
            },
        )?;
        if !image.checksum_ok {
            self.set_source_checksums(
                sid,
                Some(&hex_id(&image.stored_checksum)),
                Some(&hex_id(&image.computed_checksum)),
            )?;
        }

        let mut offset_to_id = HashMap::new();
        for e in &image.entries {
            let id = self.insert_candidate_pack(sid, e)?;
            offset_to_id.insert(e.offset, id);
        }
        self.insert_pack_edges(sid, &image, &offset_to_id)?;

        Ok(ImportReport {
            source_id: Some(sid),
            kind: knd::PACK.into(),
            filename: filename.into(),
            sha256: digest.into(),
            parse_status: status.into(),
            parse_detail: detail,
            candidates: image.entries.len(),
            duplicate: false,
            resolve: None,
        })
    }

    fn insert_source(
        &self,
        kind: &str,
        filename: &str,
        digest: &str,
        size: usize,
        version: Option<i64>,
        count: Option<i64>,
        checksum_hex: Option<String>,
        status: &str,
        detail: &str,
    ) -> Result<i64> {
        let c = self.db.lock();
        c.execute(
            "INSERT INTO source(kind,filename,sha256,size,path,version,object_count,
                stored_checksum_hex,pack_checksum_hex,checksum_ok,parse_status,parse_detail)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10,?11)",
            params![
                kind,
                filename,
                digest,
                size as i64,
                digest,
                version,
                count,
                checksum_hex,
                status == "ok",
                status,
                detail,
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    fn set_source_checksums(
        &self,
        sid: i64,
        stored: Option<&str>,
        computed: Option<&str>,
    ) -> Result<()> {
        let c = self.db.lock();
        c.execute(
            "UPDATE source SET stored_checksum_hex = ?1, pack_checksum_hex = ?2 WHERE id = ?3",
            params![stored, computed, sid],
        )?;
        Ok(())
    }

    fn insert_candidate_pack(
        &self,
        sid: i64,
        e: &crate::git::pack::PackEntry,
    ) -> Result<i64> {
        let claim = e.claim_oid.as_ref().map(hex_id);
        let crc_ok = e.crc_ok().map(|b| b as i64);
        let c = self.db.lock();
        c.execute(
            "INSERT INTO candidate(source_id,pack_offset,declared_oid_hex,computed_oid_hex,
                obj_type,claimed_size,inflated_size,compressed_len,header_len,
                entry_crc32,idx_crc32,crc_ok,ofs_base_offset,ref_base_oid_hex,
                parse_status,parse_detail,pinned)
             VALUES(?1,?2,?3,NULL,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,0)",
            params![
                sid,
                e.offset as i64,
                claim,
                e.kind.name(),
                e.claimed_size as i64,
                e.inflated_len as i64,
                e.compressed_len as i64,
                e.header_len as i64,
                e.entry_crc32 as i64 & 0xffff_ffff,
                e.idx_crc32.map(|v| v as i64 & 0xffff_ffff),
                crc_ok,
                e.ofs_base_offset.map(|v| v as i64),
                e.ref_base_oid.as_ref().map(hex_id),
                e.inflate_status,
                e.inflate_detail,
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    fn insert_pack_edges(
        &self,
        sid: i64,
        image: &crate::git::pack::PackImage,
        offset_to_id: &HashMap<u64, i64>,
    ) -> Result<()> {
        let c = self.db.lock();
        for e in &image.entries {
            let from = offset_to_id[&e.offset];
            match e.kind {
                crate::git::types::ObjType::OfsDelta => {
                    if let Some(off) = e.ofs_base_offset {
                        let to = offset_to_id.get(&off).copied();
                        c.execute(
                            "INSERT OR REPLACE INTO candidate_edge
                                (from_candidate_id,to_candidate_id,to_oid_hex,to_offset,kind)
                             VALUES(?1,?2,NULL,?3,'ofs')",
                            params![from, to, off as i64],
                        )?;
                    }
                }
                crate::git::types::ObjType::RefDelta => {
                    let oid = e.ref_base_oid.as_ref().map(hex_id);
                    c.execute(
                        "INSERT OR REPLACE INTO candidate_edge
                            (from_candidate_id,to_candidate_id,to_oid_hex,to_offset,kind)
                         VALUES(?1,NULL,?2,NULL,'ref')",
                        params![from, oid],
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl App {
    // ---- loose --------------------------------------------------------------

    fn import_loose(
        &self,
        filename: &str,
        digest: &str,
        data: &[u8],
    ) -> Result<ImportReport> {
        let filename_oid = loose_filename_oid(filename);
        let image = match parse_loose(data) {
            Ok(img) => img,
            Err(e) => {
                let sid = self.insert_source(
                    knd::LOOSE, filename, digest, data.len(), None, None,
                    filename_oid.clone(), "fatal", &e.to_string(),
                )?;
                return Ok(ImportReport {
                    source_id: Some(sid),
                    kind: knd::LOOSE.into(),
                    filename: filename.into(),
                    sha256: digest.into(),
                    parse_status: "fatal".into(),
                    parse_detail: e.to_string(),
                    candidates: 0,
                    duplicate: false,
                    resolve: None,
                });
            }
        };

        let status = if image.status == "ok" { "ok" } else { image.status };
        let sid = self.insert_source(
            knd::LOOSE,
            filename,
            digest,
            data.len(),
            None,
            None,
            filename_oid.clone().or(Some(hex_id(&image.computed_oid))),
            status,
            &image.detail,
        )?;

        let (kind_name, computed) = match image.kind {
            Some(k) => (k.name(), Some(hex_id(&image.computed_oid))),
            None => ("unknown", None),
        };
        let parse_status = if image.status == "ok" { "ok" } else { image.status };

        let c = self.db.lock();
        c.execute(
            "INSERT INTO candidate(source_id,pack_offset,declared_oid_hex,computed_oid_hex,
                obj_type,claimed_size,inflated_size,compressed_len,header_len,
                parse_status,parse_detail,pinned)
             VALUES(?1,NULL,?2,?3,?4,?5,?6,?7,0,?8,?9,0)",
            params![
                sid,
                filename_oid,
                computed,
                kind_name,
                image.body.len() as i64,
                image.inflated_len as i64,
                image.compressed_len as i64,
                parse_status,
                image.detail,
            ],
        )?;

        Ok(ImportReport {
            source_id: Some(sid),
            kind: knd::LOOSE.into(),
            filename: filename.into(),
            sha256: digest.into(),
            parse_status: status.into(),
            parse_detail: image.detail,
            candidates: 1,
            duplicate: false,
            resolve: None,
        })
    }

    // ---- idx ----------------------------------------------------------------

    fn import_idx(
        &self,
        filename: &str,
        digest: &str,
        data: &[u8],
    ) -> Result<ImportReport> {
        let image = match parse_idx_image(data) {
            Ok(img) => img,
            Err(e) => {
                let sid = self.insert_source(
                    knd::IDX, filename, digest, data.len(), None, None, None,
                    "fatal", &e.to_string(),
                )?;
                return Ok(ImportReport {
                    source_id: Some(sid),
                    kind: knd::IDX.into(),
                    filename: filename.into(),
                    sha256: digest.into(),
                    parse_status: "fatal".into(),
                    parse_detail: e.to_string(),
                    candidates: 0,
                    duplicate: false,
                    resolve: None,
                });
            }
        };

        let sid = {
            let c = self.db.lock();
            c.execute(
                "INSERT INTO source(kind,filename,sha256,size,path,version,object_count,
                    stored_checksum_hex,pack_checksum_hex,checksum_ok,parse_status,parse_detail)
                 VALUES('idx',?1,?2,?3,?4,?5,?6,NULL,?7,1,?8,?9)",
                params![
                    filename,
                    digest,
                    data.len() as i64,
                    digest,
                    image.version as i64,
                    image.count as i64,
                    hex_id(&image.pack_checksum),
                    image.parse_error.as_deref().unwrap_or("ok"),
                    image.parse_error.clone().unwrap_or_default(),
                ],
            )?;
            c.last_insert_rowid()
        };

        Ok(ImportReport {
            source_id: Some(sid),
            kind: knd::IDX.into(),
            filename: filename.into(),
            sha256: digest.into(),
            parse_status: image.parse_error.as_deref().unwrap_or("ok").into(),
            parse_detail: image.parse_error.unwrap_or_default(),
            candidates: image.records.len(),
            duplicate: false,
            resolve: None,
        })
    }

    /// Pair every imported index with a pack whose stored trailer checksum
    /// equals the index's pack-checksum. Attaches declared oids and CRCs,
    /// and records mismatch evidence for both sides.
    pub fn repair_pairings(&self) -> Result<()> {
        // Load idx/pack sources and their bytes on demand.
        let idx_sources = self.sources_of_kind(knd::IDX)?;
        let pack_sources = self.sources_of_kind(knd::PACK)?;

        for idx_src in &idx_sources {
            let idx_bytes = std::fs::read(self.files_dir.join(&idx_src.sha256))?;
            let idx = match parse_idx_image(&idx_bytes) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let mut matched: Option<&SourceRow> = None;
            for ps in &pack_sources {
                if ps.pack_checksum_hex.as_deref()
                    == Some(hex_id(&idx.pack_checksum).as_str())
                {
                    matched = Some(ps);
                    break;
                }
                // v1 idx only stores the checksum; compare via file trailer.
                if let Some(stored) = &ps.pack_checksum_hex {
                    if stored.eq_ignore_ascii_case(&hex_id(&idx.pack_checksum)) {
                        matched = Some(ps);
                        break;
                    }
                }
            }

            match matched {
                Some(ps) => {
                    self.set_pair(idx_src.id, Some(ps.id), "matched by pack checksum")?;
                    self.set_pair(ps.id, Some(idx_src.id), "matched by pack checksum")?;
                    self.attach_idx_claims(ps.id, &idx)?;
                }
                None => {
                    self.set_pair(
                        idx_src.id,
                        None,
                        "orphan index: pack checksum matches no imported pack",
                    )?;
                }
            }
        }

        // A pack without a matching index gets explicit evidence.
        for ps in &pack_sources {
            if ps.pair_source_id.is_none() {
                let has_idx = idx_sources.iter().any(|i| i.pair_source_id == Some(ps.id));
                if !has_idx {
                    self.set_pair(ps.id, None, "no matching index imported")?;
                }
            }
        }
        Ok(())
    }

    fn set_pair(&self, sid: i64, pair: Option<i64>, note: &str) -> Result<()> {
        let c = self.db.lock();
        c.execute(
            "UPDATE source SET pair_source_id = ?1, pairing_note = ?2 WHERE id = ?3",
            params![pair, note, sid],
        )?;
        Ok(())
    }

    fn attach_idx_claims(&self, pack_sid: i64, idx: &crate::git::idx::IdxImage) -> Result<()> {
        let cands = self.candidates_of_source(pack_sid)?;
        let c = self.db.lock();
        for cand in cands {
            let off = match cand.pack_offset {
                Some(o) => o as u64,
                None => continue,
            };
            if let Some(rec) = idx.record_at(off) {
                let oid = hex_id(&rec.oid);
                let crc = if idx.has_crc { Some(rec.crc32 as i64 & 0xffff_ffff) } else { None };
                let crc_ok = crc
                    .zip(cand.entry_crc32)
                    .map(|(a, b)| (a as u32 == b as u32) as i64);
                c.execute(
                    "UPDATE candidate SET declared_oid_hex = ?1, idx_crc32 = ?2, crc_ok = ?3
                     WHERE id = ?4",
                    params![oid, crc, crc_ok, cand.id],
                )?;
                // Record resolved ofs edges now that base offsets map to ids.
                c.execute(
                    "UPDATE candidate_edge SET to_candidate_id =
                        (SELECT id FROM candidate WHERE source_id = ?1 AND pack_offset = to_offset)
                     WHERE from_candidate_id IN
                        (SELECT id FROM candidate WHERE source_id = ?1) AND kind='ofs'",
                    params![pack_sid],
                )?;
            }
        }
        Ok(())
    }

    pub fn sources_of_kind(&self, kind: &str) -> Result<Vec<SourceRow>> {
        let c = self.db.lock();
        let mut stmt = c.prepare("SELECT * FROM source WHERE kind = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![kind], row_to_source)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn loose_filename_oid(filename: &str) -> Option<String> {
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .trim_end_matches(".zlib")
        .to_string();
    if base.len() == 40 && base.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(base);
    }
    // sharded form: ab/cdef... (2 + 38)
    if base.len() == 41 {
        let mut it = base.split('/');
        let (a, b) = (it.next()?, it.next()?);
        let joined = format!("{a}{b}");
        if a.len() == 2
            && b.len() == 38
            && joined.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some(joined);
        }
    }
    None
}

/// Keep the engine's pack parser symbol reachable for tests/tools.
pub fn parse_pack_bytes(data: &[u8]) -> Result<crate::git::pack::PackImage> {
    parse_pack_image(data)
}

/// Build an attached idx image against an in-memory pack (test support).
pub fn build_attached(
    pack: &mut crate::git::pack::PackImage,
    idx: &crate::git::idx::IdxImage,
) {
    attach_idx(pack, idx);
}
