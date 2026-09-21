//! Candidate-row insertion, pack/idx checksum pairing and pack rebuilds.

use std::collections::HashMap;

use rusqlite::params;

use crate::git::idx::{parse_idx, ParsedIdx};
use crate::git::pack::{parse_pack, ParseBudget, ParsedPack};
use crate::git::{git_oid, GitType};
use crate::store::Store;

pub(crate) fn loose_name_oid(name: &str) -> Option<String> {
    let base = name.split('/').next_back().unwrap_or(name);
    if base.len() == 40 && base.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(base.to_ascii_lowercase())
    } else {
        None
    }
}

impl Store {
    pub(crate) fn set_source_summary(
        &self,
        id: i64,
        summary: &str,
        errors: &[String],
    ) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE sources SET parse_summary=?1, parse_errors=?2 WHERE id=?3",
            params![summary, serde_json::to_string(errors).unwrap_or_default(), id],
        )?;
        Ok(())
    }


    pub(crate) fn set_source_fanout(
        &self,
        id: i64,
        fanout: &[u32; 256],
    ) -> anyhow::Result<()> {
        let bytes: Vec<u8> = fanout.iter().flat_map(|v| v.to_be_bytes()).collect();
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE sources SET fanout=?1 WHERE id=?2",
            rusqlite::params![bytes, id],
        )?;
        Ok(())
    }

    pub(crate) fn set_source_checksum(
        &self,
        id: i64,
        checksum: Option<String>,
    ) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE sources SET checksum=?1 WHERE id=?2",
            params![checksum, id],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_object_row(
        &self,
        oid: &str,
        source_id: i64,
        locator: &str,
        kind_name: &str,
        offset: i64,
        raw_size: i64,
        inflate_size: i64,
        crc_ok: Option<bool>,
        parse_error: Option<String>,
        base_ref: Option<String>,
        base_offset: Option<i64>,
        _err: Option<String>,
    ) -> anyhow::Result<()> {
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO objects(oid, source_id, locator, kind_name, \"offset\",
                 raw_size, inflate_size, crc_ok, parse_error, base_ref, base_offset,
                 claimed_oid)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11, 0)",
            params![
                oid,
                source_id,
                locator,
                kind_name,
                offset,
                raw_size,
                inflate_size,
                crc_ok.map(|b| b as i64),
                parse_error,
                base_ref,
                base_offset
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Rebuild every candidate row belonging to a pack, enriching with idx
    /// names/CRCs when a checksum-matching index is paired.
    pub(crate) fn rebuild_pack_objects(
        &self,
        source_id: i64,
        bytes: &[u8],
        parsed: &ParsedPack,
        idx_rows: &HashMap<u64, (String, u32)>,
    ) -> anyhow::Result<usize> {
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM objects WHERE source_id=?1 AND locator LIKE 'pack:%'",
            params![source_id],
        )?;

        let mut inserted = 0usize;
        for entry in &parsed.entries {
            let offset = entry.offset as i64;
            let locator = format!("pack:{}", entry.offset);
            let kind_name = entry
                .kind
                .map(|k| k.name().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let (idx_oid, idx_crc) = idx_rows
                .get(&entry.offset)
                .map(|(o, c)| (Some(o.clone()), Some(*c)))
                .unwrap_or((None, None));

            let mut oid = String::new();
            let mut parse_error = entry.error.clone();

            if entry.error.is_none() {
                if let Some(kind) = entry.kind {
                    if kind.is_base() {
                        oid = git_oid(kind, &entry.inflated);
                        if let Some(expected) = &idx_oid {
                            if expected != &oid {
                                let msg = format!(
                                    "oid conflict at offset {}: content hashes to {oid}, index names it {expected}",
                                    entry.offset
                                );
                                parse_error.get_or_insert(msg);
                            }
                        }
                    } else if let Some(expected) = &idx_oid {
                        oid = expected.clone();
                    }
                }
            } else if let Some(expected) = &idx_oid {
                oid = expected.clone();
            }

            let (base_ref, base_offset) = match entry.kind {
                Some(GitType::OfsDelta) => (
                    entry.base_offset.map(|o| format!("ofs:{o}")),
                    entry.base_offset.map(|o| o as i64),
                ),
                Some(GitType::RefDelta) => (entry.base_ref.clone(), None),
                _ => (None, None),
            };

            let crc_ok = idx_crc.and(entry.crc_ok);

            tx.execute(
                "INSERT INTO objects(oid, source_id, locator, kind_name, \"offset\",
                     raw_size, inflate_size, crc_ok, parse_error, base_ref, base_offset,
                     claimed_oid)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11, 0)",
                params![
                    oid,
                    source_id,
                    locator,
                    kind_name,
                    offset,
                    (entry.compressed_len as i64) + entry.header_len as i64,
                    entry.inflated.len() as i64,
                    crc_ok.map(|b| b as i64),
                    parse_error,
                    base_ref,
                    base_offset
                ],
            )?;
            inserted += 1;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// After every import, pair packs and indexes by the pack sha1 checksum,
    /// then rebuild any pack whose pairing situation changed.
    pub(crate) fn try_pair_and_refresh(&self) -> anyhow::Result<()> {
        // Snapshot current pair state.
        let packs: Vec<(i64, Option<String>, Option<i64>)> = {
            let conn = self.db.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, checksum, paired_source_id FROM sources WHERE kind='pack'",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get(2)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let idxs: Vec<(i64, Option<String>, Option<i64>)> = {
            let conn = self.db.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, checksum, paired_source_id FROM sources WHERE kind='idx'",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get(2)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut idx_by_checksum: HashMap<String, i64> = HashMap::new();
        for (id, checksum, _) in &idxs {
            if let Some(c) = checksum {
                idx_by_checksum.entry(c.clone()).or_insert(*id);
            }
        }

        let mut changed_packs = Vec::new();
        {
            let conn = self.db.lock().unwrap();
            for (pack_id, checksum, current_pair) in &packs {
                let desired = checksum
                    .as_ref()
                    .and_then(|c| idx_by_checksum.get(c).copied());
                if desired != *current_pair {
                    conn.execute(
                        "UPDATE sources SET paired_source_id=?1 WHERE id=?2",
                        params![desired, pack_id],
                    )?;
                    if let Some(idx_id) = desired {
                        conn.execute(
                            "UPDATE sources SET paired_source_id=?1 WHERE id=?2",
                            params![pack_id, idx_id],
                        )?;
                    }
                    changed_packs.push(*pack_id);
                }
            }
        }

        for pack_id in changed_packs {
            self.refresh_pack(pack_id)?;
        }
        Ok(())
    }

    /// (Re)parse a pack together with its paired index and rebuild rows.
    pub(crate) fn refresh_pack(&self, pack_id: i64) -> anyhow::Result<()> {
        let (stored_path, idx_id) = {
            let conn = self.db.lock().unwrap();
            conn.query_row(
                "SELECT stored_path, paired_source_id FROM sources WHERE id=?1",
                params![pack_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
            )?
        };
        let pack_bytes = std::fs::read(self.data_dir.join(&stored_path))?;

        let mut idx_rows: HashMap<u64, (String, u32)> = HashMap::new();
        let mut offsets: Vec<u64> = Vec::new();
        let mut crc_map: HashMap<u64, u32> = HashMap::new();
        let mut idx_errors: Vec<String> = Vec::new();

        if let Some(idx_id) = idx_id {
            let idx_path = {
                let conn = self.db.lock().unwrap();
                conn.query_row(
                    "SELECT stored_path FROM sources WHERE id=?1",
                    params![idx_id],
                    |r| r.get::<_, String>(0),
                )?
            };
            let idx_bytes = std::fs::read(self.data_dir.join(idx_path))?;
            match parse_idx(&idx_bytes) {
                Ok(idx) => {
                    for row in &idx.rows {
                        idx_rows.insert(row.offset, (row.oid.clone(), row.crc32));
                        offsets.push(row.offset);
                        crc_map.insert(row.offset, row.crc32);
                    }
                    idx_errors.extend(idx.errors);
                }
                Err(e) => idx_errors.push(e),
            }
        }

        let parsed = parse_pack(
            &pack_bytes,
            if offsets.is_empty() { None } else { Some(&offsets) },
            if crc_map.is_empty() { None } else { Some(&crc_map) },
            &ParseBudget::default(),
        );
        let count = self.rebuild_pack_objects(pack_id, &pack_bytes, &parsed, &idx_rows)?;
        let mut all_errors = parsed.errors.clone();
        all_errors.extend(idx_errors);
        self.set_source_summary(
            pack_id,
            &format!(
                "pack objects={} intact={} trailer_ok={} paired_idx={:?} candidates={count}",
                parsed.object_count,
                parsed.entries.iter().filter(|e| e.error.is_none()).count(),
                parsed.trailer_ok,
                idx_id
            ),
            &all_errors,
        )?;
        Ok(())
    }
}
