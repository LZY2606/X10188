//! Parse imported files into candidate rows and keep pack/idx pairs
//! consistent by pack checksum.

use std::collections::HashMap;

use rusqlite::params;

use crate::git::idx::parse_idx;
use crate::git::loose::parse_loose;
use crate::git::pack::{parse_pack, ParseBudget};
use crate::git::{git_oid, GitType};
use crate::import::ImportReport;
use crate::store::Store;
use crate::pairing::loose_name_oid;

const LOOSE_CAP: u64 = 256 * 1024 * 1024;

impl Store {
    pub(crate) fn ingest_pack(
        &self,
        source_id: i64,
        bytes: &[u8],
    ) -> anyhow::Result<ImportReport> {
        self.refresh_pack(source_id)?;
        let conn = self.db.lock().unwrap();
        let (summary, errors): (String, String) = conn.query_row(
            "SELECT parse_summary, parse_errors FROM sources WHERE id=?1",
            params![source_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let count = conn.query_row(
            "SELECT COUNT(*) FROM objects WHERE source_id=?1",
            params![source_id],
            |r| r.get::<_, i64>(0),
        )? as usize;
        let checksum: Option<String> = conn.query_row(
            "SELECT checksum FROM sources WHERE id=?1",
            params![source_id],
            |r| r.get(0),
        )?;
        let parse_errors = serde_json::from_str::<Vec<String>>(&errors)
            .unwrap_or_default();
        Ok(ImportReport {
            source_id,
            kind: "pack".into(),
            candidate_count: count,
            paired_id: checksum.and(None),
            parse_errors,
        })
    }

    pub(crate) fn ingest_idx(
        &self,
        source_id: i64,
        bytes: &[u8],
    ) -> anyhow::Result<ImportReport> {
        match parse_idx(bytes) {
            Ok(idx) => {
                let mut errors = idx.errors.clone();
                let summary = format!(
                    "idx v{} objects={} fanout_tail={}",
                    idx.version,
                    idx.rows.len(),
                    idx.fanout[255]
                );
                self.set_source_summary(source_id, &summary, &errors)?;
                self.set_source_fanout(source_id, &idx.fanout)?;
                self.set_source_checksum(source_id, idx.pack_checksum.clone())?;
                Ok(ImportReport {
                    source_id,
                    kind: "idx".into(),
                    candidate_count: idx.rows.len(),
                    paired_id: None,
                    parse_errors: std::mem::take(&mut errors),
                })
            }
            Err(e) => {
                self.set_source_summary(source_id, "idx unparseable", &[e.clone()])?;
                Ok(ImportReport {
                    source_id,
                    kind: "idx".into(),
                    candidate_count: 0,
                    paired_id: None,
                    parse_errors: vec![e],
                })
            }
        }
    }

    pub(crate) fn ingest_loose(
        &self,
        source_id: i64,
        original_name: &str,
        bytes: &[u8],
    ) -> anyhow::Result<ImportReport> {
        let mut errors = Vec::new();
        match parse_loose(bytes, LOOSE_CAP) {
            Ok(obj) => {
                let oid = git_oid(obj.kind, &obj.content);
                if let Some(expected) = loose_name_oid(original_name) {
                    if expected != oid {
                        errors.push(format!(
                            "loose object name claims {expected} but content hashes to {oid}"
                        ));
                    }
                }
                self.insert_object_row(
                    &oid,
                    source_id,
                    "loose",
                    obj.kind.name(),
                    0,
                    bytes.len() as i64,
                    obj.content.len() as i64,
                    None,
                    None,
                    None,
                    None,
                    errors.first().cloned(),
                )?;
                self.set_source_checksum(source_id, Some(oid.clone()))?;
                self.set_source_summary(
                    source_id,
                    &format!("loose {} {} bytes", obj.kind.name(), obj.content.len()),
                    &errors,
                )?;
                Ok(ImportReport {
                    source_id,
                    kind: "loose".into(),
                    candidate_count: 1,
                    paired_id: None,
                    parse_errors: errors,
                })
            }
            Err(e) => {
                self.insert_object_row(
                    "",
                    source_id,
                    "loose",
                    "unknown",
                    0,
                    bytes.len() as i64,
                    0,
                    None,
                    None,
                    None,
                    None,
                    Some(e.clone()),
                )?;
                self.set_source_summary(source_id, "loose unparseable", &[e.clone()])?;
                Ok(ImportReport {
                    source_id,
                    kind: "loose".into(),
                    candidate_count: 0,
                    paired_id: None,
                    parse_errors: vec![e],
                })
            }
        }
    }
}
