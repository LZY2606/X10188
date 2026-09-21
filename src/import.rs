//! File ingestion: save uploads into the data directory, parse them,
//! pair packs with indexes by checksum, and record object candidates.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::params;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::git::idx::parse_idx;
use crate::git::loose::parse_loose;
use crate::git::pack::{parse_pack, ParseBudget};
use crate::git::{git_oid, GitType};
use crate::store::{now_ts, Store, DEFAULT_BRANCH};

/// Outcome of one import call.
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub candidate_count: usize,
    pub paired_id: Option<i64>,
    pub parse_errors: Vec<String>,
}

impl Store {
    /// Save raw bytes into the data directory and ingest them.
    /// Import order never affects candidate ordering: candidates are sorted
    /// deterministically by (oid, source id, offset) at query time.
    pub fn import_bytes(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> anyhow::Result<ImportReport> {
        let sha256 = hex::encode(Sha256::digest(bytes));
        {
            let conn = self.db.lock().unwrap();
            if let Some(id) = conn
                .query_row(
                    "SELECT id FROM sources WHERE sha256 = ?1",
                    params![sha256],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
            {
                return Ok(ImportReport {
                    source_id: id,
                    kind: "duplicate".into(),
                    candidate_count: 0,
                    paired_id: None,
                    parse_errors: vec!["identical file already imported".into()],
                });
            }
        }

        let lower = filename.to_ascii_lowercase();
        let kind = if lower.ends_with(".pack") {
            "pack"
        } else if lower.ends_with(".idx") {
            "idx"
        } else {
            "loose"
        };

        let ext = match kind {
            "pack" => ".pack",
            "idx" => ".idx",
            _ => "",
        };
        let safe = sanitize_filename(filename);
        let stored_name = format!("{}{ext}", &sha256[..16]);
        let stored_path: PathBuf = ["files", &stored_name].iter().collect();
        let abs = self.data_dir.join(&stored_path);
        std::fs::write(abs, bytes)?;

        let conn = self.db.lock().unwrap();
        let source_id = conn.last_insert_rowid_or(
            "INSERT INTO sources(kind, filename, stored_path, size, sha256, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                kind,
                safe,
                stored_path.display().to_string(),
                bytes.len() as i64,
                sha256,
                now_ts()
            ],
        )?;
        drop(conn);

        let report = match kind {
            "pack" => self.ingest_pack(source_id, bytes),
            "idx" => self.ingest_idx(source_id, bytes),
            _ => self.ingest_loose(source_id, filename, bytes),
        }?;

        // After every import, attempt checksum-based pairing and rebuild the
        // affected pack/idx candidates so CRC evidence is attached.
        self.try_pair_and_refresh()?;
        Ok(report)
    }
}

trait InsertHelper {
    fn last_insert_rowid_or(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> rusqlite::Result<i64>;
}

impl InsertHelper for rusqlite::Connection {
    fn last_insert_rowid_or(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> rusqlite::Result<i64> {
        self.execute(sql, params)?;
        Ok(self.last_insert_rowid())
    }
}

fn sanitize_filename(name: &str) -> String {
    name.split('/')
        .next_back()
        .unwrap_or(name)
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

use rusqlite::OptionalExtension;
