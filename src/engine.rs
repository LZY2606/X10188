//! The resolution engine: imports, candidate identities, delta DAG,
//! budget-aware reconstruction with resumable pauses and incremental
//! subgraph re-resolution.

pub mod build;
pub mod importer;
pub mod query;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::git;
use crate::git::delta::{apply_with_budgets, DeltaBudgets};
use crate::git::idx::IdxImage;
use crate::git::pack::PackImage;
use crate::git::types::{hash_object, oid_hex, ObjType, OID_LEN};
use crate::git::zlib::{inflate_one, InflateLimits, InflateStatus};
use crate::model::{Blocker, Budgets, CandidateRow, ResolutionRow, SourceRow, StepJson};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct App {
    pub db: Db,
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
    pub objects_dir: PathBuf,
    pub budgets: Mutex<Budgets>,
}

#[derive(Debug, Clone)]
pub struct ResolvedObj {
    pub kind: ObjType,
    pub data: Vec<u8>,
    pub depth: u32,
    pub steps: Vec<StepJson>,
}

#[derive(Debug, Clone)]
pub enum Res {
    Done(ResolvedObj),
    MissingBase { blockers: Vec<Blocker> },
    Cycle { chain: Vec<i64> },
    Bad { code: String, detail: String, blockers: Vec<Blocker> },
    Paused { kind: String, limit: u64, used: u64, blockers: Vec<Blocker> },
}

impl Res {
    pub fn from_err(e: &Error) -> Res {
        match e {
            Error::BudgetPaused { kind, limit, used, .. } => Res::Paused {
                kind: kind.clone(),
                limit: *limit,
                used: *used,
                blockers: vec![],
            },
            _ => Res::Bad {
                code: e.code().to_string(),
                detail: e.to_string(),
                blockers: vec![],
            },
        }
    }
}

pub struct Runtime<'a> {
    pub app: &'a App,
    pub visiting: HashSet<i64>,
    pub chain: Vec<i64>,
    /// Candidates whose stored resolution must be (re)written after this run.
    pub touched: HashSet<i64>,
    /// Cumulative expanded bytes consumed during this run (seeded from DB).
    pub used_seed: u64,
}

impl<'a> Runtime<'a> {
    pub fn new(app: &'a App) -> Self {
        Runtime {
            app,
            visiting: HashSet::new(),
            chain: Vec::new(),
            touched: HashSet::new(),
            used_seed: 0,
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

impl App {
    pub fn open(data_dir: &Path) -> Result<App> {
        std::fs::create_dir_all(data_dir)?;
        let files_dir = data_dir.join("sources");
        let objects_dir = data_dir.join("objects");
        std::fs::create_dir_all(&files_dir)?;
        std::fs::create_dir_all(&objects_dir)?;
        let db = Db::open_in_dir(data_dir)?;
        let app = App {
            db,
            data_dir: data_dir.to_path_buf(),
            files_dir,
            objects_dir,
            budgets: Mutex::new(Budgets::default()),
        };
        app.load_settings()?;
        Ok(app)
    }

    fn load_settings(&self) -> Result<()> {
        let mut b = self.budgets.lock().unwrap();
        if let Some(v) = self.db.get_setting("max_depth")? {
            b.max_depth = v.parse().unwrap_or(b.max_depth);
        }
        if let Some(v) = self.db.get_setting("max_total_bytes")? {
            b.max_total_bytes = v.parse().unwrap_or(b.max_total_bytes);
        }
        if let Some(v) = self.db.get_setting("max_single_ratio")? {
            b.max_single_ratio = v.parse().unwrap_or(b.max_single_ratio);
        }
        if let Some(v) = self.db.get_setting("max_result_bytes")? {
            b.max_result_bytes = v.parse().unwrap_or(b.max_result_bytes);
        }
        Ok(())
    }

    pub fn budgets(&self) -> Budgets {
        *self.budgets.lock().unwrap()
    }

    pub fn set_budgets(&self, b: Budgets) -> Result<()> {
        *self.budgets.lock().unwrap() = b;
        self.db.set_setting("max_depth", &b.max_depth.to_string())?;
        self.db.set_setting("max_total_bytes", &b.max_total_bytes.to_string())?;
        self.db.set_setting("max_single_ratio", &b.max_single_ratio.to_string())?;
        self.db.set_setting("max_result_bytes", &b.max_result_bytes.to_string())?;
        Ok(())
    }

    // ----- row helpers ------------------------------------------------------

    pub fn get_candidate(&self, id: i64) -> Result<CandidateRow> {
        let c = self.db.lock();
        c.query_row("SELECT * FROM candidate WHERE id = ?1", params![id], row_to_candidate)
            .optional_row()
    }

    pub fn source_row(&self, id: i64) -> Result<SourceRow> {
        let c = self.db.lock();
        c.query_row("SELECT * FROM source WHERE id = ?1", params![id], row_to_source)
            .optional_row()
    }

    pub fn all_candidates(&self) -> Result<Vec<CandidateRow>> {
        let c = self.db.lock();
        let mut stmt = c.prepare("SELECT * FROM candidate ORDER BY id")?;
        let rows = stmt.query_map([], row_to_candidate)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn candidates_of_source(&self, source_id: i64) -> Result<Vec<CandidateRow>> {
        let c = self.db.lock();
        let mut stmt = c
            .prepare("SELECT * FROM candidate WHERE source_id = ?1 ORDER BY pack_offset, id")?;
        let rows = stmt.query_map(params![source_id], row_to_candidate)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn candidate_compressed(&self, cand: &CandidateRow) -> Result<Vec<u8>> {
        let (path, start, len) = self.candidate_bytes_locator(cand)?;
        let data = std::fs::read(&path)?;
        let end = start + len;
        if end > data.len() {
            return Err(Error::bad("candidate byte range exceeds source file"));
        }
        Ok(data[start..end].to_vec())
    }

    fn candidate_bytes_locator(&self, cand: &CandidateRow) -> Result<(PathBuf, usize, usize)> {
        let src = self.source_row(cand.source_id)?;
        let path = self.files_dir.join(&src.sha256);
        let start = cand.pack_offset.unwrap_or(0) as usize + cand.header_len as usize;
        Ok((path, start, cand.compressed_len as usize))
    }

    /// Deterministic global ordering for candidates sharing an oid:
    /// pinned first, then well-formed over parse-bad, then smallest source
    /// digest, then filename, then offset. Import order/id is never consulted
    /// for ordering (id kept only as a final tie-break on identical files).
    pub fn ranked_candidates_for_oid(&self, oid: &str) -> Result<Vec<CandidateRow>> {
        let c = self.db.lock();
        let mut stmt = c.prepare(
            "SELECT c.* FROM candidate c
             JOIN source s ON s.id = c.source_id
             WHERE c.declared_oid_hex = ?1 OR c.computed_oid_hex = ?1
             ORDER BY c.pinned DESC,
                      CASE c.parse_status WHEN 'ok' THEN 0 ELSE 1 END,
                      s.sha256 ASC, s.filename ASC,
                      c.pack_offset ASC, c.id ASC",
        )?;
        let rows = stmt.query_map(params![oid], row_to_candidate)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn choose_ref_base(&self, oid: &str) -> Option<CandidateRow> {
        self.ranked_candidates_for_oid(oid)
            .ok()?
            .into_iter()
            .next()
    }

    pub fn ofs_base_candidate(&self, cand: &CandidateRow) -> Result<Option<CandidateRow>> {
        let Some(off) = cand.ofs_base_offset else { return Ok(None) };
        let c = self.db.lock();
        Ok(c.query_row(
            "SELECT * FROM candidate WHERE source_id = ?1 AND pack_offset = ?2",
            params![cand.source_id, off],
            row_to_candidate,
        )
        .optional()?)
    }

    // ----- content storage --------------------------------------------------

    pub fn write_content(&self, cand_id: i64, data: &[u8]) -> Result<String> {
        let name = format!("cand_{cand_id}.out");
        std::fs::write(self.objects_dir.join(&name), data)?;
        Ok(name)
    }

    pub fn remove_content(&self, name: &str) {
        let _ = std::fs::remove_file(self.objects_dir.join(name));
    }

    pub fn read_content(&self, name: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.objects_dir.join(name))?)
    }

    // ----- edges ------------------------------------------------------------

    /// Candidates whose *declared* base (ref oid or ofs offset) equals the
    /// given candidate identity. Used for incremental re-resolution.
    pub fn declared_consumers(&self, base: &CandidateRow) -> Result<Vec<i64>> {
        let c = self.db.lock();
        let mut out = Vec::new();
        // ofs consumers share the same source/offset; ref consumers use oid.
        if let Some(off) = base.pack_offset {
            let mut stmt = c.prepare(
                "SELECT from_candidate_id FROM candidate_edge
                 WHERE kind = 'ofs' AND to_offset = ?1
                   AND from_candidate_id IN (SELECT id FROM candidate WHERE source_id = ?2)",
            )?;
            let rows = stmt.query_map(params![off, base.source_id], |r| r.get::<_, i64>(0))?;
            for r in rows {
                out.push(r?);
            }
        }
        if let Some(oid) = base
            .declared_oid_hex
            .clone()
            .or(base.computed_oid_hex.clone())
        {
            let mut stmt = c.prepare(
                "SELECT from_candidate_id FROM candidate_edge
                 WHERE kind = 'ref' AND to_oid_hex = ?1",
            )?;
            let rows = stmt.query_map(params![oid], |r| r.get::<_, i64>(0))?;
            for r in rows {
                out.push(r?);
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}

// ---------- row mapping ----------

#[allow(clippy::too_many_lines)]
pub fn row_to_candidate(r: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow> {
    Ok(CandidateRow {
        id: r.get("id")?,
        source_id: r.get("source_id")?,
        pack_offset: r.get("pack_offset")?,
        declared_oid_hex: r.get("declared_oid_hex")?,
        computed_oid_hex: r.get("computed_oid_hex")?,
        obj_type: r.get("obj_type")?,
        claimed_size: r.get("claimed_size")?,
        inflated_size: r.get("inflated_size")?,
        compressed_len: r.get("compressed_len")?,
        header_len: r.get("header_len")?,
        entry_crc32: r.get("entry_crc32")?,
        idx_crc32: r.get("idx_crc32")?,
        crc_ok: r.get::<_, Option<i64>>("crc_ok")?.map(|v| v != 0),
        ofs_base_offset: r.get("ofs_base_offset")?,
        ref_base_oid_hex: r.get("ref_base_oid_hex")?,
        parse_status: r.get("parse_status")?,
        parse_detail: r.get("parse_detail")?,
        pinned: r.get::<_, i64>("pinned")? != 0,
        path: None,
    })
}

#[allow(clippy::too_many_lines)]
pub fn row_to_source(r: &rusqlite::Row<'_>) -> rusqlite::Result<SourceRow> {
    Ok(SourceRow {
        id: r.get("id")?,
        kind: r.get("kind")?,
        filename: r.get("filename")?,
        sha256: r.get("sha256")?,
        size: r.get("size")?,
        pair_source_id: r.get("pair_source_id")?,
        pairing_note: r.get("pairing_note")?,
        parse_status: r.get("parse_status")?,
        parse_detail: r.get("parse_detail")?,
        pack_checksum_hex: r.get("pack_checksum_hex")?,
        imported_at: r.get("imported_at")?,
    })
}

trait OptionalRow<T> {
    fn optional_row(self) -> Result<T>;
}

impl<T> OptionalRow<T> for rusqlite::Result<Option<T>> {
    fn optional_row(self) -> Result<T> {
        match self {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(Error::not_found("row not found")),
            Err(e) => Err(Error::from(e)),
        }
    }
}

// ---------- shared low-level helpers for submodules ----------

pub fn parse_pack_image(data: &[u8]) -> Result<PackImage> {
    git::pack::parse_pack(data)
}
pub fn parse_idx_image(data: &[u8]) -> Result<IdxImage> {
    git::idx::parse_idx(data)
}
pub fn git_hash(kind: ObjType, body: &[u8]) -> [u8; OID_LEN] {
    hash_object(kind, body)
}
pub fn hex_id(id: &[u8; OID_LEN]) -> String {
    oid_hex(id)
}
pub fn inflate_budgeted(
    data: &[u8],
    claimed: u64,
    total_remaining: u64,
    ratio: u64,
) -> Result<crate::git::zlib::InflateOutcome> {
    inflate_one(
        data,
        &InflateLimits {
            claimed,
            total_remaining,
            max_ratio: ratio,
            hard_cap: crate::git::zlib::DEFAULT_HARD_CAP,
        },
    )
}
pub fn inflate_status_name(s: &InflateStatus) -> &'static str {
    match s {
        InflateStatus::Ok => "ok",
        InflateStatus::SizeSpoof { .. } => "size_spoof",
        InflateStatus::Truncated => "truncated",
        InflateStatus::HardCapExceeded => "hard_cap",
        InflateStatus::BudgetPaused { .. } => "budget_paused",
    }
}
pub fn delta_apply(
    base: &[u8],
    delta_payload: &[u8],
    total_remaining: u64,
    max_result: u64,
) -> Result<crate::git::delta::DeltaApplication> {
    apply_with_budgets(
        base,
        delta_payload,
        &DeltaBudgets { max_result, total_remaining },
    )
}
