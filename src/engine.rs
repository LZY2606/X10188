//! Analysis engine: ingestion, delta-DAG resolution, budgets, isolation
//! of corrupt objects, blocking chains, pins and incremental recompute.

use crate::db;
use crate::model::error_code;
use crate::model::{CandidateStatus, ObjType, Oid};
use crate::parse::delta::{self, DeltaOp};
use crate::parse::git_object::RawObject;
use crate::parse::index::{ParsedIndex, ParsedIndex};
use crate::parse::loose::ParsedLoose;
use crate::parse::pack::{EntryKind, ParsedPack, ParseIssue, PackEntry, DEFAULT_OBJECT_CAP};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_MAX_DEPTH: u32 = 50;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SINGLE_RATIO_NUM: u64 = 1;
const DEFAULT_SINGLE_RATIO_DEN: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    /// Single object may consume at most num/den of the total budget.
    pub single_ratio_num: u64,
    pub single_ratio_den: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            single_ratio_num: DEFAULT_SINGLE_RATIO_NUM,
            single_ratio_den: DEFAULT_SINGLE_RATIO_DEN,
        }
    }
}

impl Budget {
    pub fn single_cap(&self) -> u64 {
        self.max_total_bytes
            .saturating_mul(self.single_ratio_num)
            / self.single_ratio_den.max(1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunStats {
    pub expanded_bytes: u64,
    pub resolved: usize,
    pub paused: bool,
    pub pause_code: Option<String>,
    pub pause_candidate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParseSummary {
    pub kind: String,
    pub ok: bool,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CandidateRow {
    pub id: String,
    pub source_id: String,
    pub entry_kind: String,
    pub raw_type_code: Option<u8>,
    pub obj_type: Option<String>,
    pub header_offset: Option<i64>,
    pub header_len: Option<i64>,
    pub data_offset: Option<i64>,
    pub zlib_end: Option<i64>,
    pub declared_size: Option<i64>,
    pub expected_oid: Option<String>,
    pub actual_oid: Option<String>,
    pub status: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub evidence_hex: Option<String>,
    pub blocking_chain: Option<String>,
    pub content_len: Option<i64>,
    pub is_text: bool,
    pub inflated_len: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub child_id: String,
    pub parent_id: Option<String>,
    pub base_ref: Option<String>,
    pub base_source_offset: Option<i64>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct Engine {
    pub data_dir: std::path::PathBuf,
    pub objects_dir: std::path::PathBuf,
    pub conn: Connection,
}

impl Engine {
    pub fn open(data_dir: std::path::PathBuf) -> rusqlite::Result<Engine> {
        std::fs::create_dir_all(&data_dir).ok();
        let objects_dir = data_dir.join("objects");
        std::fs::create_dir_all(&objects_dir).ok();
        let conn = db::open(&data_dir.join("microscope.db"))?;
        Ok(Engine { data_dir, objects_dir, conn })
    }

    pub fn budget(&self) -> rusqlite::Result<Budget> {
        let raw: Option<String> = self
            .conn
            .query_row("SELECT value FROM state WHERE key='budget'", [], |r| r.get(0))
            .optional()?;
        Ok(match raw {
            Some(s) => serde_json::from_str(&s).unwrap_or_default(),
            None => Budget::default(),
        })
    }

    pub fn set_budget(&mut self, budget: Budget) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO state(key, value) VALUES('budget', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [serde_json::to_string(&budget).unwrap()],
        )?;
        Ok(())
    }

    fn stats(&self) -> rusqlite::Result<RunStats> {
        let raw: Option<String> = self
            .conn
            .query_row("SELECT value FROM state WHERE key='run_stats'", [], |r| r.get(0))
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
    }

    fn save_stats(&mut self, stats: &RunStats) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO state(key, value) VALUES('run_stats', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [serde_json::to_string(stats).unwrap()],
        )?;
        Ok(())
    }

    fn event(&mut self, kind: &str, detail: serde_json::Value) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO events(at, kind, detail) VALUES(?1, ?2, ?3)",
            rusqlite::params![now_ms(), kind, detail.to_string()],
        )?;
        Ok(())
    }

    fn object_path(&self, cid: &str) -> std::path::PathBuf {
        self.objects_dir.join(cid)
    }

    fn store_object(&self, cid: &str, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.object_path(cid), data)
    }

    pub fn read_object(&self, cid: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.object_path(cid))
    }

    fn remove_object(&self, cid: &str) {
        std::fs::remove_file(self.object_path(cid)).ok();
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn looks_like_pack(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"PACK"
}

pub fn looks_like_idx(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == [0xff, b't', b'O', b'c']
}

pub fn detect_kind(data: &[u8], filename: &str) -> &'static str {
    if looks_like_pack(data) {
        "pack"
    } else if looks_like_idx(data) {
        "index"
    } else if filename.contains("/objects/") || filename.contains('\\') {
        "loose"
    } else {
        // Try zlib + loose header as a last resort.
        match crate::parse::zlib::inflate(data, 64 * 1024 * 1024) {
            Ok(g) => {
                if crate::parse::git_object::parse_loose_body(&g.data).is_ok() {
                    "loose"
                } else {
                    "unknown"
                }
            }
            Err(_) => "unknown",
        }
    }
}

fn preview_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(2048)];
    std::str::from_utf8(head)
        .map(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t'))
        .unwrap_or(false)
}

fn candidate_id(source_id: &str, key: &str) -> String {
    format!("c_{}", &sha256_hex(format!("{source_id}:{key}").as_bytes())[..32])
}
