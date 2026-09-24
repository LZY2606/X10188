use serde::{Deserialize, Serialize};

pub mod status {
    pub const RESOLVED: &str = "resolved";
    pub const MISSING_BASE: &str = "missing_base";
    pub const CYCLE: &str = "cycle";
    pub const BAD: &str = "bad";
    pub const PAUSED: &str = "paused";
    pub const LEAF: &str = "leaf";
}

pub mod kind {
    pub const PACK: &str = "pack";
    pub const IDX: &str = "idx";
    pub const LOOSE: &str = "loose";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepJson {
    pub step: usize,
    pub candidate_id: i64,
    pub kind: String,
    pub base_candidate_id: Option<i64>,
    pub delta_header_len: usize,
    pub ops_count: usize,
    pub ops_range_start: usize,
    pub ops_range_end: usize,
    pub input_len: u64,
    pub output_len: u64,
    pub compressed_len: usize,
    pub check: String,
    pub check_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Blocker {
    pub code: String,
    pub message: String,
    pub candidate_id: Option<i64>,
    pub chain: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub pair_source_id: Option<i64>,
    pub pairing_note: String,
    pub parse_status: String,
    pub parse_detail: String,
    pub pack_checksum_hex: Option<String>,
    pub imported_at: String,
}

#[derive(Debug, Clone)]
pub struct CandidateRow {
    pub id: i64,
    pub source_id: i64,
    pub pack_offset: Option<i64>,
    pub declared_oid_hex: Option<String>,
    pub computed_oid_hex: Option<String>,
    pub obj_type: String,
    pub claimed_size: i64,
    pub inflated_size: i64,
    pub compressed_len: i64,
    pub header_len: i64,
    pub entry_crc32: Option<i64>,
    pub idx_crc32: Option<i64>,
    pub crc_ok: Option<bool>,
    pub ofs_base_offset: Option<i64>,
    pub ref_base_oid_hex: Option<String>,
    pub parse_status: String,
    pub parse_detail: String,
    pub pinned: bool,
    pub path: Option<String>,
}

impl CandidateRow {
    /// Effective identity: index-declared/loose filename oid, or computed.
    pub fn effective_oid(&self) -> Option<&str> {
        self.declared_oid_hex
            .as_deref()
            .or(self.computed_oid_hex.as_deref())
    }
}

#[derive(Debug, Clone)]
pub struct ResolutionRow {
    pub candidate_id: i64,
    pub status: String,
    pub resolved_type: Option<String>,
    pub content_len: i64,
    pub content_path: Option<String>,
    pub oid_hex: Option<String>,
    pub oid_match: Option<bool>,
    pub depth: i64,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub blockers_json: String,
    pub steps_json: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_single_ratio: u64,
    pub max_result_bytes: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_depth: 50,
            max_total_bytes: 256 * 1024 * 1024,
            max_single_ratio: 4096,
            max_result_bytes: 128 * 1024 * 1024,
        }
    }
}
