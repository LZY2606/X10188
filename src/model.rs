use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub id: String,
    pub filename: String,
    pub kind: SourceKind,
    pub size: u64,
    pub sha256: String,
    pub imported_at: i64,
    pub parse_status: ParseStatus,
    pub parse_error: Option<String>,
    pub paired_pack_id: Option<String>,
    pub pack_checksum: Option<String>,
    pub pack_checksum_valid: Option<bool>,
    pub index_checksum_valid: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Pack,
    Index,
    Loose,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateRecord {
    pub id: String,
    pub source_id: String,
    pub location: CandidateLocation,
    pub raw_type: String,
    pub claimed_oid: Option<String>,
    pub computed_oid: Option<String>,
    pub ref_base_oid: Option<String>,
    pub ofs_base_offset: Option<u64>,
    pub ofs_base_candidate_id: Option<String>,
    pub header_offset: u64,
    pub data_offset: u64,
    pub compressed_end: Option<u64>,
    pub recovery_offset: Option<u64>,
    pub compressed_len: Option<u64>,
    pub declared_size: u64,
    pub raw_len: usize,
    pub raw_digest: String,
    pub parse_valid: bool,
    pub parse_error: Option<String>,
    pub expected_crc32: Option<u32>,
    pub actual_crc32: Option<u32>,
    pub crc_valid: Option<bool>,
    pub index_fanout_bucket: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateLocation {
    Pack,
    Loose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    pub name: String,
    pub label: String,
    pub pins: std::collections::BTreeMap<String, String>,
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_single_bytes: u64,
    pub used_bytes: u64,
    pub resumed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BranchEvaluation {
    pub branch: String,
    pub objects: Vec<ObjectEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectEvaluation {
    pub candidate_id: String,
    pub status: ResolutionStatus,
    pub object_type: Option<String>,
    pub oid: Option<String>,
    pub claimed_oid: Option<String>,
    pub depth: u32,
    pub output_len: Option<u64>,
    pub content_digest: Option<String>,
    pub preview: Option<String>,
    pub base_chain: Vec<String>,
    pub blocked_chain: Vec<BlockedNode>,
    pub steps: Vec<DeltaStepRecord>,
    pub evidence: Vec<Evidence>,
    pub charged_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Resolved,
    MissingBase,
    Cycle,
    Invalid,
    BudgetPaused,
    ParseError,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedNode {
    pub candidate_id: Option<String>,
    pub oid: Option<String>,
    pub source_id: Option<String>,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStepRecord {
    pub ordinal: u32,
    pub base_candidate_id: String,
    pub base_oid: Option<String>,
    pub delta_candidate_id: String,
    pub delta_kind: String,
    pub instruction_range: (u64, u64),
    pub source_size: usize,
    pub target_size: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub output_id: String,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub offset: Option<u64>,
    pub range: Option<(u64, u64)>,
    pub source_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FanoutView {
    pub source_id: String,
    pub entries: Vec<FanoutBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutBucket {
    pub prefix: u8,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppState {
    pub sources: Vec<SourceRecord>,
    pub candidates: Vec<CandidateRecord>,
    pub branches: Vec<BranchRecord>,
    pub evaluations: Vec<BranchEvaluation>,
    pub fanout: Vec<FanoutView>,
    pub conflicts: Vec<OidConflict>,
    pub deletion_checks: Vec<DeletionCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidConflict {
    pub oid: String,
    pub candidate_ids: Vec<String>,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionCheck {
    pub source_id: String,
    pub filename: String,
    pub blocking_candidate_ids: Vec<String>,
    pub blocking_oids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetConfig {
    pub max_depth: Option<u32>,
    pub max_total_bytes: Option<u64>,
    pub max_single_bytes: Option<u64>,
}
