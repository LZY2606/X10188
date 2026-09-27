//! 引擎层对外的数据类型（序列化给 Web UI 与测试）。

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ObjectView {
    pub id: i64,
    pub source_id: i64,
    pub source_filename: String,
    pub source_kind: String,
    pub offset: i64,
    pub kind: String,
    pub declared_size: i64,
    pub claimed_oid: Option<String>,
    pub zlib_start: Option<i64>,
    pub zlib_end: Option<i64>,
    pub parse_errors: Vec<String>,
    pub edges: Vec<EdgeView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EdgeView {
    pub ref_type: String,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedView {
    pub object_id: i64,
    pub status: String,
    pub final_kind: Option<String>,
    pub final_oid: Option<String>,
    pub depth: Option<i64>,
    pub error: Option<String>,
    pub blockers: Vec<BlockerView>,
    pub content_preview: Option<String>,
    pub content_len: Option<i64>,
    pub checksum_note: Option<String>,
    pub candidates: Vec<CandidateView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockerView {
    pub oid: Option<String>,
    pub object_id: Option<i64>,
    pub reason: String,
    pub via: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateView {
    pub object_id: i64,
    pub source: String,
    pub offset: i64,
    pub claimed_oid: Option<String>,
    pub final_oid: Option<String>,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepView {
    pub step_no: i64,
    pub object_id: i64,
    pub base_object_id: Option<i64>,
    pub base_oid: Option<String>,
    pub instr_start: Option<i64>,
    pub instr_end: Option<i64>,
    pub input_len: i64,
    pub output_len: i64,
    pub check: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunView {
    pub id: i64,
    pub outcome: String,
    pub bytes_used: i64,
    pub max_total_bytes: i64,
    pub max_object_bytes: i64,
    pub max_depth: i64,
    pub retriable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceView {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub size: i64,
    pub sha256: String,
}
