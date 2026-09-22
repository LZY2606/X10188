//! Serde-friendly data types shared between the analysis engine and the
//! JSON HTTP API.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolveStatus {
    Resolved,
    Blocked,
    Paused,
    Error,
}

impl ResolveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveStatus::Resolved => "resolved",
            ResolveStatus::Blocked => "blocked",
            ResolveStatus::Paused => "paused",
            ResolveStatus::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Option<ResolveStatus> {
        Some(match s {
            "resolved" => ResolveStatus::Resolved,
            "blocked" => ResolveStatus::Blocked,
            "paused" => ResolveStatus::Paused,
            "error" => ResolveStatus::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub id: i64,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub source_id: Option<i64>,
    pub candidate_id: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    pub offset: i64,
    pub oid: Option<String>,
    pub obj_type: Option<String>,
    pub declared_size: i64,
    pub actual_size: i64,
    pub zlib_ok: bool,
    pub size_ok: bool,
    pub crc_ok: Option<bool>,
    pub hash_ok: Option<bool>,
    pub base_offset: Option<i64>,
    pub ofs_distance: Option<i64>,
    pub ref_base: Option<String>,
    pub base_candidate_id: Option<i64>,
    pub base_candidate_provider: Option<String>,
    pub sort_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolution {
    pub candidate_id: i64,
    pub branch_id: i64,
    pub status: String,
    pub oid: Option<String>,
    pub obj_type: Option<String>,
    pub size: i64,
    pub content_key: Option<String>,
    pub hash_ok: Option<bool>,
    pub reason: Option<String>,
    pub blocked_chain: Vec<String>,
    pub recompute_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaStepOut {
    pub candidate_id: i64,
    pub branch_id: i64,
    pub step_index: i64,
    pub kind: String,
    pub insn_start: i64,
    pub insn_end: i64,
    pub src_start: Option<i64>,
    pub src_len: Option<i64>,
    pub out_start: i64,
    pub out_end: i64,
    pub base_oid: Option<String>,
    pub base_input_len: i64,
    pub result_len: i64,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub sha256: String,
    pub byte_len: i64,
    pub pack_version: Option<i64>,
    pub pack_object_count: Option<i64>,
    pub trailer_ok: Option<bool>,
    pub fanout: Option<Vec<i64>>,
    pub linked_pack_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Branch {
    pub id: i64,
    pub name: String,
    pub pinned: Vec<PinnedCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PinnedCandidate {
    pub oid: String,
    pub candidate_id: i64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DagEdge {
    pub from: i64,
    pub to: i64,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub oid: String,
    pub candidate_ids: Vec<i64>,
    pub chosen: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Budgets {
    pub max_depth: i64,
    pub max_total_expanded: i64,
    pub max_single_ratio: f64,
    pub total_expanded: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct State {
    pub sources: Vec<Source>,
    pub candidates: Vec<Candidate>,
    pub resolutions: Vec<Resolution>,
    pub steps: Vec<DeltaStepOut>,
    pub evidence: Vec<Evidence>,
    pub branches: Vec<Branch>,
    pub active_branch: i64,
    pub edges: Vec<DagEdge>,
    pub conflicts: Vec<Conflict>,
    pub budgets: Budgets,
    pub recompute_events: i64,
}
