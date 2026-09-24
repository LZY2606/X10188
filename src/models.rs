//! 分析引擎使用的内存模型。

use std::collections::HashMap;

use crate::oid::{ObjType, Oid};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Pack,
    Idx,
    Loose,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Pack => "pack",
            SourceKind::Idx => "idx",
            SourceKind::Loose => "loose",
        }
    }
    pub fn parse(s: &str) -> SourceKind {
        match s {
            "idx" => SourceKind::Idx,
            "loose" => SourceKind::Loose,
            _ => SourceKind::Pack,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Source {
    pub id: i64,
    pub kind: SourceKind,
    pub file_name: String,
    pub rel_path: String,
    pub size: u64,
    pub sha256: String,
    pub paired_pack_rel: Option<String>,
    pub pack_sha_match: Option<bool>,
    pub trailer_ok: Option<bool>,
    pub parse_error: Option<String>,
}

/// 一个“对象候选来源”：pack 中的一个条目或一个 loose 文件。
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: i64,
    pub source_id: i64,
    pub kind: CandidateKind,
    pub entry_index: Option<u32>,
    pub pack_offset: Option<u64>,
    pub entry_range: Option<(u64, u64)>,
    pub zlib_range: Option<(u64, u64)>,
    pub claimed_oid: Option<Oid>,
    pub actual_oid: Option<Oid>,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub inflated_len: usize,
    pub ofs_base_offset: Option<u64>,
    pub ref_base_oid: Option<Oid>,
    pub entry_crc32: Option<u32>,
    pub crc_ok: Option<bool>,
    pub payload: Vec<u8>,
    pub parse_error: Option<String>,
    pub parse_ok: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    PackEntry,
    Loose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolveStatus {
    Resolved,
    Blocked,
    Error,
    Paused,
    Cycle,
}

impl ResolveStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolveStatus::Resolved => "resolved",
            ResolveStatus::Blocked => "blocked",
            ResolveStatus::Error => "error",
            ResolveStatus::Paused => "paused",
            ResolveStatus::Cycle => "cycle",
        }
    }
    pub fn parse(s: &str) -> ResolveStatus {
        match s {
            "blocked" => ResolveStatus::Blocked,
            "error" => ResolveStatus::Error,
            "paused" => ResolveStatus::Paused,
            "cycle" => ResolveStatus::Cycle,
            _ => ResolveStatus::Resolved,
        }
    }
}

/// 单步 delta 取证记录。
#[derive(Clone, Debug)]
pub struct Step {
    pub step: usize,
    pub base_candidate_id: Option<i64>,
    pub base_oid: Option<Oid>,
    pub instr_start: u64,
    pub instr_end: u64,
    pub input_len: u64,
    pub output_len: u64,
    pub check_ok: bool,
    pub detail: String,
    pub instructions_json: String,
}

#[derive(Clone, Debug)]
pub struct Resolution {
    pub candidate_id: i64,
    pub status: ResolveStatus,
    pub actual_oid: Option<Oid>,
    pub out_type: Option<ObjType>,
    pub out_len: u64,
    pub chain_len: usize,
    pub error: Option<String>,
    /// 阻塞 / 环上的候选 id 序列（用于“阻塞链”展示）。
    pub blocked_chain: Vec<i64>,
    pub steps: Vec<Step>,
    /// 最终还原内容（resolved 时存在；paused 时为 None——绝不把部分输出当完整对象）。
    pub output: Option<Vec<u8>>,
    pub budget_spent: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub max_depth: u64,
    pub total_budget: u64,
    pub per_object_cap: u64,
    pub per_object_ratio: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            total_budget: 256 * 1024 * 1024,
            per_object_cap: 64 * 1024 * 1024,
            per_object_ratio: 4096,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BranchView {
    pub pins: HashMap<Oid, i64>,
}

#[derive(Clone, Debug)]
pub struct BlockedEvidence {
    pub from_candidate: i64,
    pub kind: &'static str,
    pub detail: String,
}
