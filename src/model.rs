use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            6 => Some(Self::OfsDelta),
            7 => Some(Self::RefDelta),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Commit => 1,
            Self::Tree => 2,
            Self::Blob => 3,
            Self::Tag => 4,
            Self::OfsDelta => 6,
            Self::RefDelta => 7,
        }
    }

    pub fn git_name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            Self::OfsDelta => "ofs_delta",
            Self::RefDelta => "ref_delta",
        }
    }

    pub fn from_git_name(name: &str) -> Option<Self> {
        match name {
            "commit" => Some(Self::Commit),
            "tree" => Some(Self::Tree),
            "blob" => Some(Self::Blob),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, Self::OfsDelta | Self::RefDelta)
    }
}

/// 资源预算：delta 深度 / 总展开字节 / 单对象展开比例
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_total_bytes: 512 * 1024 * 1024,
            max_ratio: 1000.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstrSummary {
    /// 指令在 delta 数据中的字节范围 [start, end)
    pub range: (usize, usize),
    pub kind: String,
    pub src_off: Option<u64>,
    pub len: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaStep {
    pub seq: u32,
    /// 基点描述：ofs 距离或 ref oid
    pub base: String,
    /// delta 数据在源文件中的字节范围
    pub delta_range: (u64, u64),
    pub instructions: Vec<InstrSummary>,
    pub instructions_truncated: bool,
    pub input_len: u64,
    pub output_len: u64,
    /// 该步输出重算 oid 与索引/文件名提示是否一致（无提示为 None）
    pub checksum_ok: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blocker {
    pub candidate_id: Option<i64>,
    pub desc: String,
    pub reason: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Status {
    Resolved,
    Blocked,
    Paused,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Blocked => "blocked",
            Self::Paused => "paused",
            Self::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "resolved" => Some(Self::Resolved),
            "blocked" => Some(Self::Blocked),
            "paused" => Some(Self::Paused),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub status: Status,
    pub oid: Option<String>,
    pub steps: Vec<DeltaStep>,
    pub blockers: Vec<Blocker>,
    pub error: Option<String>,
    pub expanded_bytes: u64,
    /// 依赖的其他候选 id（用于增量失效与删除影响分析）
    pub deps: Vec<i64>,
    /// 链上使用过的 ref-delta base oid（用于新候选出现时的失效判断）
    pub chain_base_oids: Vec<String>,
    pub used_ref: bool,
}

impl Resolution {
    pub fn empty(status: Status) -> Self {
        Self {
            status,
            oid: None,
            steps: Vec::new(),
            blockers: Vec::new(),
            error: None,
            expanded_bytes: 0,
            deps: Vec::new(),
            chain_base_oids: Vec::new(),
            used_ref: false,
        }
    }
}
