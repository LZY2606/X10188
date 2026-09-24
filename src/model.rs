//! 共享数据模型。
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub id: i64,
    pub name: String,
    pub kind: String, // "pack" | "idx" | "loose"
    pub sha256: String,
    pub path: String,
    pub size: u64,
    /// pack: 内容 sha1；idx: 其声明的 pack sha1
    pub checksum: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: i64,
    pub source_id: i64,
    pub offset: u64,
    pub type_code: u8,
    pub declared_size: u64,
    pub data_off: u64,
    pub data_len: u64,
    pub base_ofs: Option<u64>,
    pub base_oid: Option<String>,
    pub idx_oid: Option<String>,
    pub crc_expected: Option<u32>,
    pub crc_actual: Option<u32>,
    pub inflated_len: Option<u64>,
    pub parse_error: Option<String>,
}

impl Entry {
    pub fn type_name(&self) -> &'static str {
        crate::gitobj::type_name(self.type_code)
    }
    pub fn is_delta(&self) -> bool {
        crate::gitobj::is_delta(self.type_code)
    }
    pub fn crc_ok(&self) -> Option<bool> {
        match (self.crc_expected, self.crc_actual) {
            (Some(e), Some(a)) => Some(e == a),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Resolved,
    MissingBase,
    Cycle,
    Corrupt,
    Paused,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::MissingBase => "missing_base",
            Status::Cycle => "cycle",
            Status::Corrupt => "corrupt",
            Status::Paused => "paused",
        }
    }
    pub fn from_str(s: &str) -> Status {
        match s {
            "resolved" => Status::Resolved,
            "missing_base" => Status::MissingBase,
            "cycle" => Status::Cycle,
            "corrupt" => Status::Corrupt,
            _ => Status::Paused,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHop {
    pub entry_id: Option<i64>,
    pub desc: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaStep {
    pub entry_id: i64,
    pub source: String,
    pub offset: u64,
    pub base: String,
    pub instrs: Vec<crate::delta::Instr>,
    pub in_len: u64,
    pub out_len: u64,
    pub ok: bool,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub entry_id: i64,
    pub status: Status,
    pub oid: Option<String>,
    pub depth: u32,
    pub steps: Vec<DeltaStep>,
    pub blocking: Vec<BlockHop>,
    pub error: Option<String>,
    #[serde(skip)]
    pub content: Option<Vec<u8>>,
    pub out_len: u64,
    pub deps: Vec<i64>,
}

impl Resolution {
    pub fn new(entry_id: i64, status: Status) -> Self {
        Resolution {
            entry_id,
            status,
            oid: None,
            depth: 0,
            steps: Vec::new(),
            blocking: Vec::new(),
            error: None,
            content: None,
            out_len: 0,
            deps: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pin {
    pub oid: String,
    pub source_id: i64,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_ratio: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 64,
            max_total_bytes: 256 * 1024 * 1024,
            max_ratio: 1000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveReport {
    pub resolved: usize,
    pub missing_base: usize,
    pub cycles: usize,
    pub corrupt: usize,
    pub paused: usize,
    pub consumed_bytes: u64,
    pub budget: Budget,
    /// 本轮实际重新计算的 entry id（局部重算证据）
    pub recomputed: Vec<i64>,
    /// 本轮由未还原变为已还原的 oid
    pub newly_resolved: Vec<String>,
}
