use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjType {
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }
    pub fn parse(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Declared {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl Declared {
    pub fn from_pack_byte(t: u8) -> Option<Declared> {
        Some(match t {
            1 => Declared::Commit,
            2 => Declared::Tree,
            3 => Declared::Blob,
            4 => Declared::Tag,
            6 => Declared::OfsDelta,
            7 => Declared::RefDelta,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Declared::Commit => "commit",
            Declared::Tree => "tree",
            Declared::Blob => "blob",
            Declared::Tag => "tag",
            Declared::OfsDelta => "ofs_delta",
            Declared::RefDelta => "ref_delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, Declared::OfsDelta | Declared::RefDelta)
    }
    pub fn full_type(self) -> Option<ObjType> {
        match self {
            Declared::Commit => Some(ObjType::Commit),
            Declared::Tree => Some(ObjType::Tree),
            Declared::Blob => Some(ObjType::Blob),
            Declared::Tag => Some(ObjType::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: i64,
    pub source_id: i64,
    pub origin: String,
    pub pack_offset: Option<i64>,
    pub declared_type: String,
    pub declared_size: i64,
    pub inflated_size: i64,
    pub hdr_start: i64,
    pub hdr_end: i64,
    pub zdata_start: i64,
    pub zdata_end: i64,
    pub base_ofs: Option<i64>,
    pub base_oid: Option<String>,
    pub idx_oid: Option<String>,
    pub idx_crc: Option<i64>,
    pub crc_ok: Option<bool>,
    pub oid: Option<String>,
    pub parse_status: String,
    pub parse_error: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResState {
    pub candidate_id: i64,
    pub status: String,
    pub object_type: Option<String>,
    pub oid: Option<String>,
    pub out_size: i64,
    pub oid_match: Option<bool>,
    pub reason: Option<String>,
    pub blocking_chain: Vec<i64>,
    pub budget: Option<String>,
    pub gen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStep {
    pub candidate_id: i64,
    pub step_idx: i64,
    pub base_candidate_id: Option<i64>,
    pub base_kind: String,
    pub instr_start: i64,
    pub instr_end: i64,
    pub in_len: i64,
    pub out_len: i64,
    pub declared_target_size: i64,
    pub size_match: bool,
    pub ok: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from_cid: i64,
    pub to_cid: Option<i64>,
    pub to_oid: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: i64,
    pub filename: String,
    pub kind: String,
    pub sha256: String,
    pub size: i64,
    pub imported_at: i64,
    pub pack_checksum: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackInfo {
    pub source_id: i64,
    pub version: i64,
    pub count: i64,
    pub checksum: String,
    pub trailer_ok: bool,
    pub idx_source_id: Option<i64>,
    pub idx_pack_checksum: Option<String>,
    pub paired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    pub branch_id: i64,
    pub oid: String,
    pub candidate_id: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: u32,
    pub max_object_bytes: u64,
    pub max_ratio: u64,
    pub total_expand_bytes: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_depth: 50,
            max_object_bytes: 64 * 1024 * 1024,
            max_ratio: 64,
            total_expand_bytes: 256 * 1024 * 1024,
        }
    }
}
