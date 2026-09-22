use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        Some(match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn parse(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            "ofs-delta" => ObjType::OfsDelta,
            "ref-delta" => ObjType::RefDelta,
            _ => return None,
        })
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn base_type(self) -> Option<ObjType> {
        match self {
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => Some(self),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjStatus {
    Pending,
    Resolved,
    Blocked,
    Error,
    Paused,
}

impl ObjStatus {
    pub fn name(self) -> &'static str {
        match self {
            ObjStatus::Pending => "pending",
            ObjStatus::Resolved => "resolved",
            ObjStatus::Blocked => "blocked",
            ObjStatus::Error => "error",
            ObjStatus::Paused => "paused",
        }
    }
    pub fn parse(s: &str) -> ObjStatus {
        match s {
            "resolved" => ObjStatus::Resolved,
            "blocked" => ObjStatus::Blocked,
            "error" => ObjStatus::Error,
            "paused" => ObjStatus::Paused,
            _ => ObjStatus::Pending,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrCode {
    BadHeader,
    CorruptZlib,
    SizeSpoof,
    BadOffset,
    MissingBase,
    DeltaCycle,
    BadDelta,
    BadCrc,
    OidMismatch,
    DepthLimit,
    TotalBudget,
    SingleBudget,
    IdxMismatch,
}

impl ErrCode {
    pub fn name(self) -> &'static str {
        match self {
            ErrCode::BadHeader => "bad_header",
            ErrCode::CorruptZlib => "corrupt_zlib",
            ErrCode::SizeSpoof => "size_spoof",
            ErrCode::BadOffset => "bad_offset",
            ErrCode::MissingBase => "missing_base",
            ErrCode::DeltaCycle => "delta_cycle",
            ErrCode::BadDelta => "bad_delta",
            ErrCode::BadCrc => "bad_crc",
            ErrCode::OidMismatch => "oid_mismatch",
            ErrCode::DepthLimit => "depth_limit",
            ErrCode::TotalBudget => "total_budget",
            ErrCode::SingleBudget => "single_budget",
            ErrCode::IdxMismatch => "idx_mismatch",
        }
    }
    pub fn parse(s: &str) -> Option<ErrCode> {
        Some(match s {
            "bad_header" => ErrCode::BadHeader,
            "corrupt_zlib" => ErrCode::CorruptZlib,
            "size_spoof" => ErrCode::SizeSpoof,
            "bad_offset" => ErrCode::BadOffset,
            "missing_base" => ErrCode::MissingBase,
            "delta_cycle" => ErrCode::DeltaCycle,
            "bad_delta" => ErrCode::BadDelta,
            "bad_crc" => ErrCode::BadCrc,
            "oid_mismatch" => ErrCode::OidMismatch,
            "depth_limit" => ErrCode::DepthLimit,
            "total_budget" => ErrCode::TotalBudget,
            "single_budget" => ErrCode::SingleBudget,
            "idx_mismatch" => ErrCode::IdxMismatch,
            _ => return None,
        })
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            ErrCode::DepthLimit | ErrCode::TotalBudget | ErrCode::SingleBudget
        )
    }
}

#[derive(Clone, Debug)]
pub struct ParsedEntry {
    pub offset: u64,
    pub zlib_start: usize,
    pub entry_end: usize,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub payload: Vec<u8>,
    pub parse_error: Option<ErrCode>,
    pub parse_note: Option<String>,
}
