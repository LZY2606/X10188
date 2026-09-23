#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl PackKind {
    pub fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            1 => PackKind::Commit,
            2 => PackKind::Tree,
            3 => PackKind::Blob,
            4 => PackKind::Tag,
            6 => PackKind::OfsDelta,
            7 => PackKind::RefDelta,
            _ => return None,
        })
    }
    pub fn is_delta(self) -> bool {
        matches!(self, PackKind::OfsDelta | PackKind::RefDelta)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "commit" => GitType::Commit,
            "tree" => GitType::Tree,
            "blob" => GitType::Blob,
            "tag" => GitType::Tag,
            _ => return None,
        })
    }
    pub fn from_pack(k: PackKind) -> Option<Self> {
        Some(match k {
            PackKind::Commit => GitType::Commit,
            PackKind::Tree => GitType::Tree,
            PackKind::Blob => GitType::Blob,
            PackKind::Tag => GitType::Tag,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub code: String,
    pub message: String,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl Evidence {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Evidence { code: code.into(), message: message.into(), start: None, end: None }
    }
    pub fn range(mut self, start: u64, end: u64) -> Self {
        self.start = Some(start);
        self.end = Some(end);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateStatus {
    Ok,
    Truncated,
    SizeSpoof,
    ZlibError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BadOpcode(u8),
    BaseSizeMismatch { declared: u64, actual: usize },
    ResultSizeMismatch { declared: u64, actual: usize },
    CopyOutOfRange { offset: u64, size: u64, base_len: usize },
    InsertTooLong { at: usize, declared: u64 },
}

impl DeltaError {
    pub fn code(&self) -> &'static str {
        match self {
            DeltaError::Truncated => "delta_truncated",
            DeltaError::BadOpcode(_) => "delta_bad_opcode",
            DeltaError::BaseSizeMismatch { .. } => "delta_base_size_mismatch",
            DeltaError::ResultSizeMismatch { .. } => "delta_result_size_mismatch",
            DeltaError::CopyOutOfRange { .. } => "delta_copy_out_of_range",
            DeltaError::InsertTooLong { .. } => "delta_insert_too_long",
        }
    }
}
