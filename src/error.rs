#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    PackBadMagic,
    PackUnsupportedVersion,
    PackTruncated,
    PackEntryTruncated,
    EntryTypeUnknown,
    ZlibError,
    DeltaSizeMismatch,
    DeltaBadInstruction,
    DeltaResultTooLong,
    DeltaCopyOutOfRange,
    InflateTooLarge,
    IdxBadMagic,
    IdxUnsupportedVersion,
    IdxTruncated,
    IdxOffsetOutOfRange,
    IdxPackChecksumMismatch,
    IdxEntryChecksumMismatch,
    LooseBadHeader,
    LooseZlibError,
    OfsDeltaTargetOutOfRange,
    MissingBase,
    DeltaCycle,
    DepthLimit,
    BudgetExhausted,
    ObjectTooLarge,
    BaseBad,
    OidMismatch,
    PinnedMissing,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::PackBadMagic => "pack_bad_magic",
            ErrorCode::PackUnsupportedVersion => "pack_unsupported_version",
            ErrorCode::PackTruncated => "pack_truncated",
            ErrorCode::PackEntryTruncated => "pack_entry_truncated",
            ErrorCode::EntryTypeUnknown => "entry_type_unknown",
            ErrorCode::ZlibError => "zlib_error",
            ErrorCode::DeltaSizeMismatch => "delta_size_mismatch",
            ErrorCode::DeltaBadInstruction => "delta_bad_instruction",
            ErrorCode::DeltaResultTooLong => "delta_result_too_long",
            ErrorCode::DeltaCopyOutOfRange => "delta_copy_out_of_range",
            ErrorCode::InflateTooLarge => "inflate_too_large",
            ErrorCode::IdxBadMagic => "idx_bad_magic",
            ErrorCode::IdxUnsupportedVersion => "idx_unsupported_version",
            ErrorCode::IdxTruncated => "idx_truncated",
            ErrorCode::IdxOffsetOutOfRange => "idx_offset_out_of_range",
            ErrorCode::IdxOffsetOutOfRange => "idx_offset_out_of_range",
            ErrorCode::IdxPackChecksumMismatch => "idx_pack_checksum_mismatch",
            ErrorCode::IdxEntryChecksumMismatch => "idx_entry_checksum_mismatch",
            ErrorCode::LooseBadHeader => "loose_bad_header",
            ErrorCode::LooseZlibError => "loose_zlib_error",
            ErrorCode::OfsDeltaTargetOutOfRange => "ofs_target_out_of_range",
            ErrorCode::MissingBase => "missing_base",
            ErrorCode::DeltaCycle => "delta_cycle",
            ErrorCode::DepthLimit => "depth_limit",
            ErrorCode::BudgetExhausted => "budget_exhausted",
            ErrorCode::ObjectTooLarge => "object_too_large",
            ErrorCode::BaseBad => "base_bad",
            ErrorCode::OidMismatch => "oid_mismatch",
            ErrorCode::PinnedMissing => "pinned_missing",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error { code, message: message.into() }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for Error {}

pub type R<T> = Result<T, Error>;
