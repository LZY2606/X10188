//! Shared domain model: object kinds, hashing, error evidence.

use crate::oid::Oid;
use sha1::{Digest, Sha1};

/// Canonical Git object type, after delta resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

    pub fn from_name(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }
}

/// Raw entry type recorded in a pack stream (deltas included).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RawType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl RawType {
    pub fn from_pack_code(c: u8) -> Option<RawType> {
        Some(match c {
            1 => RawType::Commit,
            2 => RawType::Tree,
            3 => RawType::Blob,
            4 => RawType::Tag,
            6 => RawType::OfsDelta,
            7 => RawType::RefDelta,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        match self {
            RawType::Commit => 1,
            RawType::Tree => 2,
            RawType::Blob => 3,
            RawType::Tag => 4,
            RawType::OfsDelta => 6,
            RawType::RefDelta => 7,
        }
    }

    pub fn canonical(self) -> Option<ObjType> {
        match self {
            RawType::Commit => Some(ObjType::Commit),
            RawType::Tree => Some(ObjType::Tree),
            RawType::Blob => Some(ObjType::Blob),
            Tag => Some(ObjType::Tag),
            _ => None,
        }
    }
}


/// Compute the Git object id for `type` + `content`:
/// `SHA1("<type> <len>\0<content>")`.
pub fn git_object_id(kind: ObjType, content: &[u8]) -> Oid {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    Oid(out)
}

/// A stable machine-readable failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrCode {
    /// pack header signature/version invalid
    PackBadHeader,
    /// pack truncated mid stream (header, entry, trailer)
    PackTruncated,
    /// unknown object type code in entry header
    PackBadType,
    /// declared object size does not match inflated payload
    SizeMismatch,
    /// inflated payload exceeds the declared size (deferred size spoof)
    SizeSpoof,
    /// zlib stream corrupt or truncated
    ZlibError,
    /// pack SHA-1 trailer mismatch
    PackChecksumMismatch,
    /// ofs-delta negative distance points before pack start
    OfsOutOfRange,
    /// ofs-delta points to an offset without an entry header
    OfsNoEntry,
    /// ref-delta base oid has no candidate source anywhere
    MissingBase,
    /// delta instructions reference data outside base/result
    DeltaOutOfBounds,
    /// delta declared sizes disagree with base/result length
    DeltaSizeMismatch,
    /// delta instruction stream malformed / truncated
    DeltaMalformed,
    /// delta chain forms a cycle
    DeltaCycle,
    /// recomputed object id does not match the claimed/indexed oid
    OidMismatch,
    /// index magic/version unsupported
    IdxBadHeader,
    /// index fanout table inconsistent
    IdxFanoutBroken,
    /// index SHA-1 (pack checksum) disagrees with the paired pack
    IdxPackMismatch,
    /// index trailing checksum mismatch
    IdxChecksumMismatch,
    /// loose object zlib/header failure
    LooseCorrupt,
    /// loose object path is not 38 hex chars under a 2-hex dir
    LooseBadPath,
    /// file is neither pack, idx nor loose object
    UnknownFormat,
    /// max delta depth budget exceeded (retryable)
    PausedDepth,
    /// total expanded-byte budget exhausted (retryable)
    PausedBytes,
    /// single object expansion ratio budget exceeded (retryable)
    PausedRatio,
}

impl ErrCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrCode::PackBadHeader => "pack_bad_header",
            ErrCode::PackTruncated => "pack_truncated",
            ErrCode::PackBadType => "pack_bad_type",
            ErrCode::SizeMismatch => "size_mismatch",
            ErrCode::SizeSpoof => "size_spoof",
            ErrCode::ZlibError => "zlib_error",
            ErrCode::PackChecksumMismatch => "pack_checksum_mismatch",
            ErrCode::OfsOutOfRange => "ofs_out_of_range",
            ErrCode::OfsNoEntry => "ofs_no_entry",
            ErrCode::MissingBase => "missing_base",
            ErrCode::DeltaOutOfBounds => "delta_out_of_bounds",
            ErrCode::DeltaSizeMismatch => "delta_size_mismatch",
            ErrCode::DeltaMalformed => "delta_malformed",
            ErrCode::DeltaCycle => "delta_cycle",
            ErrCode::OidMismatch => "oid_mismatch",
            ErrCode::IdxBadHeader => "idx_bad_header",
            ErrCode::IdxFanoutBroken => "idx_fanout_broken",
            ErrCode::IdxPackMismatch => "idx_pack_mismatch",
            ErrCode::IdxChecksumMismatch => "idx_checksum_mismatch",
            ErrCode::LooseCorrupt => "loose_corrupt",
            ErrCode::LooseBadPath => "loose_bad_path",
            ErrCode::UnknownFormat => "unknown_format",
            ErrCode::PausedDepth => "paused_depth",
            ErrCode::PausedBytes => "paused_bytes",
            ErrCode::PausedRatio => "paused_ratio",
        }
    }

    /// Pause codes are *retryable*: partial state exists, no object is emitted.
    pub fn is_pause(self) -> bool {
        matches!(
            self,
            ErrCode::PausedDepth | ErrCode::PausedBytes | ErrCode::PausedRatio
        )
    }
}

/// Forensic evidence attached to a parse/resolution failure.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub code: ErrCode,
    /// Human-readable explanation (Chinese, UI friendly).
    pub detail: String,
    /// Byte offset in the originating file where the problem was observed.
    pub offset: Option<u64>,
    /// Optional secondary context (e.g. target offset of a bad ofs-delta).
    pub at: Option<u64>,
}

impl Evidence {
    pub fn new(code: ErrCode, detail: impl Into<String>) -> Self {
        Evidence {
            code,
            detail: detail.into(),
            offset: None,
            at: None,
        }
    }

    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn and_at(mut self, target: u64) -> Self {
        self.at = Some(target);
        self
    }
}
