//! Shared domain types: object ids, git types, statuses and error codes.

use serde::{Deserialize, Serialize};

/// 20-byte SHA-1 git object id, hex-encoded as 40 lowercase chars.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Oid(pub String);

impl Oid {
    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        Some(Oid(hex::encode(b)))
    }
    pub fn to_bytes(&self) -> Option<[u8; 20]> {
        let mut out = [0u8; 20];
        hex::decode_to_slice(&self.0, &mut out).ok()?;
        Some(out)
    }
    pub fn valid(&self) -> bool {
        self.0.len() == 40 && self.0.bytes().all(|b| b.is_ascii_hexdigit())
    }
    pub fn short(&self) -> String {
        self.0.chars().take(10).collect()
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Git object types (the three delta codes 6/7 are not represented here).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        Some(match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
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

/// Lifecycle status of a candidate (one concrete object occurrence).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Seen in a source but not yet processed.
    Pending,
    /// Fully reconstructed and content hash verified.
    Resolved,
    /// Needs a base that no source currently provides (retryable).
    MissingBase,
    /// Transitive dependency chain too deep (retryable).
    DepthLimit,
    /// Budget exhausted mid-run (retryable on resume).
    BudgetPaused,
    /// Part of a delta cycle.
    Cycle,
    /// Hard corruption: bad stream, bad crc, hash mismatch, ...
    Corrupt,
}

impl CandidateStatus {
    pub fn code(&self) -> &'static str {
        match self {
            CandidateStatus::Pending => "pending",
            CandidateStatus::Resolved => "resolved",
            CandidateStatus::MissingBase => "missing_base",
            CandidateStatus::DepthLimit => "depth_limit",
            CandidateStatus::BudgetPaused => "budget_paused",
            CandidateStatus::Cycle => "cycle",
            CandidateStatus::Corrupt => "corrupt",
        }
    }
    pub fn parse(s: &str) -> CandidateStatus {
        match s {
            "resolved" => CandidateStatus::Resolved,
            "missing_base" => CandidateStatus::MissingBase,
            "depth_limit" => CandidateStatus::DepthLimit,
            "budget_paused" => CandidateStatus::BudgetPaused,
            "cycle" => CandidateStatus::Cycle,
            "corrupt" => CandidateStatus::Corrupt,
            _ => CandidateStatus::Pending,
        }
    }
    pub fn terminal(self) -> bool {
        matches!(self, CandidateStatus::Resolved | CandidateStatus::Corrupt)
    }
    pub fn retryable(self) -> bool {
        matches!(
            self,
            CandidateStatus::Pending
                | CandidateStatus::MissingBase
                | CandidateStatus::DepthLimit
                | CandidateStatus::BudgetPaused
                | CandidateStatus::Cycle
        )
    }
}

/// Stable, machine-readable failure codes shown as forensic evidence.
pub mod error_code {
    pub const BAD_PACK_SIG: &str = "bad_pack_sig";
    pub const BAD_PACK_VERSION: &str = "bad_pack_version";
    pub const TRUNCATED: &str = "truncated";
    pub const BAD_TYPE: &str = "bad_type";
    pub const BAD_VARINT: &str = "bad_varint";
    pub const ZLIB_ERROR: &str = "zlib_error";
    pub const ZLIB_TRAILING: &str = "zlib_trailing";
    pub const SIZE_MISMATCH: &str = "inflated_size_mismatch";
    pub const SIZE_OVERFLOW: &str = "inflated_size_overflow";
    pub const OFS_OUT_OF_RANGE: &str = "ofs_delta_out_of_range";
    pub const IDX_SIG: &str = "bad_idx_sig";
    pub const IDX_VERSION: &str = "bad_idx_version";
    pub const IDX_CRC: &str = "index_crc_mismatch";
    pub const IDX_PACK_CHECKSUM: &str = "index_pack_checksum_mismatch";
    pub const IDX_SELF_CHECKSUM: &str = "index_self_checksum_mismatch";
    pub const IDX_COUNT_MISMATCH: &str = "index_count_mismatch";
    pub const IDX_OFFSET_UNKNOWN: &str = "index_offset_unknown";
    pub const PACK_CRC: &str = "pack_crc_mismatch";
    pub const PACK_CHECKSUM: &str = "pack_trailer_checksum_mismatch";
    pub const DELTA_TRUNCATED: &str = "delta_truncated";
    pub const DELTA_BASE_SIZE: &str = "delta_base_size_mismatch";
    pub const DELTA_BAD_OP: &str = "delta_bad_opcode";
    pub const DELTA_COPY_RANGE: &str = "delta_copy_range";
    pub const DELTA_INSERT_RANGE: &str = "delta_insert_range";
    pub const DELTA_RESULT_SIZE: &str = "delta_result_size_mismatch";
    pub const DELTA_CYCLE: &str = "delta_cycle";
    pub const DEPTH_LIMIT: &str = "depth_limit";
    pub const BUDGET_EXHAUSTED: &str = "budget_exhausted";
    pub const BUDGET_SINGLE: &str = "single_object_budget";
    pub const HASH_MISMATCH: &str = "oid_hash_mismatch";
    pub const LOOSE_BAD_OID: &str = "loose_oid_path_invalid";
    pub const LOOSE_ZLIB: &str = "loose_zlib_error";
    pub const LOOSE_HEADER: &str = "loose_header_malformed";
    pub const UNKNOWN_REF: &str = "unknown_ref_base";
}
