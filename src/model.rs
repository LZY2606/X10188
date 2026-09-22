//! Domain types shared by parsing, resolution and the web layer.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Loose,
    Pack,
    Idx,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Loose => "loose",
            SourceKind::Pack => "pack",
            SourceKind::Idx => "idx",
        }
    }
    pub fn parse(s: &str) -> Option<SourceKind> {
        Some(match s {
            "loose" => SourceKind::Loose,
            "pack" => SourceKind::Pack,
            "idx" => SourceKind::Idx,
            _ => return None,
        })
    }
}

/// Terminal, isolated error class for an entry that cannot be reconstructed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryError {
    /// raw bytes could not be inflated / parsed
    Inflate(String),
    /// object header advertised a size different from what inflated
    SizeSpoof { declared: u64, actual: u64 },
    /// unknown/unsupported object type code
    UnknownType(u8),
    /// ofs-delta negative offset does not point inside the pack
    OfsOutOfBounds { neg: u64, pack_size: u64 },
    /// delta instruction stream malformed
    BadDelta(String),
    /// resolved object id differs from the oid claimed by the source
    OidMismatch { claimed: String, actual: String },
    /// stored pack/idx CRC32 does not match recomputed
    CrcMismatch { expected: u32, actual: u32 },
    /// .idx fanout/ordering/sha invalid
    BadIndex(String),
    /// .idx does not correspond to its paired .pack
    PackIndexMismatch(String),
}

impl EntryError {
    pub fn code(&self) -> &'static str {
        match self {
            EntryError::Inflate(_) => "inflate",
            EntryError::SizeSpoof { .. } => "size_spoof",
            EntryError::UnknownType(_) => "unknown_type",
            EntryError::OfsOutOfBounds { .. } => "ofs_oob",
            EntryError::BadDelta(_) => "bad_delta",
            EntryError::OidMismatch { .. } => "oid_mismatch",
            EntryError::CrcMismatch { .. } => "crc_mismatch",
            EntryError::BadIndex(_) => "bad_index",
            EntryError::PackIndexMismatch(_) => "index_pack_mismatch",
        }
    }
    pub fn detail(&self) -> String {
        match self {
            EntryError::Inflate(m) => m.clone(),
            EntryError::SizeSpoof { declared, actual } => {
                format!("declared {declared}, actual {actual}")
            }
            EntryError::UnknownType(c) => format!("type code {c}"),
            EntryError::OfsOutOfBounds { neg, pack_size } => {
                format!("negative offset {neg} overflows pack size {pack_size}")
            }
            EntryError::BadDelta(m) => m.clone(),
            EntryError::OidMismatch { claimed, actual } => {
                format!("claimed {claimed}, actual {actual}")
            }
            EntryError::CrcMismatch { expected, actual } => {
                format!("idx {expected:#010x}, computed {actual:#010x}")
            }
            EntryError::BadIndex(m) => m.clone(),
            EntryError::PackIndexMismatch(m) => m.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolveError {
    /// dependency oid cannot be satisfied by any imported source
    MissingBase(String),
    /// ofs base offset points outside the pack
    OfsMissing(u64),
    /// a base entry itself failed; carries its error code
    BaseError(String),
    /// a delta cycle; chain lists the entries participating
    Cycle(Vec<i64>),
    /// terminal error on the entry itself
    Entry(EntryError),
}

impl ResolveError {
    pub fn code(&self) -> String {
        match self {
            ResolveError::MissingBase(_) => "missing_base".into(),
            ResolveError::OfsMissing(_) => "ofs_missing".into(),
            ResolveError::BaseError(c) => format!("base_{c}"),
            ResolveError::Cycle(_) => "cycle".into(),
            ResolveError::Entry(e) => e.code().into(),
        }
    }
}

/// Resource budget. Reaching any limit yields a retryable pause.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budget {
    /// maximum delta chain depth (number of delta applications)
    pub max_depth: u32,
    /// cumulative bytes produced while resolving one dependency graph pass
    pub total_bytes: u64,
    /// maximum reconstructed size of a single object
    pub per_object_bytes: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 16,
            total_bytes: 64 * 1024 * 1024,
            per_object_bytes: 16 * 1024 * 1024,
        }
    }
}

/// One edge in the delta DAG.
#[derive(Clone, Debug)]
pub struct Edge {
    pub child_entry: i64,
    /// base by entry id (ofs-delta, or resolved ref-delta)
    pub base_entry: Option<i64>,
    /// base by oid (ref-delta before resolution)
    pub base_oid: Option<String>,
}

/// One delta application, persisted as evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepRec {
    pub seq: u32,
    pub kind: String, // "ofs-delta" | "ref-delta"
    pub base_entry: Option<i64>,
    pub base_oid: Option<String>,
    /// byte range of the *instruction stream* inside the inflated delta
    pub instr_start: usize,
    pub instr_end: usize,
    pub in_len: usize,
    pub out_len: usize,
    pub declared_result: u64,
    pub check: String, // "ok" | error message
    pub instrs_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blocker {
    pub entry: i64,
    pub code: String,
    pub detail: String,
}

/// Result of evaluating one entry during a graph pass.
#[derive(Clone, Debug)]
pub enum EvalOutcome {
    Ok {
        kind: String,
        content: Vec<u8>,
        actual_oid: String,
        oid_ok: bool,
        depth: u32,
        bytes: u64,
        steps: Vec<StepRec>,
    },
    Paused {
        reason: String,
        partial_depth: u32,
    },
    Error(ResolveError),
}

/// Raw pack layout entry for the layout view.
#[derive(Clone, Debug, Serialize)]
pub struct LayoutEntry {
    pub offset: u64,
    pub kind: String,
    pub declared_size: u64,
    pub z_off: u64,
    pub z_len: u64,
    pub entry_id: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub entry_id: i64,
    pub source_id: i64,
    pub source_name: String,
    pub source_kind: String,
    pub offset: Option<i64>,
    pub resolved: bool,
    pub actual_oid: Option<String>,
    pub oid_ok: bool,
    pub status: String,
    pub rank: i64,
    pub pinned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceInfo {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub size: i64,
    pub sha256: String,
    pub pack_sha: Option<String>,
    pub entries: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DependencyInfo {
    pub entry_id: i64,
    pub source_id: i64,
    pub source_name: String,
    pub offset: Option<i64>,
    pub kind: Option<String>,
    pub status: String,
}
