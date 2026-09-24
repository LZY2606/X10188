//! Git object types and the common error type used across the parser.

use thiserror::Error;

/// The four canonical object payload types. `OfsDelta`/`RefDelta` are
/// represented separately as pack entry kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ObjectType::Commit),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Blob),
            4 => Some(ObjectType::Tag),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Base(ObjectType),
    OfsDelta,
    RefDelta,
}

/// Reason a single parsed object is unusable. These are *permanent* object
/// faults (the source bytes themselves are bad), as opposed to a missing
/// base which is only a temporary blocker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    Truncated,
    BadHeader(String),
    UnsupportedType(u8),
    ReservedType,
    UnknownType(u8),
    SizeSpoof {
        declared: u64,
        inflated: u64,
    },
    InflateError(String),
    DeltaTooShort,
    DeltaBadSize {
        which: &'static str,
        expected: u64,
        got: u64,
    },
    DeltaBadCopy {
        offset: usize,
        size: usize,
        base_len: usize,
    },
    DeltaInsertsOverrun,
    /// `negative_offset` would point before the start of the pack.
    OfsOutOfBounds {
        negative_offset: u64,
    },
    BadFanout {
        table: u32,
        next: u32,
    },
    BadMagic,
    BadVersion(u32),
    TooManyObjects,
    BadTrailer,
    /// Inflated payload does not hash to the oid claimed for it.
    OidMismatch,
    /// The idx entry points outside the pack or does not line up with an
    /// object header.
    IdxOffsetInvalid(u64),
    PackChecksumMismatch,
    IdxChecksumMismatch,
    LooseBadPath,
}

impl Fault {
    pub fn code(&self) -> &'static str {
        match self {
            Fault::Truncated => "truncated",
            Fault::BadHeader(_) => "bad_header",
            Fault::UnsupportedType(_) => "unsupported_type",
            Fault::ReservedType => "reserved_type",
            Fault::UnknownType(_) => "unknown_type",
            Fault::SizeSpoof { .. } => "size_spoof",
            Fault::InflateError(_) => "inflate_error",
            Fault::DeltaTooShort => "delta_too_short",
            Fault::DeltaBadSize { .. } => "delta_bad_size",
            Fault::DeltaBadCopy { .. } => "delta_bad_copy",
            Fault::DeltaInsertsOverrun => "delta_inserts_overrun",
            Fault::OfsOutOfBounds { .. } => "ofs_out_of_bounds",
            Fault::BadFanout { .. } => "bad_fanout",
            Fault::BadMagic => "bad_magic",
            Fault::BadVersion(_) => "bad_version",
            Fault::TooManyObjects => "too_many_objects",
            Fault::BadTrailer => "bad_trailer",
            Fault::OidMismatch => "oid_mismatch",
            Fault::IdxOffsetInvalid(_) => "idx_offset_invalid",
            Fault::PackChecksumMismatch => "pack_checksum_mismatch",
            Fault::IdxChecksumMismatch => "idx_checksum_mismatch",
            Fault::LooseBadPath => "loose_bad_path",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Fault::Truncated => "source ends before the object is complete".into(),
            Fault::BadHeader(s) => format!("malformed object header: {s}"),
            Fault::UnsupportedType(t) => format!("unsupported object type {t}"),
            Fault::ReservedType => "object type 5 is reserved".into(),
            Fault::UnknownType(t) => format!("unknown object type {t}"),
            Fault::SizeSpoof { declared, inflated } => format!(
                "size欺骗: header declared {declared} bytes but inflate produced {inflated}"
            ),
            Fault::InflateError(s) => format!("zlib stream error: {s}"),
            Fault::DeltaTooShort => "delta data ends inside its size header".into(),
            Fault::DeltaBadSize { which, expected, got } => {
                format!("delta {which} size mismatch: expected {expected}, got {got}")
            }
            Fault::DeltaBadCopy { offset, size, base_len } => format!(
                "delta copy out of range: offset {offset} size {size} base_len {base_len}"
            ),
            Fault::DeltaInsertsOverrun => "delta inserts more bytes than declared".into(),
            Fault::OfsOutOfBounds { negative_offset } => {
                format!("ofs-delta negative offset {negative_offset} runs before pack start")
            }
            Fault::BadFanout { table, next } => {
                format!("fanout not monotonic: table[{table}] = {next}")
            }
            Fault::BadMagic => "bad magic signature".into(),
            Fault::BadVersion(v) => format!("unsupported version {v}"),
            Fault::TooManyObjects => "object count does not fit in 64 bits".into(),
            Fault::BadTrailer => "missing or corrupt trailing checksum".into(),
            Fault::OidMismatch => "recomputed object id does not match claimed oid".into(),
            Fault::IdxOffsetInvalid(off) => format!("idx offset {off} does not point at an object"),
            Fault::PackChecksumMismatch => "pack trailer checksum mismatch".into(),
            Fault::IdxChecksumMismatch => "idx pack checksum mismatch".into(),
            Fault::LooseBadPath => "loose object path is not of the form xx/remaining38".into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(String),
    #[error("{0}")]
    Fault(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
    pub fn fault(f: &Fault) -> Self {
        Error::Fault(f.message())
    }
    pub fn other(s: impl Into<String>) -> Self {
        Error::Other(s.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
