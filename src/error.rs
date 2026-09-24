#[derive(Debug)]
pub enum Error {
    Io(String),
    Db(String),
    BadPack(String),
    BadIndex(String),
    BadLoose(String),
    BadDelta(String),
    SizeMismatch { declared: u64, actual: u64 },
    OfsOutOfRange { at: u64, negative_offset: u64 },
    DeltaCycle(Vec<String>),
    MissingBase(String),
    CrcMismatch { at: u64, expected: u32, actual: u32 },
    ChecksumMismatch(String),
    Unsupported(String),
    NotFound(String),
    Conflict(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(s) => write!(f, "io error: {s}"),
            Error::Db(s) => write!(f, "database error: {s}"),
            Error::BadPack(s) => write!(f, "bad pack: {s}"),
            Error::BadIndex(s) => write!(f, "bad index: {s}"),
            Error::BadLoose(s) => write!(f, "bad loose object: {s}"),
            Error::BadDelta(s) => write!(f, "bad delta: {s}"),
            Error::SizeMismatch { declared, actual } => write!(
                f,
                "declared size {declared} does not match actual inflated size {actual} (size spoof)"
            ),
            Error::OfsOutOfRange { at, negative_offset } => write!(
                f,
                "ofs-delta at {at} points {negative_offset} bytes backwards, before the pack start"
            ),
            Error::DeltaCycle(chain) => {
                write!(f, "delta cycle detected: {}", chain.join(" -> "))
            }
            Error::MissingBase(id) => write!(f, "missing external base {id}"),
            Error::CrcMismatch { at, expected, actual } => write!(
                f,
                "crc32 mismatch at offset {at}: index says {expected:08x}, data computes {actual:08x}"
            ),
            Error::ChecksumMismatch(s) => write!(f, "checksum mismatch: {s}"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::NotFound(s) => write!(f, "not found: {s}"),
            Error::Conflict(s) => write!(f, "conflict: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Stable machine-readable code used in persisted error evidence.
pub fn code_of(e: &Error) -> &'static str {
    match e {
        Error::Io(_) => "io",
        Error::Db(_) => "db",
        Error::BadPack(_) => "bad_pack",
        Error::BadIndex(_) => "bad_index",
        Error::BadLoose(_) => "bad_loose",
        Error::BadDelta(_) => "bad_delta",
        Error::SizeMismatch { .. } => "size_spoof",
        Error::OfsOutOfRange { .. } => "ofs_out_of_range",
        Error::DeltaCycle(_) => "delta_cycle",
        Error::MissingBase(_) => "missing_base",
        Error::CrcMismatch { .. } => "crc_mismatch",
        Error::ChecksumMismatch(_) => "checksum_mismatch",
        Error::Unsupported(_) => "unsupported",
        Error::NotFound(_) => "not_found",
        Error::Conflict(_) => "conflict",
    }
}
