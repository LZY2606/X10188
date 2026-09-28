//! Crate-wide error type.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Input bytes violate the on-disk format and this entry/scan cannot
    /// continue (the offending object is isolated, other objects still run).
    Format(String),
    /// Zlib stream truncated / corrupt.
    Zlib(String),
    /// Delta instructions invalid or would over/underrun.
    Delta(String),
    /// SQLite failure.
    Db(String),
    /// Filesystem failure.
    Io(String),
    /// A required external base is absent.
    MissingBase(String),
    /// A delta cycle was detected.
    Cycle(String),
    /// Resource budget exhausted; state is retryable, never a complete object.
    Budget(BudgetExceeded),
    BadArg(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetKind {
    Depth,
    TotalBytes,
    SingleObject,
    MaxObjects,
}

#[derive(Debug, Clone)]
pub struct BudgetExceeded {
    pub kind: BudgetKind,
    pub detail: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(s) => write!(f, "format error: {s}"),
            Error::Zlib(s) => write!(f, "zlib error: {s}"),
            Error::Delta(s) => write!(f, "delta error: {s}"),
            Error::Db(s) => write!(f, "db error: {s}"),
            Error::Io(s) => write!(f, "io error: {s}"),
            Error::MissingBase(s) => write!(f, "missing base: {s}"),
            Error::Cycle(s) => write!(f, "delta cycle: {s}"),
            Error::Budget(b) => write!(f, "budget exceeded ({:?}): {}", b.kind, b.detail),
            Error::BadArg(s) => write!(f, "bad argument: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        Error::Db(e.to_string())
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
