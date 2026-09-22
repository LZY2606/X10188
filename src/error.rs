use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(String),
    Sql(String),
    Corrupt(String),
    Budget(BudgetKind),
    NotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    Depth,
    Bytes,
    Ratio,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(v) => write!(f, "io error: {v}"),
            Error::Sql(v) => write!(f, "sqlite error: {v}"),
            Error::Corrupt(v) => write!(f, "corrupt input: {v}"),
            Error::Budget(k) => write!(f, "budget exhausted: {k}"),
            Error::NotFound(v) => write!(f, "not found: {v}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Error::Sql(value.to_string())
    }
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetKind::Depth => f.write_str("delta depth"),
            BudgetKind::Bytes => f.write_str("total expanded bytes"),
            BudgetKind::Ratio => f.write_str("single object ratio"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
