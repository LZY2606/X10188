use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Parse(String),
    BadData(String),
    NotFound(String),
    BudgetPaused {
        kind: String,
        limit: u64,
        used: u64,
        retryable: bool,
    },
    Io(String),
}

impl Error {
    pub fn parse(s: impl Into<String>) -> Self {
        Error::Parse(s.into())
    }
    pub fn bad(s: impl Into<String>) -> Self {
        Error::BadData(s.into())
    }
    pub fn not_found(s: impl Into<String>) -> Self {
        Error::NotFound(s.into())
    }
    pub fn retryable(&self) -> bool {
        matches!(self, Error::BudgetPaused { .. })
    }
    pub fn code(&self) -> &'static str {
        match self {
            Error::Parse(_) => "parse_error",
            Error::BadData(_) => "bad_data",
            Error::NotFound(_) => "not_found",
            Error::BudgetPaused { .. } => "budget_paused",
            Error::Io(_) => "io_error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(s) => write!(f, "parse error: {s}"),
            Error::BadData(s) => write!(f, "corrupt data: {s}"),
            Error::NotFound(s) => write!(f, "not found: {s}"),
            Error::Io(s) => write!(f, "io error: {s}"),
            Error::BudgetPaused { kind, limit, used, .. } => {
                write!(f, "budget paused ({kind}): used {used} / limit {limit}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
