use std::fmt;

#[derive(Debug)]
pub enum ParseError {
    Io(String),
    BadMagic(String),
    Unsupported(String),
    Corrupt(String),
    Truncated(String),
    Crc { expected: u32, actual: u32 },
    SizeSpoof { declared: u64, actual: u64 },
    Zlib(String),
    BadDelta(String),
    BadOffset(i64),
    Checksum { expected: String, actual: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(s) => write!(f, "io error: {s}"),
            ParseError::BadMagic(s) => write!(f, "bad magic: {s}"),
            ParseError::Unsupported(s) => write!(f, "unsupported: {s}"),
            ParseError::Corrupt(s) => write!(f, "corrupt data: {s}"),
            ParseError::Truncated(s) => write!(f, "truncated: {s}"),
            ParseError::Crc { expected, actual } => write!(
                f,
                "crc mismatch: expected {expected:08x}, actual {actual:08x}"
            ),
            ParseError::SizeSpoof { declared, actual } => write!(
                f,
                "size spoof: header declared {declared} bytes but stream produced {actual}"
            ),
            ParseError::Zlib(s) => write!(f, "zlib error: {s}"),
            ParseError::BadDelta(s) => write!(f, "bad delta: {s}"),
            ParseError::BadOffset(off) => write!(f, "ofs-delta negative offset out of range: {off}"),
            ParseError::Checksum { expected, actual } => write!(
                f,
                "checksum mismatch: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e.to_string())
    }
}

#[derive(Debug)]
pub enum EngineError {
    Parse(ParseError),
    Db(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Parse(p) => write!(f, "{p}"),
            EngineError::Db(s) => write!(f, "db error: {s}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ParseError> for EngineError {
    fn from(e: ParseError) -> Self {
        EngineError::Parse(e)
    }
}

impl From<rusqlite::Error> for EngineError {
    fn from(e: rusqlite::Error) -> Self {
        EngineError::Db(e.to_string())
    }
}

pub type ParseResult<T> = Result<T, ParseError>;
pub type EngineResult<T> = Result<T, EngineError>;
