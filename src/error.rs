use std::fmt;

#[derive(Debug)]
pub enum Error {
    BadMagic(String),
    Unsupported(String),
    Truncated(String),
    Zlib(String),
    SizeSpoof {
        declared: u64,
        actual: u64,
        context: String,
    },
    BadCrc {
        offset: u64,
        expected: u32,
        actual: u32,
    },
    BadChecksum {
        context: String,
        expected: String,
        actual: String,
    },
    Delta(String),
    OfsOutOfRange {
        offset: u64,
        distance: u64,
    },
    NotFound(String),
    BadInput(String),
    Sql(rusqlite::Error),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic(s) => write!(f, "bad magic: {s}"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::Truncated(s) => write!(f, "truncated: {s}"),
            Error::Zlib(s) => write!(f, "zlib error: {s}"),
            Error::SizeSpoof {
                declared,
                actual,
                context,
            } => write!(
                f,
                "size spoof in {context}: header declared {declated} bytes but stream produced {actual}",
                declated = declared
            ),
            Error::BadCrc {
                offset,
                expected,
                actual,
            } => write!(
                f,
                "crc mismatch at pack offset {offset}: idx says {expected:08x}, data is {actual:08x}"
            ),
            Error::BadChecksum {
                context,
                expected,
                actual,
            } => write!(f, "sha1 checksum mismatch for {context}: {expected} != {actual}"),
            Error::Delta(s) => write!(f, "delta error: {s}"),
            Error::OfsOutOfRange { offset, distance } => {
                write!(f, "ofs-delta at {offset} points {distance} bytes before pack start")
            }
            Error::NotFound(s) => write!(f, "not found: {s}"),
            Error::BadInput(s) => write!(f, "bad input: {s}"),
            Error::Sql(e) => write!(f, "sqlite: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sql(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
