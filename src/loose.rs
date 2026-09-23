//! Parser for loose git objects: zlib("<type> <size>\\0<content>").

use crate::types::GitType;
use crate::zlib::{inflate_stream, ZlibError};

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: GitType,
    pub declared_size: usize,
    pub content: Vec<u8>,
    /// Number of compressed bytes consumed.
    pub compressed_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LooseError {
    Zlib(ZlibError),
    Header(String),
    SizeMismatch { declared: usize, actual: usize },
}

impl std::fmt::Display for LooseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LooseError::Zlib(z) => write!(f, "{z}"),
            LooseError::Header(s) => write!(f, "loose header error: {s}"),
            LooseError::SizeMismatch { declared, actual } => write!(
                f,
                "loose size spoof: header says {declared}, body has {actual} bytes"
            ),
        }
    }
}

impl std::error::Error for LooseError {}

pub fn parse_loose(data: &[u8], inflate_cap: usize) -> Result<LooseObject, LooseError> {
    // We don't know the size up front; inflate with the hard cap, then parse.
    let inflated = inflate_stream(data, None, false, inflate_cap).map_err(LooseError::Zlib)?;
    let buf = &inflated.data;
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| LooseError::Header("missing NUL after header".into()))?;
    let header = std::str::from_utf8(&buf[..nul])
        .map_err(|_| LooseError::Header("header is not utf-8".into()))?;
    let (name, num) = header
        .split_once(' ')
        .ok_or_else(|| LooseError::Header("expected '<type> <size>'".into()))?;
    let kind = GitType::from_loose_name(name)
        .ok_or_else(|| LooseError::Header(format!("unknown type {name}")))?;
    let declared_size = num
        .parse::<usize>()
        .map_err(|_| LooseError::Header(format!("bad size {num}")))?;
    let content = buf[nul + 1..].to_vec();
    if content.len() != declared_size {
        return Err(LooseError::SizeMismatch {
            declared: declared_size,
            actual: content.len(),
        });
    }
    Ok(LooseObject {
        kind,
        declared_size,
        content,
        compressed_len: inflated.consumed,
    })
}
