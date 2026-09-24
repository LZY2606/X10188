//! Loose object parsing: either raw `zlib(type SP len NUL content)` or, when
//! importing an unknown file, a best-effort interpretation.

use super::inflate::{inflate_bounded, InflateError};
use super::oid::{hash_object, GitType, Oid};

const HARD_INFLATE_CAP: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LooseObject {
    pub ty: GitType,
    pub declared_size: usize,
    pub content: Vec<u8>,
    pub computed_oid: Oid,
    pub claimed_oid: Option<Oid>,
    pub oid_ok: bool,
}

#[derive(Debug)]
pub enum LooseError {
    Inflate(String),
    BadHeader(String),
}

impl std::fmt::Display for LooseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LooseError::Inflate(m) => write!(f, "loose zlib: {}", m),
            LooseError::BadHeader(m) => write!(f, "loose header: {}", m),
        }
    }
}

impl std::error::Error for LooseError {}

pub fn parse_loose(buf: &[u8], claimed: Option<Oid>) -> Result<LooseObject, LooseError> {
    // Two-pass size discovery is not needed: the object's own size header is
    // authoritative, but to catch spoofing we inflate only up to the size the
    // header *would* allow. Inflate the header incrementally is complex, so we
    // first inflate to the hard cap; the hard cap is the abuse boundary.
    let (data, _) = inflate_bounded(buf, HARD_INFLATE_CAP).map_err(|e| match e {
        InflateError::CapExceeded { .. } => LooseError::Inflate(
            "size spoof: inflated content exceeds safety cap".into(),
        ),
        other => LooseError::Inflate(other.to_string()),
    })?;
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| LooseError::BadHeader("missing NUL after type/size".into()))?;
    let head = std::str::from_utf8(&data[..nul])
        .map_err(|_| LooseError::BadHeader("non-UTF8 object header".into()))?;
    let (t, s) = head
        .split_once(' ')
        .ok_or_else(|| LooseError::BadHeader("expected 'type size'".into()))?;
    let ty = GitType::from_name(t.as_bytes())
        .ok_or_else(|| LooseError::BadHeader(format!("unknown type {}", t)))?;
    let size: usize = s
        .parse()
        .map_err(|_| LooseError::BadHeader(format!("bad size {}", s)))?;
    let content = data[nul + 1..].to_vec();
    if content.len() != size {
        return Err(LooseError::BadHeader(format!(
            "header size {} != body length {} (size spoof)",
            size,
            content.len()
        )));
    }
    let computed = hash_object(ty, &content);
    let oid_ok = claimed.map_or(true, |c| c == computed);
    Ok(LooseObject {
        ty,
        declared_size: size,
        content,
        computed_oid: computed,
        claimed_oid: claimed,
        oid_ok,
    })
}
