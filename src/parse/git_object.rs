//! Git "raw object" framing: `"<type> <size>\0<content>"`, SHA-1 of that
//! stream is the object id. Loose objects are stored as one zlib stream
//! of exactly this framing.

use crate::model::ObjType;
use sha1::{Digest, Sha1};

pub struct RawObject {
    pub typ: ObjType,
    pub content: Vec<u8>,
}

impl RawObject {
    pub fn frame(&self) -> Vec<u8> {
        let header = format!("{} {}\0", self.typ.as_str(), self.content.len());
        let mut out = Vec::with_capacity(header.len() + self.content.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&self.content);
        out
    }

    pub fn oid(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(&self.frame());
        hex::encode(hasher.finalize())
    }
}

/// Parse a loose-object stream body: `"<type> <size>\0<content>"`.
pub fn parse_loose_body(
    data: &[u8],
) -> Result<RawObject, String> {
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "missing NUL in loose header".to_string())?;
    let header = std::str::from_utf8(&data[..nul])
        .map_err(|_| "loose header not utf-8".to_string())?;
    let (type_str, size_str) = header
        .split_once(' ')
        .ok_or_else(|| "loose header missing space".to_string())?;
    let typ = ObjType::parse(type_str).ok_or_else(|| format!("unknown type {type_str}"))?;
    let declared: u64 = size_str
        .parse()
        .map_err(|_| format!("bad size {size_str}"))?;
    let content = data[nul + 1..].to_vec();
    if declared as usize != content.len() {
        return Err(format!(
            "declared size {declared} != content {}",
            content.len()
        ));
    }
    Ok(RawObject { typ, content })
}
