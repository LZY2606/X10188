//! loose object 解析：`<type> <len>\0<...zlib...>`，并重新计算 object id。

use serde::{Deserialize, Serialize};

use crate::git::oid::git_object_id;
use crate::Oid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LooseObject {
    pub object_type: String,
    pub declared_size: u64,
    pub body: Vec<u8>,
    pub computed_oid: Oid,
    pub claimed_oid: Oid,
    pub oid_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LooseError {
    Truncated,
    BadHeader,
    BadType(String),
    SizeParse(String),
    Zlib(String),
    SizeMismatch { declared: u64, actual: u64 },
}

impl std::fmt::Display for LooseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for LooseError {}

pub fn parse_loose(data: &[u8], claimed: Oid, hard_cap: usize) -> Result<LooseObject, LooseError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    // 先解压整个 loose 文件（只有一个 zlib 流）。
    let mut dec = ZlibDecoder::new(data);
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len() + n > hard_cap {
                    return Err(LooseError::Zlib("inflated output exceeds hard cap".into()));
                }
                raw.extend_from_slice(&buf[..n]);
            }
            Err(e) => return Err(LooseError::Zlib(e.to_string())),
        }
    }
    let nul = raw.iter().position(|b| *b == 0).ok_or(LooseError::BadHeader)?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| LooseError::BadHeader)?;
    let mut sp = header.splitn(2, ' ');
    let ty = sp.next().ok_or(LooseError::BadHeader)?;
    let size_s = sp.next().ok_or(LooseError::BadHeader)?;
    if !matches!(ty, "commit" | "tree" | "blob" | "tag") {
        return Err(LooseError::BadType(ty.into()));
    }
    let declared: u64 = size_s.parse().map_err(|_| LooseError::SizeParse(size_s.into()))?;
    let body = &raw[nul + 1..];
    if body.len() as u64 != declared {
        return Err(LooseError::SizeMismatch { declared, actual: body.len() as u64 });
    }
    let computed = git_object_id(ty, body);
    Ok(LooseObject {
        object_type: ty.into(),
        declared_size: declared,
        body: body.to_vec(),
        computed_oid: computed,
        claimed_oid: claimed,
        oid_ok: computed == claimed,
    })
}
