//! Loose object parsing: zlib stream of `"<type> <size>\0<body>"`.

use crate::error::{ParseError, ParseResult};
use crate::pack::inflate_one;
use crate::types::{GitType, Oid};
use sha1::{Digest, Sha1};

#[derive(Clone, Debug)]
pub struct LooseObject {
    pub object_type: GitType,
    pub declared_size: u64,
    pub body: Vec<u8>,
    /// Offset of the compressed payload inside the file (always 0 for a
    /// plain loose object file, kept for uniformity with pack entries).
    pub data_offset: u64,
    pub data_end: u64,
    pub oid: Oid,
}

pub fn parse_loose(buf: &[u8]) -> ParseResult<LooseObject> {
    let (raw, end) = inflate_one(buf, 0)?;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| ParseError::Corrupt("loose object header missing NUL".into()))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| ParseError::Corrupt("loose object header not utf-8".into()))?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().unwrap_or("");
    let size_str = parts
        .next()
        .ok_or_else(|| ParseError::Corrupt("loose object header missing size".into()))?;
    let object_type = GitType::from_loose_name(type_name)
        .ok_or_else(|| ParseError::Corrupt(format!("unknown loose type {type_name}")))?;
    let declared_size: u64 = size_str
        .trim()
        .parse()
        .map_err(|_| ParseError::Corrupt(format!("bad loose size {size_str}")))?;
    let body = raw[nul + 1..].to_vec();
    if body.len() as u64 != declared_size {
        return Err(ParseError::SizeSpoof {
            declared: declared_size,
            actual: body.len() as u64,
        });
    }
    let oid = git_oid(object_type, &body);
    Ok(LooseObject {
        object_type,
        declared_size,
        body,
        data_offset: 0,
        data_end: end as u64,
        oid,
    })
}

/// Compute the Git object id: sha1("<type> <len>\0" + body).
pub fn git_oid(object_type: GitType, body: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(object_type.header_name().as_bytes());
    h.update(b" ");
    h.update(body.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(body);
    let out = h.finalize();
    Oid::from_bytes(&out).expect("20 bytes")
}
