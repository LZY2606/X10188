use crate::error::{Error, Result};
use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_pack_code(c: u8) -> Result<ObjType> {
        match c {
            1 => Ok(ObjType::Commit),
            2 => Ok(ObjType::Tree),
            3 => Ok(ObjType::Blob),
            4 => Ok(ObjType::Tag),
            6 => Ok(ObjType::OfsDelta),
            7 => Ok(ObjType::RefDelta),
            _ => Err(Error::parse(format!("unknown pack object type {c}"))),
        }
    }
    pub fn from_loose_name(s: &str) -> Result<ObjType> {
        match s {
            "commit" => Ok(ObjType::Commit),
            "tree" => Ok(ObjType::Tree),
            "blob" => Ok(ObjType::Blob),
            "tag" => Ok(ObjType::Tag),
            _ => Err(Error::parse(format!("unknown loose object type {s}"))),
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    pub fn code(self) -> Option<u8> {
        match self {
            ObjType::Commit => Some(1),
            ObjType::Tree => Some(2),
            ObjType::Blob => Some(3),
            ObjType::Tag => Some(4),
            ObjType::OfsDelta | ObjType::RefDelta => None,
        }
    }
}

impl std::fmt::Display for ObjType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub fn hash_object(kind: ObjType, body: &[u8]) -> [u8; OID_LEN] {
    let header = format!("{} {}\0", kind.name(), body.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(body);
    h.finalize().into()
}

pub fn oid_hex(id: &[u8; OID_LEN]) -> String {
    hex::encode(id)
}

/// Decode a pack entry header (3-bit type + variable-length size) or an
/// ofs-delta negative-offset variable-length integer.
pub fn decode_size(first: u8, rest: &[u8]) -> (u64, usize) {
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut n = 1usize;
    for &b in rest {
        n += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return (size, n);
        }
    }
    (size, n)
}

/// Decode the ofs-delta negative-offset variable-length integer.
pub fn decode_ofs_distance(first: u8, rest: &[u8]) -> (u64, usize) {
    let mut val = (first & 0x7f) as u64;
    let mut n = 1usize;
    for &b in rest {
        n += 1;
        val = ((val + 1) << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return (val, n);
        }
    }
    (val, n)
}

/// Little-endian base-128 varint used for delta base/result sizes.
pub fn decode_delta_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let mut size = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::bad("delta varint too long"));
        }
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((size, i + 1));
        }
        shift += 7;
    }
    Err(Error::bad("truncated delta varint"))
}

pub fn encode_size(kind: ObjType, size: u64) -> Vec<u8> {
    let code = kind.code().expect("cannot encode delta as entry type");
    let mut out = Vec::new();
    let mut b = ((code as u8) << 4) | (size as u8 & 0x0f);
    let mut rest = size >> 4;
    while rest != 0 {
        b |= 0x80;
        out.push(b);
        b = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    out.push(b);
    out
}

pub fn encode_ofs_distance(dist: u64) -> Vec<u8> {
    let mut bytes = vec![(dist & 0x7f) as u8];
    let mut v = dist >> 7;
    while v != 0 {
        v -= 1;
        bytes.push(0x80 | ((v & 0x7f) as u8));
        v >>= 7;
    }
    bytes.reverse();
    bytes
}

pub fn encode_delta_varint(mut size: u64) -> Vec<u8> {
    let mut out = vec![(size & 0x7f) as u8];
    size >>= 7;
    while size != 0 {
        out.push((size & 0x7f) as u8);
        size >>= 7;
    }
    let n = out.len();
    for b in out.iter_mut().take(n - 1) {
        *b |= 0x80;
    }
    out
}

pub fn parse_oid(s: &str) -> Result<[u8; OID_LEN]> {
    let v = hex::decode(s.trim()).map_err(|_| Error::parse("bad oid hex"))?;
    if v.len() != OID_LEN {
        return Err(Error::parse("oid must be 40 hex chars"));
    }
    let mut id = [0u8; OID_LEN];
    id.copy_from_slice(&v);
    Ok(id)
}
