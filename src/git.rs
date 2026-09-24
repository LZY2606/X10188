//! Low-level Git primitives implemented from scratch (no git binary, no git crate).

use crate::error::{Error, Result};
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use std::io::Read;

/// Canonical Git object types. `Delta` kinds keep the raw pack type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Result<ObjType> {
        match code {
            1 => Ok(ObjType::Commit),
            2 => Ok(ObjType::Tree),
            3 => Ok(ObjType::Blob),
            4 => Ok(ObjType::Tag),
            6 => Ok(ObjType::OfsDelta),
            7 => Ok(ObjType::RefDelta),
            other => Err(Error::BadPack(format!("unknown object type code {other}"))),
        }
    }

    pub fn pack_code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    pub fn header_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            ObjType::OfsDelta | ObjType::RefDelta => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
}

/// Compute the Git object id (sha1 over `"<type> <len>\0<body>"`).
pub fn git_object_id(kind: ObjType, body: &[u8]) -> Result<[u8; 20]> {
    let name = kind
        .header_name()
        .ok_or_else(|| Error::BadDelta("cannot hash a delta object directly".into()))?;
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.update(b" ");
    hasher.update(body.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(body);
    Ok(hasher.finalize().into())
}

pub fn hex20(bytes: &[u8; 20]) -> String {
    hex::encode(bytes)
}

pub fn parse_oid(s: &str) -> Result<[u8; 20]> {
    let v = hex::decode(s.trim())
        .map_err(|_| Error::BadPack(format!("invalid oid hex: {s}")))?;
    if v.len() != 20 {
        return Err(Error::BadPack(format!("oid must be 20 bytes, got {}", v.len())));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn oid_prefix(oid: &[u8; 20]) -> String {
    hex20(oid)
}

/// Reader that counts every byte pulled out of the underlying slice so we can
/// locate the exact end of a zlib stream inside a pack.
struct CountedReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Read for CountedReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Inflate a zlib stream beginning at `buf[start]`. Returns the bytes and the
/// number of compressed bytes consumed (the zlib boundary inside the pack).
pub fn inflate_zlib(buf: &[u8], start: usize) -> Result<(Vec<u8>, usize)> {
    let counted = CountedReader {
        buf,
        pos: start,
    };
    let mut decoder = ZlibDecoder::new(counted);
    let mut data = Vec::new();
    decoder
        .read_to_end(&mut data)
        .map_err(|e| Error::BadPack(format!("zlib inflate failed: {e}")))?;
    let consumed = decoder.into_inner().pos - start;
    Ok((data, consumed))
}

/// A loose object is a standalone zlib stream of `"<type> <size>\0<body>"`.
pub struct LooseObject {
    pub kind: ObjType,
    pub body: Vec<u8>,
    pub compressed_len: usize,
}

pub fn parse_loose(buf: &[u8]) -> Result<LooseObject> {
    let (raw, compressed_len) = inflate_zlib(buf, 0)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::BadLoose("missing NUL in loose object header".into()))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| Error::BadLoose("non-utf8 loose object header".into()))?;
    let (name, size_str) = header
        .split_once(' ')
        .ok_or_else(|| Error::BadLoose("loose header missing space".into()))?;
    let declared: usize = size_str
        .parse()
        .map_err(|_| Error::BadLoose("loose header size not numeric".into()))?;
    let body = raw[nul + 1..].to_vec();
    if declared != body.len() {
        return Err(Error::SizeMismatch {
            declared: declared as u64,
            actual: body.len() as u64,
        });
    }
    let kind = match name {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(Error::BadLoose(format!("unknown type {other}"))),
    };
    Ok(LooseObject {
        kind,
        body,
        compressed_len,
    })
}

/// Read the pack variable-length size/type header at `pos`.
/// Returns (type_code, declared_size, new_pos).
pub fn read_pack_entry_header(buf: &[u8], mut pos: usize) -> Result<(u8, u64, usize)> {
    if pos >= buf.len() {
        return Err(Error::BadPack("unexpected end reading entry header".into()));
    }
    let first = buf[pos];
    pos += 1;
    let type_code = (first >> 4) & 0b111;
    let mut size = (first & 0b0000_1111) as u64;
    let mut shift = 4;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err(Error::BadPack("varint continuation past end".into()));
        }
        byte = buf[pos];
        pos += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((type_code, size, pos))
}

/// Read the ofs-delta negative distance encoding.
pub fn read_ofs_distance(buf: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    if pos >= buf.len() {
        return Err(Error::BadPack("unexpected end reading ofs distance".into()));
    }
    let mut byte = buf[pos];
    pos += 1;
    let mut distance = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err(Error::BadPack("ofs distance continuation past end".into()));
        }
        byte = buf[pos];
        pos += 1;
        distance = distance.wrapping_add(1);
        distance = (distance << 7) | (byte & 0x7f) as u64;
    }
    Ok((distance, pos))
}

/// Read a 20-byte big-endian oid.
pub fn read_oid(buf: &[u8], pos: usize) -> Result<[u8; 20]> {
    if pos + 20 > buf.len() {
        return Err(Error::BadPack("unexpected end reading base oid".into()));
    }
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&buf[pos..pos + 20]);
    Ok(oid)
}

/// Encode a pack entry size/type header (used by tests to synthesize packs).
pub fn write_pack_size_header(kind: ObjType, size: u64) -> Vec<u8> {
    let code = kind.pack_code();
    let mut out = Vec::new();
    let mut first = ((code & 0b111) << 4) | ((size as u8) & 0b1111);
    let mut rest = size >> 4;
    if rest > 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest > 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

pub fn write_ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance > 0 {
        distance -= 1;
        bytes.push(((distance & 0x7f) as u8) | 0x80);
        distance >>= 7;
    }
    bytes.reverse();
    bytes
}
