//! Pure-Rust Git object primitives: types, hashing, size encoding.
//! No external `git` binary is used anywhere in this crate.

pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;

use sha1::{Digest, Sha1};

/// The object types that can appear inside a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl GitType {
    pub fn from_code(code: u8) -> Option<GitType> {
        Some(match code {
            1 => GitType::Commit,
            2 => GitType::Tree,
            3 => GitType::Blob,
            4 => GitType::Tag,
            6 => GitType::OfsDelta,
            7 => GitType::RefDelta,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::OfsDelta => "ofs-delta",
            GitType::RefDelta => "ref-delta",
        }
    }

    /// True for the four "real" object types (not delta containers).
    pub fn is_base(self) -> bool {
        matches!(
            self,
            GitType::Commit | GitType::Tree | GitType::Blob | GitType::Tag
        )
    }
}

/// Compute the Git object id (`sha1("<type> <len>\\0<content>")`) as lowercase hex.
pub fn git_oid(kind: GitType, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(kind.name().as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Raw (loose-object style) envelope for a base object.
pub fn envelope(kind: GitType, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 16);
    out.extend_from_slice(kind.name().as_bytes());
    out.push(b' ');
    out.extend_from_slice(content.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(content);
    out
}

/// Pack/loose variable length size encoding (LEB128-ish, 4-bit first nibble).
pub fn read_size_varint(buf: &[u8], first: u8) -> Result<(u64, usize), String> {
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift: u32 = 4;
    if first & 0x80 == 0 {
        return Ok((size, 0));
    }
    let mut consumed = 0usize;
    loop {
        let byte = *buf
            .get(consumed)
            .ok_or_else(|| "truncated size varint".to_string())?;
        consumed += 1;
        size |= ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or_else(|| "size varint shift overflow".to_string())?;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("size varint too large".to_string());
        }
    }
    Ok((size, consumed))
}

/// Decode the negative-offset varint used by `ofs-delta`.
/// `buf` starts at the first byte *after* the type/size header.
pub fn read_ofs_varint(buf: &[u8], first: u8) -> Result<(u64, usize), String> {
    let mut offset: u64 = (first & 0x7f) as u64;
    let mut consumed = 0usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *buf
            .get(consumed)
            .ok_or_else(|| "truncated ofs-delta varint".to_string())?;
        consumed += 1;
        offset = offset
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| "ofs-delta distance overflow".to_string())?;
        offset |= (byte & 0x7f) as u64;
    }
    Ok((offset, consumed))
}

/// Encode the pack size varint together with the object type (header byte).
pub fn encode_pack_header(kind: GitType, size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut c: u8 = (size & 0x0f) as u8 | (kind.code() << 4);
    let mut rest = size >> 4;
    while rest > 0 {
        c |= 0x80;
        bytes.push(c);
        c = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    bytes.push(c);
    bytes
}

/// Encode an ofs-delta negative distance.
pub fn encode_ofs_distance(distance: u64) -> Vec<u8> {
    assert!(distance > 0, "ofs distance must be positive");
    let mut rev = vec![(distance & 0x7f) as u8];
    let mut rest = distance >> 7;
    while rest > 0 {
        rest -= 1;
        rev.push(0x80 | ((rest & 0x7f) as u8));
        rest >>= 7;
    }
    rev.reverse();
    rev
}

/// A short hex prefix, stable across the application (lowercase).
pub fn short_oid(oid: &str, n: usize) -> String {
    oid.chars().take(n).collect()
}

/// Inflate a standalone zlib stream (loose object) with a hard size cap.
pub fn inflate_limited(data: &[u8], cap: u64) -> Result<Vec<u8>, String> {
    pack::inflate_at(data, 0, cap).map(|(bytes, _consumed)| bytes)
}
