//! Low-level Git object utilities: oid computation, varints, zlib boundary parsing.
//! No system git is invoked anywhere in this crate.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};
use thiserror::Error;

pub type Oid = [u8; 20];

pub fn oid_hex(oid: &Oid) -> String {
    hex::encode(oid)
}

pub fn parse_oid_hex(s: &str) -> Option<Oid> {
    let b = hex::decode(s).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    Some(o)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            _ => None,
        }
    }
    pub fn from_name(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }
}

/// Compute the Git object id for a type+payload (sha1 of "<type> <len>\0<payload>").
pub fn compute_oid(t: ObjType, payload: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(t.as_str().as_bytes());
    h.update(b" ");
    h.update(payload.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(payload);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

/// Decode a git-style little-endian-7bit varint (used for delta sizes).
/// Returns (value, bytes_consumed).
pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

#[derive(Debug, Error)]
pub enum ZlibError {
    #[error("zlib stream corrupt: {0}")]
    Corrupt(String),
    #[error("zlib stream truncated (needed more input)")]
    Truncated,
    #[error("decompressed size {got} exceeds budget {max} (possible size fraud)")]
    BudgetExceeded { got: u64, max: u64 },
    #[error("declared size {declared} does not match inflated size {actual} (size fraud)")]
    SizeFraud { declared: u64, actual: u64 },
}

/// Inflate a zlib stream starting at data[0], returning the inflated bytes and the
/// exact number of compressed bytes consumed (the zlib boundary), so the caller can
/// locate the next object / the pack trailer without scanning.
pub fn inflate_boundary(
    data: &[u8],
    declared_size: Option<u64>,
    max_out: u64,
) -> Result<(Vec<u8>, usize), ZlibError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= data.len() {
            return Err(ZlibError::Truncated);
        }
        let status = d
            .decompress(&data[in_before..], &mut chunk, FlushDecompress::None)
            .map_err(|e| ZlibError::Corrupt(e.to_string()))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > max_out {
            return Err(ZlibError::BudgetExceeded {
                got: out.len() as u64,
                max: max_out,
            });
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                let consumed = d.total_in() as usize;
                if consumed >= data.len() && produced == 0 {
                    return Err(ZlibError::Truncated);
                }
            }
        }
    }
    let used = d.total_in() as usize;
    if let Some(decl) = declared_size {
        if decl != out.len() as u64 {
            return Err(ZlibError::SizeFraud {
                declared: decl,
                actual: out.len() as u64,
            });
        }
    }
    Ok((out, used))
}

/// Compress data as a zlib stream (test helper / loose writing).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
