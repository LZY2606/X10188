//! Parsers for git `.pack`, `.idx` and loose object files.
//!
//! Everything here is structural parsing only: resolution of delta chains and
//! recomputation of object ids happens in [`crate::engine`].

use crate::inflate::{inflate_bounded, InflateError};
use crate::oid::Oid;

pub const PACK_SIG: [u8; 4] = *b"PACK";
pub const IDX_SIG_V2: [u8; 4] = [255, 116, 79, 99]; // \377tOc
pub const PACK_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl PackType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => PackType::Commit,
            2 => PackType::Tree,
            3 => PackType::Blob,
            4 => PackType::Tag,
            6 => PackType::OfsDelta,
            7 => PackType::RefDelta,
            _ => return None,
        })
    }
    pub fn kind_name(self) -> &'static str {
        match self {
            PackType::Commit => "commit",
            PackType::Tree => "tree",
            PackType::Blob => "blob",
            PackType::Tag => "tag",
            PackType::OfsDelta => "ofs-delta",
            PackType::RefDelta => "ref-delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, PackType::OfsDelta | PackType::RefDelta)
    }
}

#[derive(Debug, Clone)]
pub enum DeltaRef {
    /// Signed distance from the current entry offset back to the base entry.
    Ofs { negative_distance: u64, base_offset: u64 },
    /// 20-byte id of the base object.
    Ref(Oid),
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Absolute offset of the entry header within the pack file.
    pub offset: u64,
    pub raw_type: PackType,
    /// Size declared by the entry header (untrusted).
    pub declared_size: u64,
    pub delta_ref: Option<DeltaRef>,
    /// Offset where the zlib stream starts.
    pub zlib_start: u64,
    /// Compressed length actually consumed by the zlib stream.
    pub zlib_len: usize,
    /// Inflated bytes (delta instructions or object body).
    pub payload: Vec<u8>,
    /// Non-fatal inflation notes (kept as evidence).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackParseResult {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha: Oid,
    pub file_len: u64,
    /// Structural errors that stopped a clean parse; entries before the
    /// failure are still kept so the microscope can show partial layout.
    pub errors: Vec<PackError>,
    /// Offset of the 20-byte trailing SHA1 (for layout rendering).
    pub trailer_offset: u64,
}

#[derive(Debug, Clone)]
pub struct PackError {
    pub at_offset: u64,
    pub message: String,
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_entry_header(buf: &[u8], pos: &mut u64) -> Result<(PackType, u64), String> {
    let p = *pos as usize;
    if p >= buf.len() {
        return Err("对象头超出文件范围".into());
    }
    let first = buf[p];
    let mut t = (first >> 4) & 0x07;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut i = p + 1;
    if first & 0x80 != 0 {
        loop {
            if i >= buf.len() {
                return Err("对象头 varint 截断".into());
            }
            let b = buf[i];
            i += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 70 {
                return Err("对象头 varint 过长".into());
            }
        }
    }
    *pos = i as u64;
    if t == 0 {
        return Err("对象类型 0 非法".into());
    }
    if t == 5 {
        return Err("对象类型 5 保留未使用".into());
    }
    if t > 7 {
        return Err("对象类型超出 7".into());
    }
    Ok((
        PackType::from_u8(t).ok_or_else(|| format!("未知对象类型 {}", t))?,
        size,
    ))
}

/// Decode the n-byte offset encoding used after an OFS_DELTA header.
fn read_ofs_distance(buf: &[u8], pos: &mut u64) -> Result<u64, String> {
    let p = *pos as usize;
    if p >= buf.len() {
        return Err("ofs-delta 距离截断".into());
    }
    let mut c = buf[p] as u64;
    let mut dist = c & 0x7f;
    let mut i = p + 1;
    while c & 0x80 != 0 {
        if i >= buf.len() {
            return Err("ofs-delta 距离截断".into());
        }
        c = buf[i] as u64;
        i += 1;
        dist += 1;
        dist = (dist << 7) + (c & 0x7f);
    }
    *pos = i as u64;
    Ok(dist)
}
