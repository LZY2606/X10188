//! Git pack and pack index parsing (no system git involved).

use crate::git::{self, InflateError};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Offset of the entry header within the pack file.
    pub offset: u64,
    pub type_code: u8,
    /// Size declared in the entry header (inflated size; for deltas, the
    /// inflated size of the delta payload itself).
    pub size_declared: u64,
    /// For ofs-delta: absolute offset of the base entry in the same pack.
    pub base_offset: Option<u64>,
    /// For ref-delta: object id of the base.
    pub base_oid: Option<[u8; 20]>,
    /// Offset where the zlib stream starts.
    pub data_offset: u64,
    /// Compressed length of the zlib stream (boundary detected by inflate).
    pub data_len: u64,
    /// Offset one past the end of this entry.
    pub end_offset: u64,
    /// CRC32 of the raw entry bytes [offset, end_offset).
    pub crc32: u32,
    /// Inflated payload (full object content, or delta instructions).
    pub inflated: Vec<u8>,
    /// Set when the declared size turned out to be a lie mid-decompression.
    pub size_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: [u8; 20],
    pub trailer_ok: bool,
    /// Errors for entries that failed to parse/inflate; the bad object is
    /// isolated while parsing continues where possible.
    pub entry_errors: Vec<(u64, String)>,
}

fn read_u32_be(buf: &[u8], pos: usize) -> Result<u32, String> {
    if pos + 4 > buf.len() {
        return Err("pack: truncated u32".to_string());
    }
    Ok(u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]))
}

/// Parse the type/size header of a pack entry. Returns (type, size, next_pos).
fn parse_entry_header(buf: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= buf.len() {
        return Err("pack: truncated entry header".to_string());
    }
    let mut i = pos;
    let first = buf[i];
    i += 1;
    let type_code = (first >> 4) & 0x7;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        if i >= buf.len() {
            return Err("pack: truncated entry size".to_string());
        }
        b = buf[i];
        i += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("pack: entry size overflow".to_string());
        }
    }
    Ok((type_code, size, i))
}

/// Parse the ofs-delta base offset varint. Returns (base_offset, next_pos).
fn parse_ofs_delta(buf: &[u8], pos: usize, entry_offset: u64) -> Result<(u64, usize), String> {
    if pos >= buf.len() {
        return Err("pack: truncated ofs-delta".to_string());
    }
    let mut i = pos;
    let mut n = (buf[i] & 0x7f) as u64;
    i += 1;
    while buf[i - 1] & 0x80 != 0 {
        if i >= buf.len() {
            return Err("pack: truncated ofs-delta".to_string());
        }
        n = ((n + 1) << 7) | (buf[i] & 0x7f) as u64;
        i += 1;
    }
    if n > entry_offset {
        return Err(format!(
            "pack: ofs-delta distance {} exceeds entry offset {}",
            n, entry_offset
        ));
    }
    Ok((entry_offset - n, i))
}

pub fn parse_pack(data: &[u8]) -> Result<ParsedPack, String> {
    if data.len() < 12 + 20 {
        return Err("pack: too small".to_string());
    }
    if &data[0..4] != b"PACK" {
        return Err("pack: bad magic".to_string());
    }
    let version = read_u32_be(data, 4)?;
    if version != 2 && version != 3 {
        return Err(format!("pack: unsupported version {}", version));
    }
    let declared_count = read_u32_be(data, 8)?;
    let body_end = data.len() - 20;
    let mut trailer = [0u8; 20];
    trailer.copy_from_slice(&data[body_end..]);
    let actual: [u8; 20] = Sha1::digest(&data[..body_end]).into();
    let trailer_ok = actual == trailer;
    let mut entries = Vec::new();
    let mut entry_errors = Vec::new();
    let mut pos = 12usize;
    while pos < body_end && (entries.len() as u32) < declared_count {
        let entry_offset = pos as u64;
        match parse_one_entry(data, body_end, entry_offset) {
            Ok(entry) => {
                pos = entry.end_offset as usize;
                entries.push(entry);
            }
            Err(e) => {
                // Without a known boundary the remaining entries are
                // unreachable; record the failure and stop.
                entry_errors.push((entry_offset, e));
                break;
            }
        }
    }
    Ok(ParsedPack {
        version,
        declared_count,
        entries,
        trailer,
        trailer_ok,
        entry_errors,
    })
}

fn parse_one_entry(data: &[u8], body_end: usize, entry_offset: u64) -> Result<PackEntry, String> {
    let (type_code, size_declared, mut pos) = parse_entry_header(data, entry_offset as usize)?;
    let mut base_offset = None;
    let mut base_oid = None;
    match type_code {
        git::OBJ_OFS_DELTA => {
            let (bo, next) = parse_ofs_delta(data, pos, entry_offset)?;
            base_offset = Some(bo);
            pos = next;
        }
        git::OBJ_REF_DELTA => {
            if pos + 20 > body_end {
                return Err("pack: truncated ref-delta base oid".to_string());
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[pos..pos + 20]);
            base_oid = Some(oid);
            pos += 20;
        }
        git::OBJ_COMMIT | git::OBJ_TREE | git::OBJ_BLOB | git::OBJ_TAG => {}
        other => return Err(format!("pack: unknown entry type {}", other)),
    }
    let data_offset = pos as u64;
    let input = &data[pos..body_end];
    let (inflated, consumed, size_error) = match git::inflate_stream(input, Some(size_declared)) {
        Ok(res) => (res.data, res.consumed, None),
        Err(e) => {
            // Keep the entry visible in the layout with the error recorded;
            // the bad object is isolated from the rest of the analysis.
            let consumed = match &e {
                InflateError::Truncated { consumed } => *consumed,
                _ => (body_end - pos) as u64,
            };
            (Vec::new(), consumed, Some(e.to_string()))
        }
    };
    let end_offset = data_offset + consumed;
    let crc32 = crc32fast::hash(&data[entry_offset as usize..end_offset as usize]);
    Ok(PackEntry {
        offset: entry_offset,
        type_code,
        size_declared,
        base_offset,
        base_oid,
        data_offset,
        data_len: consumed,
        end_offset,
        crc32,
        inflated,
        size_error,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// sha1 of the pack this index belongs to (v2 only).
    pub pack_sha1: Option<[u8; 20]>,
}

pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx, String> {
    if data.len() < 4 * 256 {
        return Err("idx: too small".to_string());
    }
    if data[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        parse_idx_v2(data)
    } else {
        parse_idx_v1(data)
    }
}

fn parse_idx_v2(data: &[u8]) -> Result<ParsedIdx, String> {
    let version = read_u32_be(data, 4)?;
    if version != 2 {
        return Err(format!("idx: unsupported version {}", version));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_u32_be(data, 8 + i * 4)?;
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    if big_base > data.len() {
        return Err("idx: truncated tables".to_string());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 = read_u32_be(data, crc_base + i * 4)?;
        let raw_off = read_u32_be(data, off_base + i * 4)?;
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let p = big_base + idx * 8;
            if p + 8 > data.len() {
                return Err("idx: truncated 64-bit offset table".to_string());
            }
            u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = if data.len() >= big_base + 40 {
        let p = data.len() - 40;
        let mut sha = [0u8; 20];
        sha.copy_from_slice(&data[p..p + 20]);
        Some(sha)
    } else {
        None
    };
    Ok(ParsedIdx {
        version: 2,
        fanout,
        entries,
        pack_sha1,
    })
}

fn parse_idx_v1(data: &[u8]) -> Result<ParsedIdx, String> {
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_u32_be(data, i * 4)?;
    }
    let n = fanout[255] as usize;
    let base = 256 * 4;
    if base + n * 24 > data.len() {
        return Err("idx: truncated v1 table".to_string());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let p = base + i * 24;
        let offset = read_u32_be(data, p)? as u64;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p + 4..p + 24]);
        entries.push(IdxEntry { oid, crc32: 0, offset });
    }
    Ok(ParsedIdx {
        version: 1,
        fanout,
        entries,
        pack_sha1: None,
    })
}

