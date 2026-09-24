//! Pure-Rust PACK v2 parser: header, entries, ofs/ref deltas, zlib edges.

use super::inflate::{inflate_bounded, InflateError};
use super::oid::{sha1_raw, GitType, Oid};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PackKind {
    OfsDelta,
    RefDelta,
    Full(GitType),
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub index: usize,
    pub kind: PackKind,
    pub header_offset: usize,
    pub data_offset: usize,
    pub end_offset: usize,
    pub declared_size: usize,
    /// Inflated payload (object body for full entries; delta blob for deltas).
    pub payload: Vec<u8>,
    /// Bytes of raw pack region covering this whole entry (header+zlib+crc).
    pub crc_expect: u32,
    pub crc_actual: u32,
    pub crc_ok: bool,
    /// Offset of the ofs-delta base entry header.
    pub base_offset: Option<usize>,
    /// Oid named by a ref-delta.
    pub base_oid: Option<Oid>,
}

#[derive(Clone, Debug, Default)]
pub struct PackParseResult {
    pub entries: Vec<PackEntry>,
    pub version: u32,
    pub object_count: u32,
    pub pack_checksum: Option<Oid>,
    pub pack_checksum_ok: bool,
    /// Fatal parse evidence that stopped the scan.
    pub fatal: Option<String>,
}

fn read_size_varint(buf: &[u8], mut pos: usize) -> Result<(u32, usize, u8), String> {
    if pos >= buf.len() {
        return Err("truncated entry header".into());
    }
    let first = buf[pos];
    pos += 1;
    let mut size = (first & 0x0f) as u32;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("truncated size varint".into());
        }
        b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u32) << shift;
        shift += 7;
        if shift > 35 {
            return Err("absurd size varint".into());
        }
    }
    Ok((size, pos, first))
}

fn read_ofs_delta_distance(buf: &[u8], mut pos: usize) -> Result<(usize, usize), String> {
    if pos >= buf.len() {
        return Err("truncated ofs-delta header".into());
    }
    let first = buf[pos];
    pos += 1;
    let mut distance: usize = (first & 0x7f) as usize;
    let mut b = first;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("truncated ofs-delta offset".into());
        }
        b = buf[pos];
        pos += 1;
        distance = (distance + 1).checked_shl(7).ok_or("ofs distance overflow")?
            | (b & 0x7f) as usize;
    }
    Ok((distance, pos))
}

pub fn parse_pack(buf: &[u8]) -> PackParseResult {
    let mut res = PackParseResult::default();
    if buf.len() < 12 {
        res.fatal = Some("file shorter than 12-byte pack header".into());
        return res;
    }
    if &buf[0..4] != b"PACK" {
        res.fatal = Some("missing PACK magic".into());
        return res;
    }
    res.version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    res.object_count = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if res.version != 2 {
        res.fatal = Some(format!("unsupported pack version {}", res.version));
        return res;
    }

    let mut pos = 12usize;
    let mut idx = 0usize;
    while idx < res.object_count as usize {
        let header_offset = pos;
        let entry = match parse_entry(buf, pos, idx) {
            Ok((e, next)) => {
                pos = next;
                e
            }
            Err(msg) => {
                res.fatal = Some(format!("entry {} at offset {} failed: {}", idx, pos, msg));
                break;
            }
        };
        res.entries.push(entry);
        idx += 1;
    }

    if res.fatal.is_none() {
        // 20-byte pack trailer SHA-1 over all preceding bytes.
        if pos + 20 > buf.len() {
            res.fatal = Some("missing 20-byte pack checksum trailer".into());
        } else {
            let expect = Oid::from_bytes(buf[pos..pos + 20].try_into().unwrap());
            let actual = Oid::from_bytes(sha1_raw(&buf[..pos]));
            res.pack_checksum = Some(expect);
            res.pack_checksum_ok = expect == actual;
        }
    }
    res
}

fn parse_entry(buf: &[u8], start: usize, index: usize) -> Result<(PackEntry, usize), String> {
    let (size, after_size, first) = read_size_varint(buf, start)?;
    let type_code = (first >> 4) & 0x07;
    let mut kind = match type_code {
        1 => PackKind::Full(GitType::Commit),
        2 => PackKind::Full(GitType::Tree),
        3 => PackKind::Full(GitType::Blob),
        4 => PackKind::Full(GitType::Tag),
        6 => PackKind::OfsDelta,
        7 => PackKind::RefDelta,
        _ => return Err(format!("invalid object type code {}", type_code)),
    };

    let mut p = after_size;
    let mut base_offset = None;
    let mut base_oid = None;
    if kind == PackKind::OfsDelta {
        let (distance, np) = read_ofs_delta_distance(buf, p)?;
        p = np;
        let bo = p
            .checked_sub(distance)
            .ok_or_else(|| format!("ofs-delta distance {} underflows before data at {}", distance, p))?;
        if bo < 12 || bo >= start {
            return Err(format!(
                "ofs-delta distance {} resolves to offset {} outside [12,{})",
                distance, bo, start
            ));
        }
        base_offset = Some(bo);
    } else if kind == PackKind::RefDelta {
        if p + 20 > buf.len() {
            return Err("truncated ref-delta base oid".into());
        }
        base_oid = Some(Oid::from_bytes(buf[p..p + 20].try_into().unwrap()));
        p += 20;
    }

    let data_offset = p;
    let cap = size as usize;
    let (payload, consumed) = inflate_bounded(&buf[p..], cap).map_err(|e| match e {
        InflateError::CapExceeded { cap, attempted } => {
            format!("size spoof: header says {} but stream produced >= {}", cap, attempted)
        }
        other => other.to_string(),
    })?;
    let end_offset = p + consumed;
    if payload.len() != cap {
        return Err(format!(
            "inflated length {} does not match header size {}",
            payload.len(),
            cap
        ));
    }

    if end_offset + 4 > buf.len() {
        return Err("entry runs past file before CRC".into());
    }
    let crc_expect = u32::from_be_bytes([
        buf[end_offset],
        buf[end_offset + 1],
        buf[end_offset + 2],
        buf[end_offset + 3],
    ]);
    let crc_actual = crc32fast::hash(&buf[start..end_offset]);
    let crc_ok = crc_expect == crc_actual;

    // Sanity: delta payload must at least contain two size varints.
    if matches!(kind, PackKind::OfsDelta | PackKind::RefDelta) && payload.len() < 2 {
        return Err("delta payload shorter than two size varints".into());
    }
    if let PackKind::Full(t) = &mut kind {
        let _ = t;
    }

    Ok((
        PackEntry {
            index,
            kind,
            header_offset: start,
            data_offset,
            end_offset,
            declared_size: cap,
            payload,
            crc_expect,
            crc_actual,
            crc_ok,
            base_offset,
            base_oid,
        },
        end_offset + 4,
    ))
}
