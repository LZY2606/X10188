//! Pure-Rust parser for the Git pack container.
//!
//! Layout: `PACK` magic, version u32, object count u32, then `count`
//! entries back-to-back, terminated by a 20-byte SHA-1 trailer.
//! Each entry starts with a type+size varint header (optionally
//! followed by ofs/ref delta base info) and then one zlib stream.

use crate::model::error_code;
use crate::model::{ObjType, Oid};
use crate::parse::varint;
use crate::parse::zlib;
use sha1::{Digest, Sha1};

pub const MAGIC: &[u8; 4] = b"PACK";
/// Safety ceiling for one inflated object regardless of its declared size.
pub const DEFAULT_OBJECT_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum EntryKind {
    Plain {
        typ: ObjType,
        inflated: Vec<u8>,
    },
    OfsDelta {
        /// Encoded negative distance from this entry's header.
        negative_offset: u64,
        /// Absolute offset of the claimed base, if the distance is in range.
        base_offset: Option<u64>,
        delta: Vec<u8>,
    },
    RefDelta {
        base_oid: Oid,
        delta: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub header_offset: u64,
    pub header_len: usize,
    /// Start of the zlib stream.
    pub data_offset: u64,
    /// End of the zlib stream (= start of next entry).
    pub zlib_end: u64,
    pub raw_type_code: u8,
    pub declared_size: u64,
    pub kind: EntryKind,
}

#[derive(Debug, Clone)]
pub struct ParseIssue {
    pub offset: u64,
    pub code: &'static str,
    pub message: String,
    pub evidence_hex: String,
}

impl ParseIssue {
    fn new(offset: u64, code: &'static str, message: String, evidence: &[u8]) -> Self {
        let preview = &evidence[..evidence.len().min(24)];
        ParseIssue { offset, code, message, evidence_hex: hex::encode(preview) }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub header_end: usize,
    pub entries: Vec<PackEntry>,
    pub issues: Vec<ParseIssue>,
    pub trailer: Option<[u8; 20]>,
    pub computed_checksum: Option<[u8; 20]>,
    pub checksum_ok: Option<bool>,
    pub truncated_scan: bool,
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// Read the ofs-delta "negative offset" encoding.
/// Returns `(distance, bytes_consumed)`.
fn read_ofs_distance(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let mut offset = u64::from(first & 0x7f);
    let mut used = 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *data.get(used)?;
        used += 1;
        offset = offset
            .checked_add(1)?
            .checked_shl(7)?
            .checked_add(u64::from(cur & 0x7f))?;
    }
    Some((offset, used))
}

fn read_entry_header(
    data: &[u8],
    entry_offset: usize,
) -> Result<(u8, ObjType, u64, usize, Option<Oid>, Option<(u64, Option<u64>)>, usize), ParseIssue>
{
    // Returns: (raw_type_code, plain_type, size, header_len, ref_base, ofs_base, data_offset)
    let first = *data
        .get(entry_offset)
        .ok_or_else(|| ParseIssue::new(entry_offset as u64, error_code::TRUNCATED, "entry header missing".into(), &[]))?;
    let mut size = u64::from(first & 0x0f);
    let type_code = (first >> 4) & 0x07;
    let mut shift = 4;
    let mut pos = entry_offset + 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *data
            .get(pos)
            .ok_or_else(|| ParseIssue::new(entry_offset as u64, error_code::TRUNCATED, "size varint truncated".into(), &data[entry_offset..]))?;
        size |= u64::from(cur & 0x7f) << shift;
        shift += 7;
        pos += 1;
    }

    let mut ref_base: Option<Oid> = None;
    let mut ofs_base: Option<(u64, Option<u64>)> = None;

    match type_code {
        1..=4 => {}
        6 => {
            let (distance, used) = read_ofs_distance(&data[pos..]).ok_or_else(|| {
                ParseIssue::new(entry_offset as u64, error_code::BAD_VARINT, "ofs-delta distance malformed".into(), &data[entry_offset..pos.min(data.len())])
            })?;
            pos += used;
            let base = (entry_offset as u64).checked_sub(distance);
            let in_range = base
                .map(|b| (b as usize) >= 12 && (b as usize) < entry_offset)
                .unwrap_or(false);
            ofs_base = Some((distance, if in_range { base } else { None }));
        }
        7 => {
            let raw = data
                .get(pos..pos + 20)
                .ok_or_else(|| ParseIssue::new(entry_offset as u64, error_code::TRUNCATED, "ref-delta base oid truncated".into(), &data[entry_offset..]))?;
            ref_base = Oid::from_bytes(raw);
            pos += 20;
        }
        other => {
            return Err(ParseIssue::new(
                entry_offset as u64,
                error_code::BAD_TYPE,
                format!("unknown pack object type {other}"),
                &data[entry_offset..pos],
            ));
        }
    }

    let plain = ObjType::from_code(type_code);
    Ok((type_code, plain.unwrap_or(ObjType::Blob), size, pos - entry_offset, ref_base, ofs_base, pos))
}

/// Parse a single entry beginning at `entry_offset`.
pub fn parse_entry_at(
    data: &[u8],
    entry_offset: u64,
    object_cap: u64,
) -> Result<PackEntry, ParseIssue> {
    let entry_offset = entry_offset as usize;
    let (type_code, typ, declared_size, header_len, ref_base, ofs_base, data_off) =
        read_entry_header(data, entry_offset)?;

    let cap = declared_size.min(object_cap);
    let inflated = match zlib::inflate(&data[data_off..], cap) {
        Ok(g) => g,
        Err(e) => {
            return Err(ParseIssue::new(
                entry_offset as u64,
                e.code,
                format!("{} (partial {} bytes)", e.message, e.partial_len),
                &data[entry_offset..data_off.min(data.len())],
            ));
        }
    };
    let zlib_end = data_off + inflated.consumed;

    // Size spoofing: header promise vs actual inflated length.
    if inflated.data.len() as u64 != declared_size {
        return Err(ParseIssue::new(
            entry_offset as u64,
            if inflated.data.len() as u64 > declared_size {
                error_code::SIZE_OVERFLOW
            } else {
                error_code::SIZE_MISMATCH
            },
            format!("header declares {declared_size} bytes, inflated {}", inflated.data.len()),
            &data[entry_offset..zlib_end.min(data.len())],
        ));
    }

    let kind = match type_code {
        1..=4 => EntryKind::Plain { typ, inflated: inflated.data },
        6 => {
            let (distance, base_offset) = ofs_base.unwrap();
            EntryKind::OfsDelta { negative_offset: distance, base_offset, delta: inflated.data }
        }
        7 => EntryKind::RefDelta { base_oid: ref_base.unwrap(), delta: inflated.data },
        _ => unreachable!(),
    };

    Ok(PackEntry {
        header_offset: entry_offset as u64,
        header_len,
        data_offset: data_off as u64,
        zlib_end: zlib_end as u64,
        raw_type_code: type_code,
        declared_size,
        kind,
    })
}

/// Parse an entire pack file sequentially.
pub fn parse_pack(data: &[u8], object_cap: u64) -> ParsedPack {
    let mut issues = Vec::new();
    let mut entries = Vec::new();

    let (version, count) = if data.len() < 12 {
        issues.push(ParseIssue::new(0, error_code::TRUNCATED, "pack shorter than 12-byte header".into(), data));
        return finish(data, entries, issues, 0, 0, true);
    } else if &data[..4] != MAGIC {
        issues.push(ParseIssue::new(0, error_code::BAD_PACK_SIG, format!("bad magic {:?}", &data[..4]), &data[..4]));
        return finish(data, entries, issues, 0, 0, true);
    } else {
        let v = read_u32(data, 4).unwrap();
        let c = read_u32(data, 8).unwrap();
        if v != 2 {
            issues.push(ParseIssue::new(4, error_code::BAD_PACK_VERSION, format!("unsupported pack version {v}"), &data[4..8]));
        }
        (v, c)
    };

    let mut offset = 12usize;
    let mut truncated_scan = false;
    for idx in 0..count {
        if offset as u64 + 20 > data.len() as u64 {
            issues.push(ParseIssue::new(
                offset as u64,
                error_code::TRUNCATED,
                format!("entry {idx} header overruns file"),
                &data[offset.min(data.len())..],
            ));
            truncated_scan = true;
            break;
        }
        match parse_entry_at(data, offset as u64, object_cap) {
            Ok(entry) => {
                offset = entry.zlib_end as usize;
                entries.push(entry);
            }
            Err(issue) => {
                issues.push(issue);
                truncated_scan = true;
                break;
            }
        }
    }

    if !truncated_scan && offset + 20 > data.len() {
        issues.push(ParseIssue::new(offset as u64, error_code::TRUNCATED, "missing 20-byte pack trailer".into(), &data[offset..]));
        truncated_scan = true;
    }

    finish(data, entries, issues, version, count, truncated_scan)
}

fn finish(
    data: &[u8],
    entries: Vec<PackEntry>,
    mut issues: Vec<ParseIssue>,
    version: u32,
    count: u32,
    truncated_scan: bool,
) -> ParsedPack {
    let mut trailer = None;
    let mut computed = None;
    let mut checksum_ok = None;
    if data.len() >= 20 {
        let body_end = data.len() - 20;
        let mut hasher = Sha1::new();
        hasher.update(&data[..body_end]);
        let digest: [u8; 20] = hasher.finalize().into();
        computed = Some(digest);
        let stored: [u8; 20] = data[body_end..].try_into().unwrap();
        trailer = Some(stored);
        checksum_ok = Some(stored == digest);
        if stored != digest && !truncated_scan {
            issues.push(ParseIssue::new(
                body_end as u64,
                error_code::PACK_CHECKSUM,
                "pack trailer SHA-1 does not match body".into(),
                &data[body_end..],
            ));
        }
    }
    ParsedPack {
        version,
        count,
        header_end: 12,
        entries,
        issues,
        trailer,
        computed_checksum: computed,
        checksum_ok,
        truncated_scan,
    }
}

pub fn varint_size_wire(value: u64, typ: u8) -> Vec<u8> {
    // Pack entry header wire format for tests/builders.
    let mut bytes = Vec::new();
    let mut first = (value as u8 & 0x0f) | (typ << 4);
    let mut rest = value >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    bytes.push(first);
    while rest != 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        bytes.push(b);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofs_distance_encoding() {
        // Encoding samples taken from real git packs.
        let one = read_ofs_distance(&[1]).unwrap();
        assert_eq!(one, (1, 1));
        let mut enc = vec![0x80 | 1u8, 0x02];
        let got = read_ofs_distance(&enc).unwrap();
        assert_eq!(got.0, ((1 + 1) << 7) | 2);
        assert_eq!(got.1, 2);
        enc.push(9);
    }
}
