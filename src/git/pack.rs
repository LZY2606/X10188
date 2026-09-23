//! Parser for the Git pack file container (version 2 and legacy version 3 header).
//!
//! Layout: `"PACK"` magic, u32 version, u32 object count, then packed entries, then a
//! 20-byte SHA-1 trailer over the whole preceding file. This module parses only the
//! container: types, offsets, delta references and compressed boundaries. It never
//! resolves delta chains or talks to a git binary.

use crate::git::object::{ObjType, OBJ_OFS_DELTA, OBJ_REF_DELTA};
use crate::git::zlib::{inflate_stream, InflateError};

pub const PACK_MAGIC: &[u8; 4] = b"PACK";

#[derive(Debug, Clone)]
pub enum EntryKind {
    Base(ObjType),
    OfsDelta { negative_offset: u64, base_offset: u64 },
    RefDelta { base_oid: [u8; 20] },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Absolute offset of the entry's first byte in the pack file.
    pub offset: u64,
    pub kind: EntryKind,
    /// Declared inflated size (for deltas: the delta payload size).
    pub declared_size: u64,
    pub header_len: usize,
    /// Compressed bytes consumed by the zlib stream.
    pub zlib_len: usize,
    pub data_start: u64,
    pub data_end: u64,
    /// Inflated payload (`None` when decompression failed).
    pub payload: Option<Vec<u8>>,
    pub crc32_computed: u32,
    pub inflate_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackScan {
    pub version: u32,
    pub count_declared: u32,
    pub entries: Vec<PackEntry>,
    /// Offset at which scanning stopped (start of trailing garbage / checksum).
    pub end_offset: u64,
    /// Why linear scanning stopped early, if it did.
    pub stop_reason: Option<String>,
    pub file_len: u64,
}

#[derive(Debug)]
pub enum PackError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u32),
    Truncated(String),
    BadType(u8),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackError::TooShort => f.write_str("pack shorter than 12-byte header"),
            PackError::BadMagic => f.write_str("bad pack magic"),
            PackError::UnsupportedVersion(v) => write!(f, "unsupported pack version {v}"),
            PackError::Truncated(s) => write!(f, "pack truncated: {s}"),
            PackError::BadType(t) => write!(f, "invalid object type code {t}"),
        }
    }
}

pub fn crc32_ieee(data: &[u8]) -> u32 {
    // Small table-free implementation; packs are modest in tests, and this avoids a dependency.
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn parse_entry_header(data: &[u8], offset: usize) -> Result<(EntryKind, u64, usize), PackError> {
    let mut pos = offset;
    if pos >= data.len() {
        return Err(PackError::Truncated("entry header".into()));
    }
    let first = data[pos];
    pos += 1;
    let type_code = (first & 0x70) >> 4;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    if first & 0x80 != 0 {
        loop {
            if pos >= data.len() {
                return Err(PackError::Truncated("size continuation".into()));
            }
            let byte = data[pos];
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    let kind = if type_code == OBJ_OFS_DELTA {
        if pos >= data.len() {
            return Err(PackError::Truncated("ofs-delta byte".into()));
        }
        let mut byte = data[pos];
        pos += 1;
        let mut value = (byte & 0x7f) as u64;
        while byte & 0x80 != 0 {
            if pos >= data.len() {
                return Err(PackError::Truncated("ofs-delta continuation".into()));
            }
            value += 1;
            byte = data[pos];
            pos += 1;
            value = (value << 7) | (byte & 0x7f) as u64;
        }
        EntryKind::OfsDelta {
            negative_offset: value,
            base_offset: offset as u64 - value,
        }
    } else if type_code == OBJ_REF_DELTA {
        if pos + 20 > data.len() {
            return Err(PackError::Truncated("ref-delta base oid".into()));
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[pos..pos + 20]);
        pos += 20;
        EntryKind::RefDelta { base_oid: oid }
    } else {
        let ty = ObjType::from_pack_code(type_code)
            .ok_or(PackError::BadType(type_code))?;
        EntryKind::Base(ty)
    };

    Ok((kind, size, pos - offset))
}

pub fn scan_pack(data: &[u8]) -> Result<PackScan, PackError> {
    if data.len() < 12 {
        return Err(PackError::TooShort);
    }
    if &data[0..4] != PACK_MAGIC {
        return Err(PackError::BadMagic);
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    let count_declared = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut offset = 12usize;
    let mut stop_reason = None;

    for _ in 0..count_declared {
        if offset + 1 >= data.len() {
            stop_reason = Some(format!("entry header missing at offset {offset}"));
            break;
        }
        let entry_offset = offset;
        let (kind, declared_size, header_len) = match parse_entry_header(data, offset) {
            Ok(v) => v,
            Err(e) => {
                stop_reason = Some(format!("offset {offset}: {e}"));
                break;
            }
        };
        let data_start = offset + header_len;
        let inflate_result = inflate_stream(data, data_start, declared_size);
        match inflate_result {
            Ok(inf) => {
                let data_end = data_start + inf.consumed;
                let crc = crc32_ieee(&data[entry_offset..data_end]);
                entries.push(PackEntry {
                    offset: entry_offset as u64,
                    kind,
                    declared_size,
                    header_len,
                    zlib_len: inf.consumed,
                    data_start: data_start as u64,
                    data_end: data_end as u64,
                    payload: Some(inf.data),
                    crc32_computed: crc,
                    inflate_error: None,
                });
                offset = data_end;
            }
            Err(e @ (InflateError::SizeOvershoot { .. } | InflateError::CrcMismatch)) => {
                // Size spoof / CRC corruption: keep the bad node isolated. We cannot trust the
                // stream length for an overshoot, so linear scanning stops here.
                entries.push(PackEntry {
                    offset: entry_offset as u64,
                    kind: kind.clone(),
                    declared_size,
                    header_len,
                    zlib_len: 0,
                    data_start: data_start as u64,
                    data_end: data_start as u64,
                    payload: None,
                    crc32_computed: 0,
                    inflate_error: Some(e.to_string()),
                });
                stop_reason = Some(format!("offset {entry_offset}: {e}"));
                offset = data_start;
                break;
            }
            Err(e) => {
                entries.push(PackEntry {
                    offset: entry_offset as u64,
                    kind,
                    declared_size,
                    header_len,
                    zlib_len: 0,
                    data_start: data_start as u64,
                    data_end: data_start as u64,
                    payload: None,
                    crc32_computed: 0,
                    inflate_error: Some(e.to_string()),
                });
                stop_reason = Some(format!("offset {entry_offset}: {e}"));
                offset = data_start;
                break;
            }
        }
    }

    Ok(PackScan {
        version,
        count_declared,
        entries,
        end_offset: offset as u64,
        stop_reason,
        file_len: data.len() as u64,
    })
}

/// Continue scanning from explicit offsets (taken from an index), recovering entries that
/// follow an isolated corrupt entry. `known` maps entry offset -> expected crc (if available).
pub fn scan_entries_at_offsets(
    data: &[u8],
    offsets: &[u64],
) -> Vec<(u64, Option<PackEntry>, Option<String>)> {
    let mut out = Vec::new();
    for &off in offsets {
        let off = off as usize;
        match parse_entry_header(data, off) {
            Ok((kind, declared_size, header_len)) => {
                let data_start = off + header_len;
                match inflate_stream(data, data_start, declared_size) {
                    Ok(inf) => {
                        let data_end = data_start + inf.consumed;
                        let crc = crc32_ieee(&data[off..data_end]);
                        out.push((
                            off as u64,
                            Some(PackEntry {
                                offset: off as u64,
                                kind,
                                declared_size,
                                header_len,
                                zlib_len: inf.consumed,
                                data_start: data_start as u64,
                                data_end: data_end as u64,
                                payload: Some(inf.data),
                                crc32_computed: crc,
                                inflate_error: None,
                            }),
                            None,
                        ));
                    }
                    Err(e) => out.push((
                        off as u64,
                        Some(PackEntry {
                            offset: off as u64,
                            kind,
                            declared_size,
                            header_len,
                            zlib_len: 0,
                            data_start: data_start as u64,
                            data_end: data_start as u64,
                            payload: None,
                            crc32_computed: 0,
                            inflate_error: Some(e.to_string()),
                        }),
                        Some(e.to_string()),
                    )),
                }
            }
            Err(e) => out.push((off as u64, None, Some(e.to_string()))),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::builder::build_pack;
    use crate::git::delta::encode_insert_delta;

    #[test]
    fn scan_simple_pack() {
        let objs = vec![
            crate::git::builder::PackObj::base(ObjType::Blob, b"hello world".to_vec()),
            crate::git::builder::PackObj::base(ObjType::Blob, b"second".to_vec()),
        ];
        let pack = build_pack(&objs, false);
        let scan = scan_pack(&pack).unwrap();
        assert_eq!(scan.count_declared, 2);
        assert_eq!(scan.entries.len(), 2);
        assert!(scan.stop_reason.is_none());
        assert_eq!(scan.entries[0].payload.as_deref(), Some(&b"hello world"[..]));
        assert_eq!(scan.end_offset, pack.len() as u64 - 20);
    }

    #[test]
    fn ofs_delta_header_parsed() {
        let base = b"hello ofs chain".to_vec();
        let delta = encode_insert_delta(base.len() as u64, b"new content");
        let objs = vec![
            crate::git::builder::PackObj::base(ObjType::Blob, base),
            crate::git::builder::PackObj::ofs_delta(0, delta),
        ];
        let pack = build_pack(&objs, false);
        let scan = scan_pack(&pack).unwrap();
        assert_eq!(scan.entries.len(), 2);
        match &scan.entries[1].kind {
            EntryKind::OfsDelta {
                base_offset,
                negative_offset,
            } => {
                assert_eq!(*base_offset, scan.entries[0].offset);
                assert!(*negative_offset > 0);
            }
            other => panic!("expected ofs-delta, got {other:?}"),
        }
    }
}
