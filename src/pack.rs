use crate::types::*;
use crate::zlibutil::{inflate_guarded, InflateOutcome};
use crc32fast::Hasher as CrcHasher;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: u8,
    pub header_size: u64,
    pub compressed_size: u64,
    pub declared_size: u64,
    pub ofs_base: Option<i64>,
    pub ref_base: Option<[u8; 20]>,
    pub crc32: u32,
    pub inflate: Option<InflateRecord>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InflateRecord {
    pub consumed: u64,
    pub total_in: u64,
    pub total_out: u64,
    pub outcome: String,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub data_len: u64,
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha: [u8; 20],
    pub trailer_ok: bool,
    pub parse_error: Option<String>,
}

fn read_size_encoding(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize), ParseError> {
    let first = *data.get(pos).ok_or_else(|| ParseError::new("truncated_header", "object header truncated").at(pos as u64))?;
    let obj_type = (first >> 4) & 0b111;
    let mut size = (first & 0b0111) as u64;
    let mut shift = 4;
    pos += 1;
    let mut b = first;
    while b & 0x80 != 0 {
        b = *data.get(pos).ok_or_else(|| ParseError::new("truncated_header", "size varint truncated").at(pos as u64))?;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
    }
    Ok((obj_type, size, pos))
}

fn read_ofs_delta(data: &[u8], mut pos: usize) -> Result<(i64, usize), ParseError> {
    let mut b = *data.get(pos).ok_or_else(|| ParseError::new("truncated_ofs", "ofs-delta byte truncated"))?;
    let mut ofs: i64 = (b & 0x7f) as i64;
    pos += 1;
    while b & 0x80 != 0 {
        b = *data.get(pos).ok_or_else(|| ParseError::new("truncated_ofs", "ofs-delta varint truncated"))?;
        ofs = ((ofs + 1) << 7) | (b & 0x7f) as i64;
        pos += 1;
    }
    Ok((-ofs, pos))
}

pub fn parse_pack(data: &[u8]) -> ParsedPack {
    let mut pp = ParsedPack {
        data_len: data.len() as u64,
        version: 0,
        count: 0,
        entries: Vec::new(),
        trailer_sha: [0u8; 20],
        trailer_ok: false,
        parse_error: None,
    };
    if data.len() < 32 {
        pp.parse_error = Some("file shorter than pack header+trailer".into());
        return pp;
    }
    if &data[0..4] != b"PACK" {
        pp.parse_error = Some("bad pack signature".into());
        return pp;
    }
    pp.version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    pp.count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if pp.version != 2 {
        pp.parse_error = Some(format!("unsupported pack version {}", pp.version));
        return pp;
    }

    let mut pos = 12usize;
    for _ in 0..pp.count {
        let entry_start = pos;
        let parsed = (|| -> Result<PackEntry, ParseError> {
            let (obj_type, declared_size, after_size) = read_size_encoding(data, pos)?;
            pos = after_size;
            let mut ofs_base = None;
            let mut ref_base = None;
            if obj_type == OBJ_OFS_DELTA {
                let (rel, after) = read_ofs_delta(data, pos)?;
                ofs_base = Some(rel);
                pos = after;
            } else if obj_type == OBJ_REF_DELTA {
                if pos + 20 > data.len() {
                    return Err(ParseError::new("truncated_ref", "ref-delta base name truncated").at(pos as u64));
                }
                let mut name = [0u8; 20];
                name.copy_from_slice(&data[pos..pos + 20]);
                ref_base = Some(name);
                pos += 20;
            } else if obj_type < 1 || obj_type == 5 || obj_type > 7 {
                return Err(ParseError::new("bad_type", format!("invalid object type {}", obj_type)).at(entry_start as u64));
            }
            let zlib_start = pos;
            // Per-entry CRC is computed over packed entry data, from header
            // start through the last consumed compressed byte.
            let (outcome, _content) = inflate_guarded(data, zlib_start, declared_size);
            let mut entry = PackEntry {
                offset: entry_start as u64,
                obj_type,
                header_size: (zlib_start - entry_start) as u64,
                compressed_size: 0,
                declared_size,
                ofs_base,
                ref_base,
                crc32: 0,
                inflate: None,
                error: None,
            };
            match &outcome {
                InflateOutcome::Exact { consumed, total_in, total_out } => {
                    pos = zlib_start + *consumed;
                    entry.compressed_size = *consumed as u64;
                    entry.inflate = Some(InflateRecord {
                        consumed: *consumed as u64,
                        total_in: *total_in,
                        total_out: *total_out,
                        outcome: "exact".into(),
                    });
                }
                InflateOutcome::Truncated { got, declared, consumed } => {
                    pos = zlib_start + consumed;
                    entry.compressed_size = consumed as u64;
                    entry.error = Some(format!(
                        "size_lie: header declares {} inflated bytes but stream produced {}",
                        declared, got
                    ));
                    entry.inflate = Some(InflateRecord {
                        consumed: consumed as u64,
                        total_in: consumed as u64,
                        total_out: *got,
                        outcome: "truncated".into(),
                    });
                }
                InflateOutcome::Overflow { got, declared } => {
                    entry.error = Some(format!(
                        "size_lie: header declares {} bytes but inflated output exceeded (got {})",
                        declared, got
                    ));
                    entry.inflate = Some(InflateRecord {
                        consumed: 0,
                        total_in: 0,
                        total_out: *got,
                        outcome: "overflow".into(),
                    });
                    // Cannot reliably find stream boundary; abort remaining parse.
                    return Err(ParseError::new("size_lie", entry.error.clone().unwrap()).at(entry_start as u64));
                }
                InflateOutcome::Error(e) => {
                    entry.error = Some(format!("zlib_error: {}", e));
                    entry.inflate = Some(InflateRecord {
                        consumed: 0,
                        total_in: 0,
                        total_out: 0,
                        outcome: "error".into(),
                    });
                    return Err(ParseError::new("zlib_error", e.clone()).at(entry_start as u64));
                }
            }
            let mut h = CrcHasher::new();
            h.update(&data[entry_start..pos]);
            entry.crc32 = h.sum();
            Ok(entry)
        })();
        match parsed {
            Ok(e) => pp.entries.push(e),
            Err(e) => {
                // Record a tombstone entry so the UI can show evidence, then
                // stop walking (zlib boundary is unrecoverable here).
                pp.parse_error = Some(format!("@{:#x}: {}", e.offset.unwrap_or(0), e));
                // Push best-effort partial entry describing the failure offset.
                pp.entries.push(PackEntry {
                    offset: entry_start as u64,
                    obj_type: 0,
                    header_size: 0,
                    compressed_size: 0,
                    declared_size: 0,
                    ofs_base: None,
                    ref_base: None,
                    crc32: 0,
                    inflate: None,
                    error: Some(e.to_string()),
                });
                break;
            }
        }
    }

    if data.len() >= 20 {
        pp.trailer_sha.copy_from_slice(&data[data.len() - 20..]);
        let mut h = crate::gitid::Sha1::new();
        h.update(&data[..data.len() - 20]);
        let calc = h.finalize();
        pp.trailer_ok = calc == pp.trailer_sha;
    }
    pp
}
