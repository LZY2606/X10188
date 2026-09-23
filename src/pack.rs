//! Parser for git v2 pack files (`*.pack`).
//!
//! Everything is parsed by hand — no system git and no git library — so the
//! exact byte offsets and compressed boundaries can be retained as evidence.

use crate::types::GitType;
use crate::zlib::{inflate_stream, ZlibError};
use sha1::{Digest, Sha1};

pub const PACK_SIGNATURE: &[u8; 4] = b"PACK";
pub const PACK_TRAILER_LEN: usize = 20;

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u32,
    pub num_objects_declared: u32,
    pub file_size: usize,
    pub trailer_ok: bool,
    pub trailer_stored: [u8; 20],
    pub trailer_computed: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Sequence number in scan order.
    pub ordinal: usize,
    /// Byte offset where the entry header starts.
    pub offset: u64,
    /// Byte offset where the zlib stream starts.
    pub data_offset: u64,
    /// Length of the compressed zlib stream in bytes.
    pub compressed_len: usize,
    pub kind: Option<GitType>,
    /// Size encoded in the entry header.
    pub declared_size: u64,
    /// Actual inflated length.
    pub actual_size: usize,
    /// Inflated payload (delta instructions for deltas, content for bases).
    pub payload: Option<Vec<u8>>,
    /// Base object id for ref-delta entries.
    pub base_oid: Option<[u8; 20]>,
    /// Negative-distance encoding for ofs-delta entries.
    pub ofs_distance: Option<u64>,
    /// CRC32 claimed by the index for this entry, if known.
    pub crc_from_idx: Option<u32>,
    /// CRC32 we compute over the exact on-disk entry bytes.
    pub crc_actual: u32,
    /// Error isolated to this entry, if any.
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackParseError {
    pub offset: u64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub header: Option<PackHeader>,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<PackParseError>,
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Parse a whole pack file.  `inflate_cap` bounds inflation of any single
/// entry (defence against corrupted/malicious size headers).
pub fn parse_pack(data: &[u8], inflate_cap: usize) -> ParsedPack {
    let mut result = ParsedPack {
        header: None,
        entries: Vec::new(),
        errors: Vec::new(),
    };

    if data.len() < 12 + PACK_TRAILER_LEN {
        result.errors.push(PackParseError {
            offset: 0,
            message: format!("file too small for a pack: {} bytes", data.len()),
        });
        return result;
    }
    if &data[..4] != PACK_SIGNATURE {
        result.errors.push(PackParseError {
            offset: 0,
            message: "bad PACK signature".into(),
        });
        return result;
    }
    let version = read_u32(data, 4);
    let num_objects = read_u32(data, 8);
    if version != 2 {
        result.errors.push(PackParseError {
            offset: 4,
            message: format!("unsupported pack version {version} (only v2 supported)"),
        });
        return result;
    }

    let body_end = data.len() - PACK_TRAILER_LEN;
    let mut trailer_computed = Sha1::new();
    trailer_computed.update(&data[..body_end]);
    let trailer_computed: [u8; 20] = trailer_computed.finalize().into();
    let mut trailer_stored = [0u8; 20];
    trailer_stored.copy_from_slice(&data[body_end..]);
    result.header = Some(PackHeader {
        version,
        num_objects_declared: num_objects,
        file_size: data.len(),
        trailer_ok: trailer_computed == trailer_stored,
        trailer_stored,
        trailer_computed,
    });

    let mut pos = 12usize;
    let mut ordinal = 0usize;

    while pos < body_end {
        if ordinal >= num_objects as usize {
            result.errors.push(PackParseError {
                offset: pos as u64,
                message: format!(
                    "more entries on disk than declared ({num_objects}); stopping scan"
                ),
            });
            break;
        }
        let entry_offset = pos;

        // LSB-first variable-length entry header.
        let (kind_opt, declared_size, hdr_len, hdr_err) =
            read_entry_header(data, pos, body_end);
        pos += hdr_len;

        let mut entry = PackEntry {
            ordinal,
            offset: entry_offset as u64,
            data_offset: pos as u64,
            compressed_len: 0,
            kind: kind_opt,
            declared_size,
            actual_size: 0,
            payload: None,
            base_oid: None,
            ofs_distance: None,
            crc_from_idx: None,
            crc_actual: 0,
            error: None,
        };
        if let Some(msg) = hdr_err {
            entry.error = Some(msg.clone());
            result.errors.push(PackParseError {
                offset: entry_offset as u64,
                message: msg,
            });
            result.entries.push(entry);
            break; // cannot locate the zlib stream without a valid header
        }

        // Delta-specific fixed fields.
        match entry.kind {
            Some(GitType::OfsDelta) => match read_ofs_distance(data, pos, body_end) {
                Ok((distance, used)) => {
                    entry.ofs_distance = Some(distance);
                    pos += used;
                    entry.data_offset = pos as u64;
                    if distance as usize > entry_offset {
                        entry.error = Some(format!(
                            "ofs-delta distance {distance} reaches before pack start (entry @{entry_offset})"
                        ));
                    }
                }
                Err(msg) => {
                    entry.error = Some(msg.clone());
                    result.errors.push(PackParseError {
                        offset: pos as u64,
                        message: msg,
                    });
                    result.entries.push(entry);
                    break;
                }
            },
            Some(GitType::RefDelta) => {
                if pos + 20 > body_end {
                    let msg = "ref-delta base oid overruns pack".to_string();
                    entry.error = Some(msg.clone());
                    result.errors.push(PackParseError {
                        offset: pos as u64,
                        message: msg,
                    });
                    result.entries.push(entry);
                    break;
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&data[pos..pos + 20]);
                entry.base_oid = Some(oid);
                pos += 20;
                entry.data_offset = pos as u64;
            }
            _ => {}
        }

        let zlib_start = pos;
        match inflate_stream(
            &data[zlib_start..body_end],
            Some(declared_size as usize),
            true,
            inflate_cap,
        ) {
            Ok(inflated) => {
                entry.compressed_len = inflated.consumed;
                entry.actual_size = inflated.data.len();
                entry.payload = Some(inflated.data);
                pos = zlib_start + inflated.consumed;
                let entry_end = pos;
                entry.crc_actual = crc32fast::hash(&data[entry_offset..entry_end]);
            }
            Err(ZlibError::SizeMismatch { declared, actual }) => {
                // Halfway through inflation the lie is exposed.  We cannot
                // trust the boundary, so scanning stops here; the entry is
                // still recorded as isolated evidence.
                entry.error = Some(format!(
                    "size spoof: header says {declared} but zlib produced {actual} bytes"
                ));
                entry.actual_size = actual;
                result.errors.push(PackParseError {
                    offset: entry_offset as u64,
                    message: entry.error.clone().unwrap(),
                });
                result.entries.push(entry);
                break;
            }
            Err(e) => {
                entry.error = Some(e.to_string());
                result.errors.push(PackParseError {
                    offset: entry_offset as u64,
                    message: e.to_string(),
                });
                result.entries.push(entry);
                break;
            }
        }

        result.entries.push(entry);
        ordinal += 1;
    }

    if ordinal < num_objects as usize && result.errors.is_empty() {
        result.errors.push(PackParseError {
            offset: pos as u64,
            message: format!(
                "pack declares {num_objects} objects but only {ordinal} entries were readable"
            ),
        });
    }

    result
}

/// Returns (type, declared size, header length, error).
fn read_entry_header(
    data: &[u8],
    start: usize,
    end: usize,
) -> (Option<GitType>, u64, usize, Option<String>) {
    let mut pos = start;
    if pos >= end {
        return (None, 0, 0, Some("unexpected end of pack".into()));
    }
    let first = data[pos];
    pos += 1;
    let type_code = (first >> 4) & 0b111;
    let kind = GitType::from_pack_code(type_code);
    if kind.is_none() {
        return (
            None,
            0,
            pos - start,
            Some(format!("unknown pack object type code {type_code}")),
        );
    }
    let mut size = (first & 0b1111) as u64;
    let mut shift = 4u32;
    let mut cont = first & (1 << 7) != 0;
    while cont {
        if pos >= end {
            return (kind, size, pos - start, Some("truncated entry header".into()));
        }
        let b = data[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & (1 << 7) != 0;
        if shift > 63 && cont {
            return (kind, size, pos - start, Some("entry size varint overflow".into()));
        }
    }
    (kind, size, pos - start, None)
}

/// ofs-delta negative-offset varint (git format).
fn read_ofs_distance(data: &[u8], start: usize, end: usize) -> Result<(u64, usize), String> {
    let mut pos = start;
    if pos >= end {
        return Err("truncated ofs-delta header".into());
    }
    let mut b = data[pos];
    pos += 1;
    let mut distance = (b & 0x7f) as u64;
    while b & (1 << 7) != 0 {
        if pos >= end {
            return Err("truncated ofs-delta offset".into());
        }
        b = data[pos];
        pos += 1;
        distance += 1;
        distance = (distance << 7) | (b & 0x7f) as u64;
    }
    Ok((distance, pos - start))
}
