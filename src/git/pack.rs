//! Parse a Git `.pack` file, preserving raw offsets and zlib boundaries.

use super::delta;
use super::types::{read_ofs_distance, read_pack_obj_header, ObjType};
use super::zlib::inflate_one;
use sha1::{Digest, Sha1};

pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";
/// Per-object inflation hard cap while parsing (forensic safety bound).
pub const PARSE_INFLATE_CAP: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PackProblem {
    pub code: String,
    pub message: String,
    pub offset: Option<u64>,
    pub range: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub enum DeltaRef {
    /// OFS_DELTA: negative distance encoded in the entry, resolved target
    /// absolute offset (None when the distance runs outside the pack).
    Ofs { distance: u64, target: Option<u64> },
    /// REF_DELTA: 20-byte base object id.
    Ref([u8; 20]),
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Absolute offset of the entry's first header byte.
    pub offset: u64,
    pub header_len: usize,
    pub obj_type: Option<ObjType>,
    /// Raw pack type tag (even if unknown).
    pub type_tag: u8,
    pub declared_size: u64,
    pub delta_ref: Option<DeltaRef>,
    /// Offset where the zlib payload begins.
    pub payload_offset: u64,
    /// Bytes consumed by the zlib stream (boundary).
    pub zlib_consumed: Option<usize>,
    pub end_offset: Option<u64>,
    /// CRC32 over the *raw on-disk* entry bytes (header + zlib stream),
    /// matching what a v2 index stores.
    pub crc32: Option<u32>,
    pub inflated: Option<Vec<u8>>,
    pub problems: Vec<PackProblem>,
}

impl PackEntry {
    pub fn is_corrupt(&self) -> bool {
        self.problems
            .iter()
            .any(|p| matches!(p.code.as_str(), "unknown_type" | "bad_header"
                | "ofs_out_of_bounds" | "ref_truncated" | "zlib_error"
                | "spoofed_size" | "size_mismatch"))
    }
}

#[derive(Debug, Clone)]
pub struct PackSummary {
    pub version: u32,
    pub num_objects: u32,
    pub header_len: usize,
    pub trailer_offset: Option<u64>,
    /// SHA1 stored in the final 20 bytes, hex.
    pub stored_checksum: Option<String>,
    /// Recomputed SHA1 over all preceding bytes, hex.
    pub actual_checksum: Option<String>,
    pub checksum_valid: bool,
    pub entries: Vec<PackEntry>,
    pub problems: Vec<PackProblem>,
}

fn problem(code: &str, msg: impl Into<String>, offset: Option<u64>) -> PackProblem {
    PackProblem {
        code: code.into(),
        message: msg.into(),
        offset,
        range: None,
    }
}

/// Parse a pack. When `known_offsets` is supplied (from a paired .idx) every
/// listed offset is parsed directly; otherwise entries are discovered by
/// sequential zlib-boundary walking.
pub fn parse_pack(data: &[u8], known_offsets: Option<&[u64]>) -> PackSummary {
    let mut problems = Vec::new();

    if data.len() < 12 || data[0..4] != PACK_SIGNATURE {
        problems.push(problem("bad_signature", "missing PACK signature", None));
        return PackSummary {
            version: 0,
            num_objects: 0,
            header_len: data.len().min(12),
            trailer_offset: None,
            stored_checksum: None,
            actual_checksum: None,
            checksum_valid: false,
            entries: Vec::new(),
            problems,
        };
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let num_objects = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != 2 {
        problems.push(problem(
            "unsupported_version",
            format!("pack version {} (only v2 supported)", version),
            Some(4),
        ));
    }

    let mut summary = PackSummary {
        version,
        num_objects,
        header_len: 12,
        trailer_offset: None,
        stored_checksum: None,
        actual_checksum: None,
        checksum_valid: false,
        entries: Vec::new(),
        problems,
    };

    let offsets: Vec<u64> = match known_offsets {
        Some(o) => o.to_vec(),
        None => {
            // Sequential walk until trailer or a fatal boundary loss.
            let mut v = Vec::new();
            let mut cur = 12u64;
            while (cur as usize) + 20 < data.len() && (v.len() as u32) < num_objects {
                v.push(cur);
                match peek_entry_end(data, cur) {
                    Some(end) => cur = end,
                    None => break,
                }
            }
            v
        }
    };

    for off in offsets {
        let entry = parse_entry(data, off);
        summary.entries.push(entry);
    }

    // Cross-check counts when walking without an index.
    if known_offsets.is_none() && summary.entries.len() as u32 != num_objects {
        summary.problems.push(problem(
            "object_count_mismatch",
            format!(
                "header declares {} objects, {} could be located",
                num_objects,
                summary.entries.len()
            ),
            Some(12),
        ));
    }

    // Trailer: final 20 bytes are the pack SHA1 over everything before them.
    if data.len() >= 20 {
        let split = data.len() - 20;
        let stored = &data[split..];
        let mut hasher = Sha1::new();
        hasher.update(&data[..split]);
        let actual: [u8; 20] = hasher.finalize().into();
        summary.trailer_offset = Some(split as u64);
        summary.stored_checksum = Some(hex::encode(stored));
        summary.actual_checksum = Some(hex::encode(actual));
        summary.checksum_valid = stored == actual;
        if !summary.checksum_valid {
            summary.problems.push(problem(
                "pack_checksum_mismatch",
                "stored pack SHA1 does not match recomputed SHA1",
                Some(split as u64),
            ));
        }
    } else {
        summary.problems.push(problem("truncated", "pack shorter than 20 bytes", None));
    }

    summary
}

/// Only find where the entry at `off` ends (used while discovering offsets).
fn peek_entry_end(data: &[u8], off: u64) -> Option<u64> {
    let (payload, end) = skip_header(data, off)?;
    let (_typ, declared, _h) = read_pack_obj_header(&data[off as usize..])?;
    let o = inflate_one(&data[payload as usize..], declared, PARSE_INFLATE_CAP).ok()?;
    Some(payload + o.consumed as u64)
}

/// Returns (payload_offset, entry_end_offset_if_stream_ok).
fn skip_header(data: &[u8], off: u64) -> Option<(u64, Option<u64>)> {
    let slice = &data.get(off as usize..)?;
    let (_typ, _size, hlen) = read_pack_obj_header(slice)?;
    let mut p = off as usize + hlen;
    let tag = (slice[0] >> 4) & 7;
    if tag == 6 {
        let (_d, n) = read_ofs_distance(&data[p..])?;
        p += n;
    } else if tag == 7 {
        p += 20;
    }
    Some((p as u64, None))
}

fn parse_entry(data: &[u8], off: u64) -> PackEntry {
    let mut entry = PackEntry {
        offset: off,
        header_len: 0,
        obj_type: None,
        type_tag: (data.get(off as usize).copied().unwrap_or(0) >> 4) & 7,
        declared_size: 0,
        delta_ref: None,
        payload_offset: off,
        zlib_consumed: None,
        end_offset: None,
        crc32: None,
        inflated: None,
        problems: Vec::new(),
    };

    let Some(slice) = data.get(off as usize..) else {
        entry.problems.push(problem(
            "bad_header",
            "entry offset runs past end of pack",
            Some(off),
        ));
        return entry;
    };
    let Some((typ, size, hlen)) = read_pack_obj_header(slice) else {
        entry.problems.push(problem(
            "bad_header",
            "cannot parse object entry header",
            Some(off),
        ));
        return entry;
    };
    entry.obj_type = Some(typ);
    entry.declared_size = size;
    entry.header_len = hlen;

    let mut p = off as usize + hlen;
    match typ {
        ObjType::OfsDelta => {
            match read_ofs_distance(&data[p..]) {
                Some((distance, n)) => {
                    p += n;
                    let target = if distance <= off {
                        Some(off - distance)
                    } else {
                        entry.problems.push(problem(
                            "ofs_out_of_bounds",
                            format!(
                                "ofs-delta distance {} at offset {} precedes pack start",
                                distance, off
                            ),
                            Some(off),
                        ));
                        None
                    };
                    entry.delta_ref = Some(DeltaRef::Ofs { distance, target });
                }
                None => {
                    entry.problems.push(problem(
                        "bad_header",
                        "truncated ofs-delta distance",
                        Some(off),
                    ));
                    return entry;
                }
            }
        }
        ObjType::RefDelta => {
            if p + 20 > data.len() {
                entry.problems.push(problem(
                    "ref_truncated",
                    "ref-delta base oid runs past pack end",
                    Some(off),
                ));
                return entry;
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[p..p + 20]);
            p += 20;
            entry.delta_ref = Some(DeltaRef::Ref(oid));
        }
        _ => {}
    }

    entry.payload_offset = p as u64;

    let outcome = inflate_one(&data[p..], size, PARSE_INFLATE_CAP);
    match outcome {
        Ok(o) => {
            entry.zlib_consumed = Some(o.consumed);
            entry.end_offset = Some(p as u64 + o.consumed as u64);
            let raw = &data[off as usize..p + o.consumed];
            entry.crc32 = Some(crc32fast::hash(raw));
            if o.size_mismatch {
                entry.problems.push(PackProblem {
                    code: "spoofed_size".into(),
                    message: format!(
                        "header declares {} inflated bytes but zlib stream is {} bytes",
                        size,
                        o.data.len()
                    ),
                    offset: Some(off),
                    range: Some((off, p as u64)),
                });
                // Keep the real bytes as evidence, but never trust them.
                entry.inflated = Some(o.data);
            } else {
                entry.inflated = Some(o.data);
            }
        }
        Err(e) => {
            entry.problems.push(PackProblem {
                code: if e.code == "inflation_cap" {
                    "inflation_cap".into()
                } else {
                    "zlib_error".into()
                },
                message: e.message,
                offset: Some(off),
                range: Some((p as u64, p as u64 + e.consumed as u64)),
            });
        }
    }

    entry
}

/// Apply-delta re-export for the engine so parsing rules live in one place.
pub fn apply(base: &[u8], d: &[u8]) -> Result<delta::DeltaResult, delta::DeltaError> {
    delta::apply_delta(base, d)
}
