//! Standalone `.pack` parser.
//!
//! Parses the pack header, per-object headers (type + size varints,
//! `ofs-delta` / `ref-delta` base references), inflates each object while
//! locating the exact zlib stream boundary, and checks per-object CRC32 plus
//! the trailing pack checksum. Corrupt objects are isolated: with an index
//! (exact offsets) the parser simply jumps to the next object.

use std::collections::HashMap;

use crc32fast::Hasher as CrcHasher;
use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

use super::{read_ofs_varint, read_size_varint, GitType};

/// Hard per-object inflate ceiling used even when no explicit budget is given.
pub const HARD_INFLATE_CAP: u64 = 512 * 1024 * 1024;

/// Budgets honoured while scanning a pack.
#[derive(Debug, Clone)]
pub struct ParseBudget {
    pub max_inflate_per_object: u64,
    pub max_inflate_total: u64,
}

impl Default for ParseBudget {
    fn default() -> Self {
        ParseBudget {
            max_inflate_per_object: HARD_INFLATE_CAP,
            max_inflate_total: HARD_INFLATE_CAP * 16,
        }
    }
}

/// One raw object record straight from the pack (deltas not applied yet).
#[derive(Debug, Clone)]
pub struct RawEntry {
    pub index: usize,
    pub offset: u64,
    /// Bytes consumed by type/size (+delta reference) header.
    pub header_len: u64,
    /// First byte of the zlib-compressed payload.
    pub data_start: u64,
    /// Exact size of the zlib stream (as consumed by the decoder).
    pub compressed_len: u64,
    pub next_offset: u64,
    pub kind: Option<GitType>,
    pub declared_size: u64,
    pub ofs_distance: Option<u64>,
    pub base_offset: Option<u64>,
    pub base_ref: Option<String>,
    /// Inflated payload: object bytes or a delta instruction stream.
    pub inflated: Vec<u8>,
    pub crc32: u32,
    pub crc_expected: Option<u32>,
    pub crc_ok: Option<bool>,
    /// Set when this specific object could not be fully parsed; other
    /// objects in the pack remain available.
    pub error: Option<String>,
}

/// Result of scanning one pack file.
#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub object_count: u32,
    pub entries: Vec<RawEntry>,
    pub trailer_expected: String,
    pub trailer_actual: String,
    pub trailer_ok: bool,
    /// Pack-level problems (bad magic, count mismatch, unrecoverable scan).
    pub errors: Vec<String>,
}

/// Inflate a zlib stream beginning at `start`, returning the bytes and the
/// exact number of compressed bytes consumed. Inflation is bounded by `cap`.
pub fn inflate_at(
    data: &[u8],
    start: usize,
    cap: u64,
) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut rounds = 0u64;

    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        let status = dec
            .decompress(
                &data[start + in_before as usize..],
                &mut chunk,
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib error at pack offset {start}: {e}"))?;
        let produced = dec.total_out() - out_before;
        out.extend_from_slice(&chunk[..produced as usize]);

        if dec.total_out() > cap {
            return Err(format!(
                "inflated payload exceeds {cap} byte cap (declared stream truncated or huge)"
            ));
        }
        if status == Status::StreamEnd {
            return Ok((out, dec.total_in() as usize));
        }
        if status == Status::Ok && dec.total_in() == in_before && produced == 0 {
            return Err(format!("zlib made no progress at pack offset {start}"));
        }
        rounds += 1;
        if rounds > 1_000_000 {
            return Err("zlib round limit exceeded".to_string());
        }
    }
}

/// Parse a complete pack file.
///
/// * `forced_offsets` — object starts taken from a trusted `.idx`; lets the
///   parser recover from neighbouring corruption. When absent the pack is
///   scanned sequentially.
/// * `idx_crc` — expected CRC32 keyed by object offset.
pub fn parse_pack(
    data: &[u8],
    forced_offsets: Option<&[u64]>,
    idx_crc: Option<&HashMap<u64, u32>>,
    budget: &ParseBudget,
) -> ParsedPack {
    let mut errors = Vec::new();

    if data.len() < 32 {
        return fail("pack shorter than 32 bytes");
    }
    if &data[0..4] != b"PACK" {
        return fail("bad pack magic (expected 'PACK')");
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        errors.push(format!("unsupported pack version {version} (only v2 parsed)"));
    }
    let claimed = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let trailer_pos = (data.len() - 20) as u64;
    let trailer_actual = hex::encode(&data[data.len() - 20..]);
    let mut sha = Sha1::new();
    sha.update(&data[..data.len() - 20]);
    let trailer_expected = hex::encode(sha.finalize());
    let trailer_ok = trailer_actual == trailer_expected;
    if !trailer_ok {
        errors.push("pack trailing checksum mismatch".to_string());
    }

    let sorted_offsets: Vec<u64> = match forced_offsets {
        Some(fo) => {
            let mut v: Vec<u64> = fo
                .iter()
                .copied()
                .filter(|o| *o >= 12 && *o < trailer_pos)
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        }
        None => Vec::new(),
    };
    let have_forced = !sorted_offsets.is_empty();
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut inflate_total: u64 = 0;
    let mut cur = 12u64;
    let mut ordinal = 0usize;

    loop {
        if have_forced {
            if ordinal >= sorted_offsets.len() {
                break;
            }
            cur = sorted_offsets[ordinal];
            if cur >= trailer_pos {
                errors.push(format!(
                    "index offset {cur} points at/after pack checksum"
                ));
                break;
            }
        } else if cur >= trailer_pos {
            break;
        }

        let remaining_cap = budget
            .max_inflate_per_object
            .min(budget.max_inflate_total.saturating_sub(inflate_total));

        let mut entry = match parse_entry_at(data, cur, ordinal, remaining_cap) {
            Ok(e) => e,
            Err(msg) => {
                if have_forced {
                    errors.push(format!(
                        "object #{ordinal} at offset {cur} unparseable: {msg}"
                    ));
                    entries.push(RawEntry::error(ordinal, cur, msg));
                    ordinal += 1;
                    continue;
                } else {
                    errors.push(format!(
                        "sequential scan stopped at offset {cur}: {msg}"
                    ));
                    entries.push(RawEntry::error(ordinal, cur, msg));
                    break;
                }
            }
        };

        if entry.next_offset > trailer_pos {
            let msg = format!(
                "object #{} at {} runs past pack data (ends {}, trailer at {})",
                ordinal, entry.offset, entry.next_offset, trailer_pos
            );
            entry.error.get_or_insert_with(|| msg.clone());
            errors.push(msg);
        }
        if have_forced {
            let expected_next = sorted_offsets
                .get(ordinal + 1)
                .copied()
                .unwrap_or(trailer_pos);
            if entry.next_offset != expected_next && entry.error.is_none() {
                let msg = format!(
                    "zlib boundary {} disagrees with index (expected next object at {expected_next})",
                    entry.next_offset
                );
                entry.error = Some(msg.clone());
                errors.push(msg);
            }
        }

        if let Some(map) = idx_crc {
            if let Some(expected) = map.get(&entry.offset) {
                entry.crc_expected = Some(*expected);
                entry.crc_ok = Some(entry.crc32 == *expected);
                if entry.crc_ok == Some(false) {
                    let msg = format!(
                        "CRC32 mismatch at offset {}: pack has {:08x}, index expects {:08x}",
                        entry.offset, entry.crc32, expected
                    );
                    entry.error.get_or_insert_with(|| msg.clone());
                    errors.push(msg);
                }
            }
        }

        inflate_total = inflate_total.saturating_add(entry.inflated.len() as u64);
        cur = entry.next_offset;
        entries.push(entry);
        ordinal += 1;
    }

    let parsed_ok = entries.iter().filter(|e| e.error.is_none()).count() as u32;
    if parsed_ok != claimed {
        errors.push(format!(
            "object count mismatch: header claims {claimed}, parsed {parsed_ok} intact objects"
        ));
    }
    if have_forced && sorted_offsets.len() as u32 != claimed {
        errors.push(format!(
            "index/pack mismatch: index lists {} offsets, pack header claims {claimed}",
            sorted_offsets.len()
        ));
    }

    ParsedPack {
        object_count: claimed,
        entries,
        trailer_expected,
        trailer_actual,
        trailer_ok,
        errors,
    }
}

fn parse_entry_at(
    data: &[u8],
    offset: u64,
    index: usize,
    cap: u64,
) -> Result<RawEntry, String> {
    let start = offset as usize;
    let first = *data
        .get(start)
        .ok_or_else(|| format!("no header byte at offset {offset}"))?;
    let code = (first >> 4) & 0x07;
    let kind = GitType::from_code(code)
        .ok_or_else(|| format!("invalid object type code {code} at offset {offset}"))?;

    let (declared_size, size_extra) = read_size_varint(&data[start + 1..], first)
        .map_err(|e| format!("bad size varint at offset {offset}: {e}"))?;
    let mut p = start + 1 + size_extra;

    let mut ofs_distance = None;
    let mut base_offset = None;
    let mut base_ref = None;

    match kind {
        GitType::OfsDelta => {
            let first_ofs = *data
                .get(p)
                .ok_or_else(|| "truncated ofs-delta reference".to_string())?;
            let (distance, extra) =
                read_ofs_varint(&data[p + 1..], first_ofs)
                    .map_err(|e| format!("bad ofs-delta varint: {e}"))?;
            p += 1 + extra;
            ofs_distance = Some(distance);
            let target = offset.checked_sub(distance).ok_or_else(|| {
                format!("ofs-delta distance {distance} underflows at offset {offset}")
            })?;
            if target < 12 || target >= offset {
                return Err(format!(
                    "ofs-delta at {offset} references out-of-range offset {target} (distance {distance})"
                ));
            }
            base_offset = Some(target);
        }
        GitType::RefDelta => {
            let raw = data
                .get(p..p + 20)
                .ok_or_else(|| "truncated ref-delta base name".to_string())?;
            base_ref = Some(hex::encode(raw));
            p += 20;
        }
        _ => {}
    }

    let data_start = p as u64;
    let (inflated, consumed) = inflate_at(data, p, cap).map_err(|e| {
        if declared_size > cap {
            format!("{e}; declared size {declared_size}")
        } else {
            e
        }
    })?;
    let next_offset = data_start + consumed as u64;
    let inflated_len = inflated.len() as u64;

    let mut hasher = CrcHasher::new();
    hasher.update(&data[start..next_offset as usize]);
    let crc32 = hasher.finalize();

    let mut entry = RawEntry {
        index,
        offset,
        header_len: data_start - offset,
        data_start,
        compressed_len: consumed as u64,
        next_offset,
        kind: Some(kind),
        declared_size,
        ofs_distance,
        base_offset,
        base_ref,
        inflated,
        crc32,
        crc_expected: None,
        crc_ok: None,
        error: None,
    };

    if inflated_len != declared_size {
        entry.error = Some(format!(
            "size spoof: header declares {declared_size} bytes but zlib yielded {inflated_len} at offset {offset}"
        ));
    }
    Ok(entry)
}

impl RawEntry {
    fn error(index: usize, offset: u64, error: String) -> Self {
        RawEntry {
            index,
            offset,
            header_len: 0,
            data_start: 0,
            compressed_len: 0,
            next_offset: offset,
            kind: None,
            declared_size: 0,
            ofs_distance: None,
            base_offset: None,
            base_ref: None,
            inflated: Vec::new(),
            crc32: 0,
            crc_expected: None,
            crc_ok: None,
            error: Some(error),
        }
    }
}

fn fail(msg: &str) -> ParsedPack {
    ParsedPack {
        object_count: 0,
        entries: Vec::new(),
        trailer_expected: String::new(),
        trailer_actual: String::new(),
        trailer_ok: false,
        errors: vec![msg.to_string()],
    }
}
