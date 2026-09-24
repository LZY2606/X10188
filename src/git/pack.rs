//! Pure-Rust parser for `PACK` v2 files.
//!
//! No system git is involved. Every object keeps its raw byte range and
//! compressed range; inflated payloads are returned alongside per-entry fault
//! information so one bad object never aborts the scan.

use sha1::{Digest, Sha1};

use super::crc::crc32;
use super::inflate::inflate_once;
use super::types::{EntryKind, Fault, ObjectType};
use super::varint;

pub const MAGIC: [u8; 4] = *b"PACK";

#[derive(Clone, Debug)]
pub struct PackHeader {
    pub version: u32,
    pub object_count: u32,
    /// Byte offset where the first object begins (always 12).
    pub data_start: usize,
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    /// Offset of the entry's first header byte.
    pub offset: usize,
    pub kind: EntryKind,
    pub object_type: Option<ObjectType>,
    /// Declared inflated size from the entry header.
    pub declared_size: u64,
    /// `[start, end)` range of the (possibly multi-byte) object header,
    /// including the ref-delta 20 bytes / ofs varint.
    pub header_range: (usize, usize),
    /// `[start, end)` range of the compressed zlib member.
    pub compressed_range: (usize, usize),
    /// Bytes of the whole on-disk entry (`header` + zlib member).
    pub raw_len: usize,
    /// For ofs-delta: how many bytes backwards the base entry begins.
    pub negative_offset: Option<u64>,
    /// For ref-delta: claimed base object id.
    pub ref_base: Option<[u8; 20]>,
    /// Inflated payload (base content or raw delta bytes).
    pub data: Option<Vec<u8>>,
    /// CRC32 of the raw on-disk entry bytes (header + zlib member).
    pub crc: u32,
    /// Permanent fault detected while parsing this entry, if any.
    pub fault: Option<Fault>,
}

impl PackEntry {
    pub fn is_delta(&self) -> bool {
        matches!(self.kind, EntryKind::OfsDelta | EntryKind::RefDelta)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ParsedPack {
    pub header: Option<PackHeader>,
    pub entries: Vec<PackEntry>,
    /// Fatal faults that apply to the whole file.
    pub file_faults: Vec<Fault>,
    /// Whether the 20-byte SHA1 trailer matches everything before it.
    pub trailer_ok: bool,
    pub file_len: usize,
    /// Offset of the 20-byte trailer.
    pub trailer_offset: usize,
}

/// Parses an entire pack.
///
/// * `hints` — object offsets from a companion index, sorted ascending. When
///   present, scanning resynchronises on the next hint after a corrupt entry;
///   when absent, scanning proceeds sequentially and stops at the first fault.
/// * `inflate_ceiling` — maximum bytes any single inflated member may occupy.
pub fn parse_pack(bytes: &[u8], hints: Option<&[u64]>, inflate_ceiling: usize) -> ParsedPack {
    let mut parsed = ParsedPack {
        file_len: bytes.len(),
        ..Default::default()
    };

    if bytes.len() < 32 {
        parsed.file_faults.push(Fault::Truncated);
        return parsed;
    }
    if bytes[0..4] != MAGIC {
        parsed.file_faults.push(Fault::BadMagic);
        return parsed;
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let object_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    if version != 2 {
        parsed.file_faults.push(Fault::BadVersion(version));
    }
    parsed.header = Some(PackHeader {
        version,
        object_count,
        data_start: 12,
    });

    parsed.trailer_offset = bytes.len() - 20;
    let mut sha = Sha1::new();
    sha.update(&bytes[..parsed.trailer_offset]);
    let want: [u8; 20] = sha.finalize().into();
    parsed.trailer_ok = want == bytes[parsed.trailer_offset..];
    if !parsed.trailer_ok {
        parsed.file_faults.push(Fault::PackChecksumMismatch);
    }

    // Offsets we are allowed to start an entry at.
    let mut hints: Vec<u64> = hints.map(|h| h.to_vec()).unwrap_or_default();
    hints.sort_unstable();
    hints.dedup();

    let mut pos = 12usize;
    let mut guard = 0usize;
    while pos < parsed.trailer_offset {
        guard += 1;
        if guard as u64 > object_count as u64 + 2 {
            parsed.file_faults.push(Fault::TooManyObjects);
            break;
        }
        match parse_entry(bytes, pos, inflate_ceiling) {
            Ok(entry) => {
                let next = pos + entry.raw_len;
                parsed.entries.push(entry);
                if next <= pos || next > parsed.trailer_offset {
                    break;
                }
                pos = next;
            }
            Err((fault, consumed)) => {
                // Record a fault shell so the bad object is isolated and
                // visible, then try to resynchronise on the next hint.
                parsed.entries.push(PackEntry {
                    offset: pos,
                    kind: EntryKind::Base(ObjectType::Blob),
                    object_type: None,
                    declared_size: 0,
                    header_range: (pos, pos.saturating_add(consumed)),
                    compressed_range: (0, 0),
                    raw_len: consumed.max(1),
                    negative_offset: None,
                    ref_base: None,
                    data: None,
                    crc: 0,
                    fault: Some(fault),
                });
                let next_hint = hints
                    .iter()
                    .copied()
                    .find(|off| *off as usize > pos);
                match next_hint {
                    Some(off) if (off as usize) < parsed.trailer_offset => {
                        pos = off as usize;
                    }
                    _ => break,
                }
            }
        }
    }

    parsed
}

/// Parses one entry starting at `start`. Returns the entry or
/// `Err((fault, header_bytes_consumed))`.
pub fn parse_entry(
    bytes: &[u8],
    start: usize,
    inflate_ceiling: usize,
) -> Result<PackEntry, (Fault, usize)> {
    let trailer = bytes.len() - 20;
    let mut pos = start;
    let first = *bytes.get(pos).ok_or((Fault::Truncated, 0))?;
    // type is bits 6..4 of the first byte.
    let type_id = (first >> 4) & 0b111;
    let mut declared = u64::from(first & 0x0f);
    let mut shift = 4u32;
    pos += 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *bytes.get(pos).ok_or((Fault::Truncated, pos - start))?;
        pos += 1;
        declared |= u64::from(cur & 0x7f) << shift;
        shift += 7;
    }

    let kind = match type_id {
        1 => EntryKind::Base(ObjectType::Commit),
        2 => EntryKind::Base(ObjectType::Tree),
        3 => EntryKind::Base(ObjectType::Blob),
        4 => EntryKind::Base(ObjectType::Tag),
        5 => {
            return Err((Fault::ReservedType, pos - start));
        }
        6 => EntryKind::OfsDelta,
        7 => EntryKind::RefDelta,
        other => return Err((Fault::UnknownType(other), pos - start)),
    };

    let object_type = match kind {
        EntryKind::Base(t) => Some(t),
        _ => None,
    };

    let mut negative_offset = None;
    let mut ref_base = None;

    if kind == EntryKind::OfsDelta {
        let (neg, n) = varint::read_ofs(&bytes[pos..])
            .ok_or((Fault::Truncated, pos - start))?;
        pos += n;
        negative_offset = Some(neg);
    } else if kind == EntryKind::RefDelta {
        if pos + 20 > trailer {
            return Err((Fault::Truncated, pos - start));
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[pos..pos + 20]);
        pos += 20;
        ref_base = Some(id);
    }

    let header_end = pos;
    let compressed_start = pos;

    // A ofs pointing before the pack start is a permanent structural fault.
    if let Some(neg) = negative_offset {
        if neg as usize > start {
            return Err((
                Fault::OfsOutOfBounds {
                    negative_offset: neg,
                },
                header_end - start,
            ));
        }
    }

    let inflated = inflate_once(&bytes[compressed_start..trailer], inflate_ceiling);
    let mut fault = None;
    let data = match inflated {
        Ok(inf) => {
            // Detect declared-size spoofing. Inflated length is ground truth.
            if inf.data.len() as u64 != declared {
                fault = Some(Fault::SizeSpoof {
                    declared,
                    inflated: inf.data.len() as u64,
                });
            }
            Some(inf.data)
        }
        Err(msg) => {
            fault = Some(Fault::InflateError(msg));
            None
        }
    };
    let consumed = match &fault {
        // On inflate failure we cannot know the stream boundary.
        Some(_) => 0,
        None => 0, // replaced below
    };
    let _ = consumed;

    // Recompute consumed cleanly.
    let (compressed_end, raw_len) = match fault {
        Some(Fault::SizeSpoof { .. }) | None => {
            // Safe unwrap: None fault implies inflation succeeded.
            let inf = inflate_once(&bytes[compressed_start..trailer], inflate_ceiling).ok();
            match inf {
                Some(inf) => (compressed_start + inf.consumed, inf.consumed + (header_end - start)),
                None => (compressed_start, header_end - start),
            }
        }
        Some(_) => (compressed_start, header_end - start),
    };

    let crc = crc32(&bytes[start..start + raw_len.max(1)]);

    Ok(PackEntry {
        offset: start,
        kind,
        object_type,
        declared_size: declared,
        header_range: (start, header_end),
        compressed_range: (compressed_start, compressed_end),
        raw_len,
        negative_offset,
        ref_base,
        data,
        crc,
        fault,
    })
}
