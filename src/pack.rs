//! Parser for Git pack files (version 2), sequential / index-free.
//!
//! The scanner walks objects in on-disk order purely from the pack bytes, so a
//! pack can be analysed even when its `.idx` is missing or mismatched. Every
//! object keeps its original byte offset and its compressed payload range.

use crate::error::{Error, Result};
use crate::git::GitType;
use crate::models::Issue;
use crate::oid::Oid;
use crate::zlib;

/// Magic + version of an idx v2 file (`\xff t O c`, then 0x00000002).
pub const IDX_V2_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";

/// Upper bound on a single inflated object during parsing. Above this we flag
/// a size lie / decompression bomb and keep only the guard byte.
pub const PARSE_HARD_CAP: usize = 256 * 1024 * 1024;

/// Base reference carried by a delta entry header.
#[derive(Clone, Debug)]
pub enum DeltaRef {
    /// Negative-offset delta: absolute byte offset of the base within the pack.
    Offset(usize),
    /// Thin/ref delta: the 20-byte object id of the base.
    Oid(Oid),
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    /// 0-based ordinal in on-disk order.
    pub ordinal: usize,
    /// Absolute offset of the entry header in the pack.
    pub offset: usize,
    /// Offset of the first compressed payload byte (after header/base ref).
    pub payload_offset: usize,
    /// Pack-declared inflated size (from the entry header).
    pub declared_size: u64,
    pub obj_type: GitType,
    /// Set for ref/ofs deltas.
    pub base_ref: Option<DeltaRef>,
    /// Inflated payload (canonical body for leaves, delta instructions for
    /// deltas). Capped to PARSE_HARD_CAP+1 on a size lie.
    pub data: Vec<u8>,
    /// Actual inflated byte length (may exceed data.len() when capped).
    pub inflated_len: u64,
    /// Number of compressed payload bytes consumed by the zlib stream.
    pub compressed_len: usize,
    /// Whether the zlib stream terminated cleanly.
    pub stream_finished: bool,
    /// Whether inflation exceeded the hard cap.
    pub over_cap: bool,
    /// Evidence gathered for this entry.
    pub issues: Vec<Issue>,
}

impl PackEntry {
    pub fn is_delta(&self) -> bool {
        matches!(self.obj_type, GitType::OfsDelta | GitType::RefDelta)
    }
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    /// Offset just past the final object / start of the 20-byte checksum.
    pub trailer_offset: Option<usize>,
    /// Stored 20-byte pack checksum (SHA-1 of all preceding pack bytes).
    pub stored_checksum: Option<Oid>,
    /// True when the stored checksum matches the recomputed one.
    pub checksum_ok: bool,
    pub pack_len: usize,
    pub issues: Vec<Issue>,
}

fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Read the n-byte size/type header at `pos`.
/// Returns (type, size, new_pos).
fn read_entry_header(buf: &[u8], pos: usize) -> Result<(GitType, u64, usize)> {
    let first = *buf.get(pos).ok_or_else(|| Error::Format("truncated entry header".into()))?;
    let code = (first >> 4) & 0x7;
    let obj_type = GitType::from_pack_code(code)
        .ok_or_else(|| Error::Format(format!("invalid pack object type {code}")))?;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4;
    let mut p = pos + 1;
    let mut b = first;
    while b & 0x80 != 0 {
        b = *buf.get(p).ok_or_else(|| Error::Format("truncated size continuation".into()))?;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        p += 1;
    }
    Ok((obj_type, size, p))
}

/// Decode the ofs-delta base offset; `pos` points at the first ofs byte.
/// Returns (negative_distance, new_pos).
fn read_ofs_distance(buf: &[u8], pos: usize) -> Result<(usize, usize)> {
    let mut p = pos;
    let mut b = *buf.get(p).ok_or_else(|| Error::Format("truncated ofs-delta byte".into()))?;
    let mut dist: usize = (b & 0x7f) as usize;
    p += 1;
    while b & 0x80 != 0 {
        b = *buf.get(p).ok_or_else(|| Error::Format("truncated ofs-delta continuation".into()))?;
        dist = ((dist + 1) << 7) | (b & 0x7f) as usize;
        p += 1;
    }
    Ok((dist, p))
}

/// Parse an entire pack buffer sequentially. Per-object failures are captured
/// as issues; parsing stops at the first unrecoverable *structural* error.
pub fn parse_pack(buf: &[u8]) -> Result<ParsedPack> {
    let mut issues = Vec::new();
    if buf.len() < 12 {
        return Err(Error::Format("pack shorter than 12-byte header".into()));
    }
    if buf[0..4] != PACK_SIGNATURE {
        return Err(Error::Format("missing PACK signature".into()));
    }
    let version = rd_u32(buf, 4);
    if version != 2 {
        return Err(Error::Format(format!("unsupported pack version {version}")));
    }
    let declared_count = rd_u32(buf, 8);

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut pos = 12usize;
    let mut aborted: Option<String> = None;

    for ordinal in 0..declared_count as usize {
        let entry_offset = pos;
        let head = match read_entry_header(buf, pos) {
            Ok(h) => h,
            Err(e) => {
                aborted = Some(e.to_string());
                break;
            }
        };
        let (obj_type, declared_size, after_size) = head;
        let mut p = after_size;
        let mut base_ref = None;

        if matches!(obj_type, GitType::OfsDelta) {
            match read_ofs_distance(buf, p) {
                Ok((dist, np)) => {
                    if dist > entry_offset {
                        issues.push(Issue::error(
                            "ofs_out_of_bounds",
                            format!("ofs-delta distance {dist} >= entry offset {entry_offset}"),
                        ));
                    } else {
                        base_ref = Some(DeltaRef::Offset(entry_offset - dist));
                    }
                    p = np;
                }
                Err(e) => {
                    aborted = Some(e.to_string());
                    break;
                }
            }
        } else if matches!(obj_type, GitType::RefDelta) {
            if p + 20 > buf.len() {
                aborted = Some("truncated ref-delta base oid".into());
                break;
            }
            base_ref = Some(DeltaRef::Oid(Oid::from_bytes(&buf[p..p + 20]).unwrap()));
            p += 20;
        }

        let payload_offset = p;
        let mut entry_issues: Vec<Issue> = Vec::new();
        let inf = match zlib::inflate(buf, payload_offset, PARSE_HARD_CAP) {
            Ok(v) => v,
            Err(e) => {
                entry_issues.push(Issue::error("zlib", e.to_string()));
                entries.push(PackEntry {
                    ordinal,
                    offset: entry_offset,
                    payload_offset,
                    declared_size,
                    obj_type,
                    base_ref,
                    data: Vec::new(),
                    inflated_len: 0,
                    compressed_len: 0,
                    stream_finished: false,
                    over_cap: false,
                    issues: entry_issues,
                });
                aborted = Some(format!("cannot locate object boundary at offset {payload_offset}"));
                break;
            }
        };

        if inf.over_cap {
            entry_issues.push(Issue::error(
                "size_bomb",
                format!(
                    "inflated content exceeds hard cap {} bytes (declared {})",
                    PARSE_HARD_CAP, declared_size
                ),
            ));
        }
        if inf.finished && (inf.data.len() as u64) != declared_size {
            entry_issues.push(Issue::error(
                "size_lie",
                format!(
                    "header declares {declared_size} bytes but zlib stream produced {} bytes",
                    inf.data.len()
                ),
            ));
        }

        let next_pos = payload_offset + inf.consumed;
        entries.push(PackEntry {
            ordinal,
            offset: entry_offset,
            payload_offset,
            declared_size,
            obj_type,
            base_ref,
            data: inf.data,
            inflated_len: 0, // filled below (truncated guard aware)
            compressed_len: inf.consumed,
            stream_finished: inf.finished,
            over_cap: inf.over_cap,
            issues: entry_issues,
        });
        // Record true inflated length: capped retention + guard byte.
        let e = entries.last_mut().unwrap();
        e.inflated_len = e.data.len() as u64;
        pos = next_pos;
    }

    // 20-byte SHA-1 checksum trailer.
    let (trailer_offset, stored_checksum, checksum_ok) = if aborted.is_none() && entries.len() == declared_count as usize {
        let start = pos;
        if start + 20 <= buf.len() {
            let stored = Oid::from_bytes(&buf[start..start + 20]).unwrap();
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(&buf[..start]);
            let mut calc = [0u8; 20];
            calc.copy_from_slice(&h.finalize().as_slice());
            let ok = calc == stored.0;
            if !ok {
                issues.push(Issue::error(
                    "pack_checksum",
                    format!(
                        "pack checksum mismatch: stored {} computed {}",
                        stored.hex(),
                        Oid(calc).hex()
                    ),
                ));
            }
            (Some(start), Some(stored), ok)
        } else {
            issues.push(Issue::error("pack_trailer", "pack truncated before checksum".into()));
            (None, None, false)
        }
    } else {
        issues.push(Issue::error(
            "scan_aborted",
            format!(
                "sequential scan stopped after {}/{} objects: {}",
                entries.len(),
                declared_count,
                aborted.unwrap_or_else(|| "inconsistent object count".into())
            ),
        ));
        (None, None, false)
    };

    Ok(ParsedPack {
        version,
        declared_count,
        entries,
        trailer_offset,
        stored_checksum,
        checksum_ok,
        pack_len: buf.len(),
        issues,
    })
}
