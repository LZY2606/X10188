//! Structural parsing of Git `.pack` files and `.idx` files.
//!
//! Only the *structure* is examined here: object bodies are kept as zlib
//! regions with raw offsets; materialization happens in [`crate::engine`].

use anyhow::{bail, Result};
use serde::Serialize;

use crate::gitfmt::{parse_ofs_delta_offset, parse_size_encoding, ObjType, OID_LEN};

pub const PACK_SIG: [u8; 4] = *b"PACK";
pub const IDX_SIG: [u8; 4] = *b"\xfftOc";

/// One structural entry located inside a pack.
#[derive(Debug, Clone, Serialize)]
pub struct PackEntry {
    /// Offset of the entry header from the start of the pack.
    pub offset: u64,
    pub obj_type: Option<ObjType>,
    pub type_name: String,
    /// Uncompressed size declared by the entry header.
    pub declared_size: u64,
    /// For ofs-delta: absolute offset of the claimed base (after validation).
    pub ofs_base_offset: Option<u64>,
    /// Raw negative-distance value encoded in an ofs-delta header.
    pub ofs_distance: Option<u64>,
    /// For ref-delta: the 20-byte base object id.
    pub ref_base_oid: Option<String>,
    /// Span `[data_start, data_end)` of the compressed zlib stream.
    pub data_start: usize,
    pub data_end: usize,
    /// Whether the zlib stream terminated cleanly at data_end.
    pub inflate_ok: bool,
    /// Actual decompressed size (None if inflate failed).
    pub inflated_size: Option<u64>,
    /// Parse error localized to this entry (other entries still parsed).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackSummary {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// Offset where object data ends / 20-byte trailing checksum begins.
    pub trailer_offset: usize,
    pub trailer_oid: String,
    pub pack_len: usize,
    pub errors: Vec<String>,
}

fn u32_be(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// Parse the full pack structure, isolating per-entry decompression failures.
pub fn parse_pack(bytes: &[u8], inflate_cap: usize) -> Result<PackSummary> {
    if bytes.len() < 12 + OID_LEN {
        bail!("pack too small: {} bytes", bytes.len());
    }
    if bytes[0..4] != PACK_SIG {
        bail!("bad PACK signature");
    }
    let version = u32_be(bytes, 4);
    if !(2..=4).contains(&version) {
        bail!("unsupported pack version {version}");
    }
    let count = u32_be(bytes, 8);

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut pos = 12usize;
    let trailer_reserve = OID_LEN;
    let mut fatal: Option<String> = None;

    for idx in 0..count as usize {
        if pos >= bytes.len() - trailer_reserve {
            fatal = Some(format!("entry {idx}: ran past pack body at offset {pos}"));
            break;
        }
        let entry_start = pos;
        let first = bytes[pos];
        pos += 1;
        let code = (first >> 4) & 0x07;
        let obj_type = ObjType::from_pack_code(code);
        let mut size: u64 = (first & 0x0f) as u64;
        let mut shift = 4u32;
        let mut header_ok = first & 0x80 == 0;
        while !header_ok {
            if pos >= bytes.len() - trailer_reserve {
                fatal = Some(format!("entry {idx}: truncated size header at {pos}"));
                break;
            }
            let b = bytes[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                header_ok = true;
            }
        }
        if fatal.is_some() {
            break;
        }

        let mut ofs_base = None;
        let mut ofs_distance = None;
        let mut ref_oid = None;

        if let Some(ObjType::OfsDelta) = obj_type {
            match parse_ofs_delta_offset(&bytes[pos..]) {
                Ok((dist, used)) => {
                    pos += used;
                    ofs_distance = Some(dist);
                    ofs_base = (entry_start as u64).checked_sub(dist);
                    if ofs_base.is_none() {
                        errors.push(format!(
                            "entry at {entry_start}: ofs-delta distance {dist} overflows before pack start"
                        ));
                    }
                }
                Err(e) => {
                    fatal = Some(format!("entry {idx} at {entry_start}: {e}"));
                    break;
                }
            }
        } else if let Some(ObjType::RefDelta) = obj_type {
            if pos + OID_LEN > bytes.len() - trailer_reserve {
                fatal = Some(format!("entry {idx}: truncated ref-delta oid"));
                break;
            }
            ref_oid = Some(hex::encode(&bytes[pos..pos + OID_LEN]));
            pos += OID_LEN;
        } else if obj_type.is_none() {
            // Illegal type code: record a quarantined entry, attempt to skip
            // impossible safely -> treat as fatal structural break.
            fatal = Some(format!(
                "entry {idx} at {entry_start}: unknown pack object type code {code}"
            ));
            break;
        }

        let data_start = pos;
        let outcome = crate::gitfmt::inflate_zlib(&bytes[pos..], inflate_cap);
        let mut entry = PackEntry {
            offset: entry_start as u64,
            obj_type,
            type_name: obj_type
                .map(|t| t.name().to_string())
                .unwrap_or_else(|| format!("type{code}")),
            declared_size: size,
            ofs_base_offset: ofs_base,
            ofs_distance,
            ref_base_oid: ref_oid,
            data_start,
            data_end: pos,
            inflate_ok: false,
            inflated_size: None,
            error: None,
        };

        match outcome {
            Ok(dec) => {
                entry.data_end = data_start + dec.consumed;
                pos = entry.data_end;
                entry.inflate_ok = true;
                entry.inflated_size = Some(dec.data.len() as u64);
                if dec.data.len() as u64 != size {
                    let msg = format!(
                        "entry at {entry_start}: declared size {size} but inflated to {} bytes (size spoof)",
                        dec.data.len()
                    );
                    entry.error = Some(msg.clone());
                    errors.push(msg);
                }
            }
            Err(e) => {
                let msg = format!("entry at {entry_start}: inflate failed: {e}");
                entry.error = Some(msg.clone());
                errors.push(msg);
                // Cannot trust stream boundary: structural scan must stop.
                fatal = Some(format!("cannot locate next entry after {entry_start}: {e}"));
                entries.push(entry);
                break;
            }
        }
        entries.push(entry);
    }

    let trailer_offset = pos;
    let mut trailer_oid = String::new();
    if trailer_offset + OID_LEN <= bytes.len() {
        trailer_oid = hex::encode(&bytes[trailer_offset..trailer_offset + OID_LEN]);
        let computed = crate::gitfmt::sha1_bytes(&bytes[..trailer_offset]);
        if hex::encode(computed) != trailer_oid {
            errors.push(format!(
                "pack trailer checksum mismatch: stored {trailer_oid}, computed {}",
                hex::encode(computed)
            ));
        }
        let extra = bytes.len() - (trailer_offset + OID_LEN);
        if extra != 0 {
            errors.push(format!("{extra} trailing byte(s) after pack checksum"));
        }
    } else {
        errors.push("pack truncated before 20-byte checksum trailer".to_string());
    }
    if entries.len() != count as usize {
        errors.push(format!(
            "header declares {count} objects but only {} were structurally parsed",
            entries.len()
        ));
    }
    if let Some(f) = fatal {
        errors.push(format!("structural scan stopped: {f}"));
    }

    Ok(PackSummary {
        version,
        count,
        entries,
        trailer_offset,
        trailer_oid,
        pack_len: bytes.len(),
        errors,
    })
}

/// One row of a parsed `.idx` (offsets & per-entry CRC32 for v2).
#[derive(Debug, Clone, Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdxSummary {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub idx_checksum: String,
    pub errors: Vec<String>,
}

/// Parse a v1 or v2 pack index with fanout/CRC validation.
pub fn parse_idx(bytes: &[u8]) -> Result<IdxSummary> {
    if bytes.len() < 8 {
        bail!("idx too small");
    }
    let mut errors = Vec::new();
    let (version, off) = if bytes[0..4] == IDX_SIG {
        let v = u32_be(bytes, 4);
        if v != 2 {
            bail!("unsupported idx version {v}");
        }
        (2u32, 8usize)
    } else {
        (1u32, 0usize)
    };

    // 256 fanout entries.
    if off + 256 * 4 > bytes.len() {
        bail!("idx truncated in fanout table");
    }
    let fanout: Vec<u32> = (0..256).map(|i| u32_be(bytes, off + i * 4)).collect();
    let total = fanout[255];
    let mut prev = 0u32;
    for (i, &f) in fanout.iter().enumerate() {
        if f < prev {
            errors.push(format!("fanout bucket {i} decreases ({prev} -> {f})"));
        }
        prev = f;
    }

    if version == 2 {
        let n = total as usize;
        let oid_off = off + 256 * 4;
        let crc_off = oid_off + n * OID_LEN;
        let off32_off = crc_off + n * 4;
        let large_off = off32_off + n * 4;
        let need = large_off + OID_LEN * 2;
        if need > bytes.len() {
            bail!("idx v2 truncated (need {need}, have {})", bytes.len());
        }
        let mut entries = Vec::with_capacity(n);
        let mut last_oid = String::new();
        for i in 0..n {
            let oid = hex::encode(&bytes[oid_off + i * OID_LEN..oid_off + (i + 1) * OID_LEN]);
            if oid <= last_oid {
                errors.push(format!("idx oid table not strictly sorted at row {i}"));
            }
            last_oid = oid.clone();
            let crc = u32::from_be_bytes([
                bytes[crc_off + i * 4],
                bytes[crc_off + i * 4 + 1],
                bytes[crc_off + i * 4 + 2],
                bytes[crc_off + i * 4 + 3],
            ]);
            let raw_off = u32_be(bytes, off32_off + i * 4);
            let offset = if raw_off & 0x8000_0000 != 0 {
                let idx64 = (raw_off & 0x7fff_ffff) as usize;
                let p = large_off + idx64 * 8;
                if p + 8 > bytes.len() {
                    bail!("idx v2 64-bit offset table overflow");
                }
                u64::from_be_bytes(bytes[p..p + 8].try_into().unwrap())
            } else {
                raw_off as u64
            };
            entries.push(IdxEntry {
                oid,
                offset,
                crc32: Some(crc),
            });
        }
        let pack_checksum = hex::encode(&bytes[large_off..large_off + OID_LEN]);
        let idx_checksum = hex::encode(&bytes[large_off + OID_LEN..large_off + 2 * OID_LEN]);
        validate_idx_trailer(bytes, large_off, &pack_checksum, &idx_checksum, &mut errors);
        Ok(IdxSummary {
            version,
            fanout,
            entries,
            pack_checksum,
            idx_checksum,
            errors,
        })
    } else {
        // v1: 256 fanout then n * (4 offset + 20 oid) records.
        let n = total as usize;
        let rec_off = off + 256 * 4;
        let need = rec_off + n * (4 + OID_LEN) + 2 * OID_LEN;
        if need > bytes.len() {
            bail!("idx v1 truncated (need {need}, have {})", bytes.len());
        }
        let mut entries = Vec::with_capacity(n);
        let mut last_oid = String::new();
        for i in 0..n {
            let base = rec_off + i * (4 + OID_LEN);
            let offset = u32_be(bytes, base) as u64;
            let oid = hex::encode(&bytes[base + 4..base + 4 + OID_LEN]);
            if oid <= last_oid {
                errors.push(format!("idx v1 oid table not strictly sorted at row {i}"));
            }
            last_oid = oid.clone();
            entries.push(IdxEntry { oid, offset, crc32: None });
        }
        let cks = rec_off + n * (4 + OID_LEN);
        let pack_checksum = hex::encode(&bytes[cks..cks + OID_LEN]);
        let idx_checksum = hex::encode(&bytes[cks + OID_LEN..cks + 2 * OID_LEN]);
        validate_idx_trailer(bytes, cks, &pack_checksum, &idx_checksum, &mut errors);
        Ok(IdxSummary {
            version,
            fanout,
            entries,
            pack_checksum,
            idx_checksum,
            errors,
        })
    }
}

fn validate_idx_trailer(
    bytes: &[u8],
    before_pack_sum: usize,
    pack_checksum: &str,
    idx_checksum: &str,
    errors: &mut Vec<String>,
) {
    let computed_idx = crate::gitfmt::sha1_bytes(&bytes[..before_pack_sum + OID_LEN]);
    if hex::encode(computed_idx) != idx_checksum {
        errors.push(format!(
            "idx self-checksum mismatch: stored {idx_checksum}, computed {}",
            hex::encode(computed_idx)
        ));
    }
    let _ = pack_checksum;
}

/// Recompute the v2 per-entry CRC32 for an entry span in a pack:
/// checksum covers the packed entry from its header byte through zlib end.
pub fn crc32_of_span(pack: &[u8], start: u64, end: usize) -> u32 {
    crc32fast::hash(&pack[start as usize..end])
}
