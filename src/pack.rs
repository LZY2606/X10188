//! Parser for Git pack files (`PACK` v2/v3 containers).
//!
//! Parsing keeps every raw offset that matters for forensic display:
//! object start, end of the entry header, start of the zlib stream, end of
//! the zlib stream, per-entry CRC bytes, ofs distance and resolved base
//! offset. Bad objects are reported with evidence; parsing continues with
//! the next object whenever the zlib boundary is recoverable.

use crate::binformat::{
    crc32_ieee, decode_ofs_distance, decode_pack_header, inflate_zlib, type_name, OBJ_OFS_DELTA,
    OBJ_REF_DELTA,
};
use crate::models::Evidence;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct RawObject {
    pub offset: u64,
    pub header_end: u64,
    pub zlib_start: u64,
    pub zlib_end: u64,
    pub raw_len: u64,
    pub type_id: u8,
    pub type_name: String,
    pub declared_size: u64,
    pub inflated: Vec<u8>,
    pub actual_size: u64,
    pub size_ok: bool,
    pub overran_cap: bool,
    pub crc_actual: u32,
    pub ofs_distance: Option<u64>,
    pub base_offset: Option<i64>,
    pub ofs_in_bounds: bool,
    pub ref_base: Option<[u8; 20]>,
    pub evidence: Vec<Evidence>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub objects: Vec<RawObject>,
    pub trailer_declared: [u8; 20],
    pub checksum_ok: bool,
    pub trailing_bytes: u64,
    pub evidence: Vec<Evidence>,
}

fn u32be(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Parse a complete pack byte buffer. `hard_cap` bounds a single inflated
/// object so a forged size header can never trigger unbounded allocation.
pub fn parse_pack(data: &[u8], hard_cap: usize) -> ParsedPack {
    let mut evidence = Vec::new();

    if data.len() < 32 {
        evidence.push(Evidence::new("pack_too_short", "file shorter than pack header + checksum"));
        return empty_pack(evidence);
    }
    if &data[0..4] != b"PACK" {
        evidence.push(Evidence::new("bad_magic", "missing PACK magic"));
        return empty_pack(evidence);
    }
    let version = u32be(data, 4);
    if version != 2 && version != 3 {
        evidence.push(Evidence::new("bad_version", format!("unsupported pack version {}", version)));
    }
    let count = u32be(data, 8);

    // Whole-pack SHA1 trailer covers everything preceding the final 20 bytes.
    let body_end = data.len() - 20;
    let mut hasher = Sha1::new();
    hasher.update(&data[..body_end]);
    let computed: [u8; 20] = hasher.finalize().into();
    let mut trailer_declared = [0u8; 20];
    trailer_declared.copy_from_slice(&data[body_end..]);
    let checksum_ok = computed == trailer_declared;
    if !checksum_ok {
        evidence.push(Evidence::new(
            "pack_checksum_mismatch",
            format!(
                "pack trailer sha {} does not match computed {}",
                hex::encode(trailer_declared),
                hex::encode(computed)
            ),
        ));
    }

    let mut objects: Vec<RawObject> = Vec::new();
    let mut pos = 12usize;
    let mut fatal_early = false;

    for idx in 0..count {
        if pos >= body_end {
            evidence.push(Evidence::new(
                "pack_truncated",
                format!("object {} starts at/after checksum trailer (pos={})", idx, pos),
            ));
            fatal_early = true;
            break;
        }
        let obj_offset = pos;
        let header = match decode_pack_header(data, pos) {
            Ok(h) => h,
            Err(e) => {
                evidence.push(Evidence::new(
                    "object_header_error",
                    format!("object at offset {}: {}", obj_offset, e),
                ));
                fatal_early = true;
                break;
            }
        };
        let (type_id, declared_size, after_hdr) = header;
        let mut zlib_start = after_hdr;
        let mut ofs_distance = None;
        let mut base_offset: Option<i64> = None;
        let mut ofs_in_bounds = true;
        let mut ref_base = None;
        let mut obj_evidence: Vec<Evidence> = Vec::new();

        if type_id == OBJ_OFS_DELTA {
            match decode_ofs_distance(data, zlib_start) {
                Ok((dist, after)) => {
                    ofs_distance = Some(dist);
                    zlib_start = after;
                    let b = obj_offset as i128 - dist as i128;
                    if b < 0 {
                        ofs_in_bounds = false;
                        obj_evidence.push(Evidence::new(
                            "ofs_before_pack",
                            format!("ofs-delta distance {} points before pack start", dist),
                        ));
                    } else {
                        base_offset = Some(b as i64);
                    }
                }
                Err(e) => {
                    evidence.push(Evidence::new(
                        "ofs_varint_error",
                        format!("object at offset {}: {}", obj_offset, e),
                    ));
                    fatal_early = true;
                    break;
                }
            }
        } else if type_id == OBJ_REF_DELTA {
            if zlib_start + 20 > body_end {
                evidence.push(Evidence::new(
                    "ref_delta_truncated",
                    format!("object at offset {} missing 20-byte base oid", obj_offset),
                ));
                fatal_early = true;
                break;
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[zlib_start..zlib_start + 20]);
            ref_base = Some(oid);
            zlib_start += 20;
        }

        let inflated = match inflate_zlib(data, zlib_start, declared_size, hard_cap) {
            Ok(inf) => inf,
            Err(e) => {
                obj_evidence.push(Evidence::new("zlib_error", e.clone()));
                objects.push(RawObject {
                    offset: obj_offset as u64,
                    header_end: after_hdr as u64,
                    zlib_start: zlib_start as u64,
                    zlib_end: zlib_start as u64,
                    raw_len: 0,
                    type_id,
                    type_name: type_name(type_id),
                    declared_size,
                    inflated: Vec::new(),
                    actual_size: 0,
                    size_ok: false,
                    overran_cap: false,
                    crc_actual: 0,
                    ofs_distance,
                    base_offset,
                    ofs_in_bounds,
                    ref_base,
                    evidence: obj_evidence,
                    parse_error: Some(e),
                });
                evidence.push(Evidence::new(
                    "walk_stopped",
                    format!("cannot locate next object after zlib failure at offset {}", obj_offset),
                ));
                fatal_early = true;
                break;
            }
        };

        let zlib_end = zlib_start + inflated.consumed;
        let mut size_ok = inflated.data.len() as u64 == declared_size;
        if inflated.overran_cap {
            size_ok = false;
            obj_evidence.push(Evidence::new(
                "size_spoof_overrun",
                format!(
                    "header declares {} bytes but stream exceeds hard cap {} bytes",
                    declared_size, hard_cap
                ),
            ));
        } else if !size_ok {
            obj_evidence.push(Evidence::new(
                "size_spoof",
                format!(
                    "header declares {} bytes but zlib produced {} bytes",
                    declared_size,
                    inflated.data.len()
                ),
            ));
        }

        if type_id < 1 || type_id == 5 || type_id > 7 {
            obj_evidence.push(Evidence::new(
                "unknown_type",
                format!("object type id {} is not valid in a pack", type_id),
            ));
        }

        let crc_actual = crc32_ieee(&data[obj_offset..zlib_end]);

        // Validate ofs base points exactly at a previously parsed object.
        if type_id == OBJ_OFS_DELTA && ofs_in_bounds {
            let target = base_offset.unwrap() as u64;
            if !objects.iter().any(|o| o.offset == target) {
                ofs_in_bounds = false;
                obj_evidence.push(Evidence::new(
                    "ofs_out_of_bounds",
                    format!(
                        "ofs-delta at {} claims base at {}, but no object starts there",
                        obj_offset, target
                    ),
                ));
            }
        }

        objects.push(RawObject {
            offset: obj_offset as u64,
            header_end: after_hdr as u64,
            zlib_start: zlib_start as u64,
            zlib_end: zlib_end as u64,
            raw_len: (zlib_end - obj_offset) as u64,
            type_id,
            type_name: type_name(type_id),
            declared_size,
            inflated: inflated.data,
            actual_size: inflated.data.len() as u64,
            size_ok,
            overran_cap: inflated.overran_cap,
            crc_actual,
            ofs_distance,
            base_offset,
            ofs_in_bounds,
            ref_base,
            evidence: obj_evidence,
            parse_error: None,
        });
        pos = zlib_end;
    }

    if !fatal_early {
        if pos != body_end {
            evidence.push(Evidence::new(
                "pack_trailing_bytes",
                format!("{} unparsed byte(s) between last object and checksum", body_end - pos),
            ));
        }
        if objects.len() as u32 != count {
            evidence.push(Evidence::new(
                "object_count_mismatch",
                format!("header declares {} objects, walked {}", count, objects.len()),
            ));
        }
    } else if objects.len() as u32 != count {
        evidence.push(Evidence::new(
            "object_count_mismatch",
            format!("header declares {} objects, recovered {}", count, objects.len()),
        ));
    }

    ParsedPack {
        version,
        count,
        objects,
        trailer_declared,
        checksum_ok,
        trailing_bytes: body_end.saturating_sub(pos.max(12).min(body_end)) as u64,
        evidence,
    }
}

fn empty_pack(evidence: Vec<Evidence>) -> ParsedPack {
    ParsedPack {
        version: 0,
        count: 0,
        objects: Vec::new(),
        trailer_declared: [0u8; 20],
        checksum_ok: false,
        trailing_bytes: 0,
        evidence,
    }
}
