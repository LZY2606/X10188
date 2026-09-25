use crate::gitobj::ObjType;
use crate::oid::Oid;
use crate::zlib;
use serde::{Deserialize, Serialize};

/// Size-spoof detection slack: the real inflated payload must not exceed the
/// declared size by more than this many bytes.
pub const SIZE_SLACK: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackHeader {
    pub version: u32,
    pub num_objects: u32,
    pub header_end: usize,
    pub trailer_offset: Option<usize>,
    pub trailer_sha: Option<Oid>,
    pub trailer_ok: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackEntry {
    pub index: usize,
    /// Offset of the entry header byte.
    pub offset: u64,
    /// Offset of the first byte after the compressed stream.
    pub data_end: u64,
    pub kind: ObjType,
    pub declared_size: u64,
    /// ofs-delta: negative distance to the base entry.
    pub ofs_distance: Option<u64>,
    /// ofs-delta: absolute offset of the base.
    pub ofs_base_offset: Option<u64>,
    /// ref-delta: base object name.
    pub ref_base_oid: Option<Oid>,
    /// Raw inflated payload: object content or delta instructions.
    pub payload_len: usize,
    /// Parsing error isolated to this entry, if any.
    pub error: Option<String>,
    /// 1-based index into the .idx CRC table (when supplied).
    pub idx_position: Option<usize>,
    pub idx_crc: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedPack {
    pub header: PackHeader,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<String>,
    /// Inflated payload for every entry whose zlib stream parsed (including
    /// errored ones, where available). Indexed by entry index.
    #[serde(skip)]
    pub payloads: Vec<Option<Vec<u8>>>,
}

/// Decode the pack object-entry header: type + size little-endian base-128.
fn read_entry_header(buf: &[u8], pos: usize) -> Option<(ObjType, u64, usize)> {
    let b0 = *buf.get(pos)?;
    let kind = ObjType::from_pack_code((b0 >> 4) & 0x7)?;
    let mut size = (b0 & 0x0f) as u64;
    let mut shift = 4;
    let mut p = pos + 1;
    let mut c = b0;
    while c & 0x80 != 0 {
        c = *buf.get(p)?;
        p += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
    }
    Some((kind, size, p))
}

/// Decode an ofs-delta offset (big-endian-ish base-128) and return
/// (negative-distance, new position).
pub fn read_ofs_offset(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut c = *buf.get(pos)?;
    pos += 1;
    let mut ofs = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *buf.get(pos)?;
        pos += 1;
        ofs = ofs.wrapping_add(1).wrapping_shl(7).wrapping_add((c & 0x7f) as u64);
    }
    Some((ofs, pos))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedIdx {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_sha: Option<Oid>,
    pub idx_sha_ok: Option<bool>,
    pub errors: Vec<String>,
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse a v2 .idx file, including fanout table and per-object CRC32.
pub fn parse_idx(data: &[u8]) -> ParsedIdx {
    let mut errors = Vec::new();
    let need_magic = data.len() >= 8 && &data[..4] == b"\xfftOc";
    let version = if need_magic {
        read_u32(&data[4..8])
    } else {
        1
    };
    if version != 2 {
        return ParsedIdx {
            version,
            fanout: vec![],
            entries: vec![],
            pack_sha: None,
            idx_sha_ok: None,
            errors: vec!["only pack idx v2 is supported".into()],
        };
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let o = 8 + i * 4;
        if o + 4 > data.len() {
            errors.push("fanout table truncated".into());
            return ParsedIdx { version, fanout, entries: vec![], pack_sha: None, idx_sha_ok: None, errors };
        }
        fanout.push(read_u32(&data[o..o + 4]));
    }
    let n = *fanout.last().unwrap() as usize;
    let oid_off = 8 + 256 * 4;
    let crc_off = oid_off + n * 20;
    let ofs_off = crc_off + n * 4;
    let large_off = ofs_off + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        if oid_off + i * 20 + 20 > data.len() {
            errors.push(format!("oid table truncated at entry {}", i));
            break;
        }
        let oid = match Oid::from_bytes(&data[oid_off + i * 20..oid_off + i * 20 + 20]) {
            Some(o) => o,
            None => continue,
        };
        if crc_off + i * 4 + 4 > data.len() {
            errors.push(format!("crc table truncated at entry {}", i));
            break;
        }
        let crc32 = read_u32(&data[crc_off + i * 4..crc_off + i * 4 + 4]);
        if ofs_off + i * 4 + 4 > data.len() {
            errors.push(format!("offset table truncated at entry {}", i));
            break;
        }
        let raw = read_u32(&data[ofs_off + i * 4..ofs_off + i * 4 + 4]);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let lo = large_off + idx * 8;
            if lo + 8 > data.len() {
                errors.push(format!("large-offset table truncated at entry {}", i));
                break;
            }
            u64::from_be_bytes(data[lo..lo + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha_off = large_off;
    let pack_sha = if entries.len() == n && pack_sha_off + 20 <= data.len() {
        Oid::from_bytes(&data[pack_sha_off..pack_sha_off + 20])
    } else {
        None
    };
    let idx_sha_ok = if data.len() >= 40 {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&data[..data.len() - 20]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&h.finalize());
        Some(Oid(out) == Oid::from_bytes(&data[data.len() - 20..]).unwrap_or(Oid::zero()))
    } else {
        None
    };
    if let Some(false) = idx_sha_ok {
        errors.push("idx trailing checksum mismatch".into());
    }
    ParsedIdx { version, fanout, entries, pack_sha, idx_sha_ok, errors }
}

/// Parse a pack file. When `idx` is present its offsets/CRCs bound and verify
/// entries; damaged entries are isolated rather than aborting the whole scan.
pub fn parse_pack(data: &[u8], idx: Option<&ParsedIdx>) -> ParsedPack {
    let mut errors = Vec::new();
    if data.len() < 12 || &data[..4] != b"PACK" {
        return ParsedPack {
            header: PackHeader {
                version: 0,
                num_objects: 0,
                header_end: 0,
                trailer_offset: None,
                trailer_sha: None,
                trailer_ok: None,
            },
            entries: vec![],
            payloads: vec![],
            errors: vec!["missing PACK signature".into()],
        };
    }
    let version = read_u32(&data[4..8]);
    let num_objects = read_u32(&data[8..12]);
    if version != 2 {
        errors.push(format!("unsupported pack version {}", version));
    }

    // Map offset -> idx position/crc, sorted by offset.
    let mut by_offset: Vec<(u64, usize, u32, Oid)> = idx
        .map(|ix| {
            ix.entries
                .iter()
                .enumerate()
                .map(|(i, e)| (e.offset, i + 1, e.crc32, e.oid))
                .collect()
        })
        .unwrap_or_default();
    by_offset.sort_unstable();

    let mut entries = Vec::new();
    let mut payloads: Vec<Option<Vec<u8>>> = Vec::new();
    let mut pos = 12usize;
    let mut scan_index = 0usize;
    let trailer_offset = data.len().saturating_sub(20);

    loop {
        if entries.len() as u32 == num_objects && pos >= trailer_offset {
            break;
        }
        if pos + 20 > data.len() {
            errors.push(format!("entry {} overruns file at offset {}", scan_index, pos));
            break;
        }
        if pos >= trailer_offset {
            errors.push(format!(
                "entry {} begins at {} inside the 20-byte trailer region",
                scan_index, pos
            ));
            break;
        }
        let entry_offset = pos as u64;
        let (kind, size, after_hdr) = match read_entry_header(data, pos) {
            Some(v) => v,
            None => {
                errors.push(format!("entry {} unreadable header at offset {}", scan_index, pos));
                break;
            }
        };
        pos = after_hdr;
        let mut ofs_distance = None;
        let mut ofs_base_offset = None;
        let mut ref_base_oid = None;
        let mut entry_err: Option<String> = None;

        if kind == ObjType::OfsDelta {
            match read_ofs_offset(data, pos) {
                Some((dist, p2)) => {
                    ofs_distance = Some(dist);
                    ofs_base_offset = Some(entry_offset.saturating_sub(dist));
                    pos = p2;
                    if dist == 0 || dist > entry_offset {
                        entry_err = Some(format!(
                            "ofs-delta distance {} out of bounds at offset {}",
                            dist, entry_offset
                        ));
                    }
                }
                None => {
                    errors.push(format!("entry {} truncated ofs offset at {}", scan_index, entry_offset));
                    break;
                }
            }
        } else if kind == ObjType::RefDelta {
            if pos + 20 > data.len() {
                errors.push(format!("entry {} truncated ref base at {}", scan_index, entry_offset));
                break;
            }
            ref_base_oid = Oid::from_bytes(&data[pos..pos + 20]);
            pos += 20;
        }

        let inflate_cap = size as usize;
        let mut data_end = pos as u64;
        let payload = if entry_err.is_some() {
            // Still try to skip the compressed bytes.
            match zlib::inflate_at(data, pos, inflate_cap, SIZE_SLACK) {
                Ok(r) => {
                    data_end = r.consumed as u64;
                    Some(r.data)
                }
                Err(_) => None,
            }
        } else {
            match zlib::inflate_at(data, pos, inflate_cap, SIZE_SLACK) {
                Ok(r) => {
                    data_end = r.consumed as u64;
                    if r.data.len() != size as usize {
                        entry_err = Some(format!(
                            "size spoof: header declares {} bytes but stream yields {}",
                            size,
                            r.data.len()
                        ));
                    }
                    Some(r.data)
                }
                Err(e) => {
                    entry_err = Some(format!("zlib error: {}", e));
                    None
                }
            }
        };

        // idx cross-checks.
        let ix = by_offset.binary_search_by_key(&entry_offset, |x| x.0);
        let (idx_position, idx_crc) = match ix {
            Ok(i) => {
                let (_, ord, crc, _oid) = by_offset[i];
                let end_hint = by_offset
                    .get(i + 1)
                    .map(|x| x.0 as usize)
                    .unwrap_or(trailer_offset);
                if entry_err.is_none() {
                    let actual = crc32fast::hash(&data[entry_offset as usize..data_end as usize]);
                    if actual != crc {
                        entry_err = Some(format!(
                            "CRC mismatch: idx says {:08x}, packed bytes hash to {:08x}",
                            crc, actual
                        ));
                    }
                    let _ = end_hint;
                }
                (Some(ord), Some(crc))
            }
            Err(_) => (None, None),
        };

        entries.push(PackEntry {
            index: scan_index,
            offset: entry_offset,
            data_end,
            kind,
            declared_size: size,
            ofs_distance,
            ofs_base_offset,
            ref_base_oid,
            payload_len: payload.as_ref().map(|p| p.len()).unwrap_or(0),
            error: entry_err.clone(),
            idx_position,
            idx_crc,
        });
        payloads.push(payload);
        scan_index += 1;

        if entry_err.is_some() && idx.is_none() {
            // Without an index we cannot reliably find the next stream boundary.
            errors.push(format!(
                "scan stops after damaged entry at offset {} (no index to resync)",
                entry_offset
            ));
            break;
        }
        // Advance: trust consumed bytes, or (damaged w/ idx) the next offset.
        pos = if data_end > pos as u64 {
            data_end as usize
        } else if let Ok(i) = ix {
            by_offset
                .get(i + 1)
                .map(|x| x.0 as usize)
                .unwrap_or(trailer_offset)
        } else {
            break;
        };
    }

    if entries.len() as u32 != num_objects {
        errors.push(format!(
            "header claims {} objects but {} were parsed",
            num_objects, entries.len()
        ));
    }

    let (trailer_sha, trailer_ok) = if data.len() >= 32 {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&data[..trailer_offset]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&h.finalize());
        let stored = Oid::from_bytes(&data[trailer_offset..trailer_offset + 20]).unwrap();
        (Some(stored), Some(Oid(out) == stored))
    } else {
        (None, None)
    };
    if let Some(false) = trailer_ok {
        errors.push("pack trailer checksum mismatch".into());
    }

    ParsedPack {
        header: PackHeader {
            version,
            num_objects,
            header_end: 12,
            trailer_offset: Some(trailer_offset),
            trailer_sha,
            trailer_ok,
        },
        entries,
        errors,
        payloads,
    }
}
