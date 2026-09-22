//! Hand-written parser for Git pack files (`PACK` v2).
//!
//! Every discovered object keeps its original byte offset, the raw entry
//! bytes (needed for index CRC verification), the declared (header) size
//! and the actual inflated length so that size spoofing can be proven.

use crate::gitio::{hex_oid, inflate_at, read_le_base128, read_ofs_varint, sha1_bytes, ObjType};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_code: u8,
    pub obj_type: ObjType,
    /// Size declared in the entry header (base size for delta objects).
    pub declared_size: u64,
    /// Relative distance to the base (OFS_DELTA only).
    pub ofs_distance: Option<u64>,
    pub base_offset: Option<u64>,
    /// Base object id (REF_DELTA only).
    pub ref_base: Option<[u8; 20]>,
    pub header_len: usize,
    pub compressed_len: usize,
    pub inflated_len: usize,
    pub zlib_ok: bool,
    pub inflate_error: Option<String>,
    pub raw_entry: Vec<u8>,
    pub inflated: Vec<u8>,
}

impl PackEntry {
    pub fn end_offset(&self) -> u64 {
        self.offset + self.header_len as u64 + self.compressed_len as u64
    }
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// Entries that failed at a given offset (when pulled in from an idx).
    pub parse_failures: Vec<(u64, String)>,
    pub checksum: [u8; 20],
    pub trailer_ok: bool,
    pub trailer_error: Option<String>,
}

fn parse_entry_at(data: &[u8], offset: u64) -> Result<PackEntry, String> {
    let start = offset as usize;
    if start >= data.len() {
        return Err(format!("entry offset {offset} past pack end"));
    }
    let (word, hlen) = read_le_base128(data, start)?;
    let obj_code = ((word >> 4) & 0x7) as u8;
    let obj_type = ObjType::from_code(obj_code)
        .ok_or_else(|| format!("invalid object type code {obj_code} at offset {offset}"))?;
    let declared_size = word & 0x0f | (word >> 7) << 4;

    let mut ofs_distance = None;
    let mut base_offset = None;
    let mut ref_base = None;

    if obj_type == ObjType::OfsDelta {
        let (dist, n) = read_ofs_varint(data, start + hlen)?;
        ofs_distance = Some(dist);
        if dist > offset {
            return Err(format!(
                "ofs-delta distance {dist} underflows base at offset {offset}"
            ));
        }
        base_offset = Some(offset - dist);
    } else if obj_type == ObjType::RefDelta {
        let p = start + hlen;
        if p + 20 > data.len() {
            return Err("truncated ref-delta base oid".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        ref_base = Some(oid);
    }

    let zlib_pos = match obj_type {
        ObjType::OfsDelta => start + hlen + {
            let (_, n) = read_ofs_varint(data, start + hlen)?;
            n
        },
        ObjType::RefDelta => start + hlen + 20,
        _ => start + hlen,
    };

    let inf = inflate_at(data, zlib_pos);
    let raw_entry = data[start..zlib_pos + inf.compressed_len].to_vec();

    Ok(PackEntry {
        offset,
        obj_code,
        obj_type,
        declared_size,
        ofs_distance,
        base_offset,
        ref_base,
        header_len: zlib_pos - start,
        compressed_len: inf.compressed_len,
        inflated_len: inf.data.len() as u64,
        zlib_ok: inf.stream_end && inf.error.is_none(),
        inflate_error: inf.error,
        raw_entry,
        inflated: inf.data,
    })
}

/// Parse a pack. `hint_offsets` are object offsets advertised by an index;
/// when the sequential walk loses sync we resync to the next hint instead
/// of abandoning the remainder of the pack.
pub fn parse_pack(data: &[u8], hint_offsets: &[u64]) -> Result<PackInfo, String> {
    if data.len() < 32 {
        return Err("pack too small (< 32 bytes)".into());
    }
    if &data[..4] != b"PACK" {
        return Err(format!("bad pack signature: {:?}", &data[..4]));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let checksum_start = data.len() - 20;
    let stored_checksum: [u8; 20] = data[checksum_start..].try_into().unwrap();
    let computed = sha1_bytes(&data[..checksum_start]);
    let trailer_ok = stored_checksum == computed;
    let trailer_error = if trailer_ok {
        None
    } else {
        Some(format!(
            "pack checksum mismatch: stored {} computed {}",
            hex_oid(&stored_checksum),
            hex_oid(&computed)
        ))
    };

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut failures: Vec<(u64, String)> = Vec::new();
    let mut pos = 12u64;
    let mut seen_hints = 0usize;

    while pos < checksum_start as u64 {
        match parse_entry_at(data, pos) {
            Ok(entry) => {
                let next = entry.end_offset();
                if !entry.zlib_ok {
                    failures.push((
                        pos,
                        entry
                            .inflate_error
                            .clone()
                            .unwrap_or_else(|| "zlib stream did not end".into()),
                    ));
                    // Resync to the nearest unused index hint, otherwise stop.
                    let mut next_hint = None;
                    while seen_hints < hint_offsets.len() && hint_offsets[seen_hints] <= pos {
                        seen_hints += 1;
                    }
                    if seen_hints < hint_offsets.len() && hint_offsets[seen_hints] > pos {
                        next_hint = Some(hint_offsets[seen_hints]);
                    }
                    match next_hint {
                        Some(h) if h < checksum_start as u64 => pos = h,
                        _ => break,
                    }
                } else {
                    entries.push(entry);
                    pos = next;
                }
            }
            Err(e) => {
                failures.push((pos, e));
                break;
            }
        }
    }

    // Pull in any index-advertised offsets the sequential walk missed.
    for &hoff in hint_offsets {
        if entries.iter().any(|e| e.offset == hoff) || hoff >= checksum_start as u64 {
            continue;
        }
        match parse_entry_at(data, hoff) {
            Ok(entry) if entry.zlib_ok => entries.push(entry),
            Ok(entry) => failures.push((hoff, entry.inflate_error.unwrap_or_else(|| "bad zlib".into()))),
            Err(e) => failures.push((hoff, e)),
        }
    }

    entries.sort_by_key(|e| e.offset);
    entries.dedup_by_key(|e| e.offset);

    Ok(PackInfo {
        version,
        count,
        entries,
        parse_failures: failures,
        checksum: stored_checksum,
        trailer_ok,
        trailer_error,
    })
}
