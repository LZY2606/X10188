//! Parse a Git pack file, retaining raw offsets and zlib boundaries.

use crate::git::{inflate_one, read_ofs_distance, read_pack_entry_header, GitType};

/// Information supplied by an index, used to locate/verify pack entries.
#[derive(Debug, Clone)]
pub struct IndexHint {
    pub offsets_oids: Vec<(u64, [u8; 20])>,
    pub crc_by_offset: std::collections::HashMap<u64, u32>,
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub obj_type: Option<u8>,
    pub header_offset: u64,
    pub data_offset: u64,
    pub end_offset: u64,
    /// Declared uncompressed size from the entry header.
    pub declared_size: u64,
    /// Actual uncompressed bytes obtained from zlib.
    pub actual_size: u64,
    /// Bytes consumed by the compressed stream.
    pub compressed_len: u64,
    /// Raw decompressed delta stream / object payload.
    pub raw: Vec<u8>,
    /// ofs-delta: base offset; ref-delta: base oid.
    pub base_offset: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
    pub expected_oid: Option<[u8; 20]>,
    /// CRC of the packed entry bytes as reported by the index.
    pub index_crc: Option<u32>,
    /// CRC computed locally.
    pub actual_crc: u32,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackParse {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailing_sha_ok: bool,
    pub trailer_offset: u64,
    pub parse_errors: Vec<String>,
}

fn read_u32(data: &[u8], p: usize) -> Result<u32, String> {
    data.get(p..p + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| "unexpected end of data".to_string())
}

fn parse_one_entry(
    data: &[u8],
    start: usize,
    index: usize,
    hint: Option<&IndexHint>,
) -> Result<PackEntry, String> {
    let (code, size, hdr_len) = read_pack_entry_header(data, start)?;
    let t = GitType::from_pack(code).ok_or_else(|| format!("unknown pack type {code}"))?;
    let mut p = start + hdr_len;

    let mut base_offset = None;
    let mut base_oid = None;
    if t == GitType::OfsDelta {
        let (dist, used) = read_ofs_distance(data, p)?;
        p += used;
        let bo = (start as u64).checked_sub(dist);
        if bo.is_none() {
            return Err(format!(
                "ofs-delta negative distance {dist} underflows entry offset {start}"
            ));
        }
        let bo = bo.unwrap();
        if bo >= start as u64 {
            return Err(format!("ofs-delta base offset {bo} is not before entry offset {start}"));
        }
        if (bo as usize) < 12 {
            return Err(format!("ofs-delta base offset {bo} points inside pack header"));
        }
        base_offset = Some(bo);
    } else if t == GitType::RefDelta {
        if p + 20 > data.len() {
            return Err("truncated ref-delta base oid".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        p += 20;
        base_oid = Some(oid);
    }

    let data_offset = p as u64;
    let (raw, used_comp) = inflate_one(data, p)?;
    let end_offset = (p + used_comp) as u64;

    if (raw.len() as u64) != size {
        return Err(format!(
            "size spoof: entry header declares {size} bytes but zlib yields {} bytes",
            raw.len()
        ));
    }

    let start_u = start as u64;
    let expected_oid = hint.and_then(|h| {
        h.offsets_oids
            .iter()
            .find(|(off, _)| *off == start_u)
            .map(|(_, oid)| *oid)
    });
    let index_crc = hint.and_then(|h| h.crc_by_offset.get(&start_u).copied());
    let actual_crc = crc32fast::hash(&data[start..end_offset as usize]);

    Ok(PackEntry {
        index,
        obj_type: Some(code),
        header_offset: start_u,
        data_offset,
        end_offset,
        declared_size: size,
        actual_size: raw.len() as u64,
        compressed_len: used_comp as u64,
        raw,
        base_offset,
        base_oid,
        expected_oid,
        index_crc,
        actual_crc,
        parse_error: None,
    })
}

fn broken_entry(
    index: usize,
    start: usize,
    next: Option<usize>,
    msg: String,
    hint: Option<&IndexHint>,
) -> PackEntry {
    let end = next.unwrap_or(start + 1);
    let start_u = start as u64;
    let expected_oid = hint.and_then(|h| {
        h.offsets_oids
            .iter()
            .find(|(off, _)| *off == start_u)
            .map(|(_, oid)| *oid)
    });
    let index_crc = hint.and_then(|h| h.crc_by_offset.get(&start_u).copied());
    PackEntry {
        index,
        obj_type: None,
        header_offset: start_u,
        data_offset: start_u,
        end_offset: end as u64,
        declared_size: 0,
        actual_size: 0,
        compressed_len: 0,
        raw: Vec::new(),
        base_offset: None,
        base_oid: None,
        expected_oid,
        index_crc,
        actual_crc: 0,
        parse_error: Some(msg),
    }
}

/// Parse a complete pack. `hint` enables index-guided recovery from a bad
/// object: subsequent entries are still parsed via their known offsets.
pub fn parse_pack(data: &[u8], hint: Option<&IndexHint>) -> Result<PackParse, String> {
    if data.len() < 32 {
        return Err("pack shorter than 32 byte minimum".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("missing PACK magic".into());
    }
    let version = read_u32(data, 4)?;
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = read_u32(data, 8)?;
    let trailer_offset = data.len() as u64 - 20;

    let mut entries = Vec::new();
    let mut parse_errors = Vec::new();
    let mut pos = 12usize;
    let mut idx = 0usize;

    // Known object-start offsets (sorted) for recovery / counting.
    let mut starts: Vec<usize> = hint
        .map(|h| h.offsets_oids.iter().map(|(o, _)| *o as usize).collect())
        .unwrap_or_default();
    starts.sort_unstable();
    starts.dedup();

    while pos < data.len() - 20 && (starts.is_empty() || idx < starts.len().max(count as usize)) {
        // With hints, prefer the next known start.
        let start = if let Some(s) = starts.get(idx) {
            let s = *s;
            if s > pos {
                parse_errors.push(format!(
                    "gap/recovery: skipping {}-{} to next index offset",
                    pos, s
                ));
            }
            s
        } else {
            pos
        };

        if start >= data.len() - 20 {
            break;
        }

        match parse_one_entry(data, start, idx, hint) {
            Ok(mut e) => {
                if let (Some(want), Some(got)) = (e.index_crc, e.actual_crc) {
                    if want != got {
                        e.parse_error = Some(format!(
                            "bad CRC: index records {want:#010x} but packed bytes hash to {got:#010x}"
                        ));
                    }
                }
                pos = e.end_offset as usize;
                entries.push(e);
            }
            Err(msg) => {
                parse_errors.push(format!("object #{idx} at offset {start}: {msg}"));
                // Recover using the next known offset; otherwise stop.
                let next = starts.get(idx + 1).copied();
                if let Some(next) = next {
                    let mut e = broken_entry(idx, start, Some(next), msg, hint);
                    // CRC for the broken span, useful as evidence.
                    e.actual_crc = crc32fast::hash(&data[start..next]);
                    if let Some(want) = e.index_crc {
                        if want != e.actual_crc {
                            e.parse_error = Some(format!(
                                "{}; bad CRC: index {want:#010x} actual {:#010x}",
                                e.parse_error.unwrap(),
                                e.actual_crc
                            ));
                        }
                    }
                    entries.push(e);
                    pos = next;
                } else {
                    let mut e = broken_entry(idx, start, None, msg, hint);
                    entries.push(e);
                    break;
                }
            }
        }
        idx += 1;
        if hint.is_none() && entries.len() as u32 >= count {
            break;
        }
    }

    // Trailer verification: sha1 of all preceding bytes.
    use sha1_smol::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(&data[..data.len() - 20]);
    let want = hasher.digest().bytes();
    let got = &data[data.len() - 20..];
    let trailing_sha_ok = want == got;
    if !trailing_sha_ok {
        parse_errors.push("pack trailer sha1 mismatch".into());
    }

    if !starts.is_empty() && entries.len() != count as usize {
        parse_errors.push(format!(
            "expected {} objects from index, parsed {}",
            count,
            entries.len()
        ));
    }

    Ok(PackParse {
        version,
        count,
        entries,
        trailing_sha_ok,
        trailer_offset,
        parse_errors,
    })
}
