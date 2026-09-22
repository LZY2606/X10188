use crate::git::{
    oid_hex, read_ofs_distance, read_pack_size, zlib_decompress_limited, ObjectType, Oid,
};
use crc32fast::hash as crc32;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub header_end: u64,
    pub compressed_start: u64,
    pub compressed_end: u64,
    pub raw_type: u8,
    pub object_type: ObjectType,
    pub declared_size: u64,
    pub payload: Option<Vec<u8>>,
    pub base_offset: Option<u64>,
    pub base_oid: Option<Oid>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub data: Vec<u8>,
    pub version: u32,
    pub declared_count: u32,
    pub entries: BTreeMap<u64, PackEntry>,
    pub parse_errors: Vec<String>,
}

fn u32_at(data: &[u8], pos: usize) -> Result<u32, String> {
    data.get(pos..pos + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).ok_or_else(|| "truncated u32".into())
}

pub fn parse_pack(data: Vec<u8>, hint_offsets: &BTreeSet<u64>, hard_limit: usize) -> ParsedPack {
    let mut errors = Vec::new();
    let mut entries = BTreeMap::new();
    if data.len() < 12 || &data[0..4] != b"PACK" {
        return ParsedPack { data, version: 0, declared_count: 0, entries, parse_errors: vec!["missing PACK magic".into()] };
    }
    let version = match u32_at(&data, 4) { Ok(v) => v, Err(e) => return ParsedPack { data, version: 0, declared_count: 0, entries, parse_errors: vec![e] } };
    let count = match u32_at(&data, 8) { Ok(v) => v, Err(e) => return ParsedPack { data, version, declared_count: 0, entries, parse_errors: vec![e] } };
    if version != 2 { errors.push(format!("unsupported pack version {version}")); }
    if data.len() < 20 { errors.push("pack trailer is missing".into()); }

    let known_trailer = if data.len() >= 20 { Some(data.len() - 20) } else { None };
    let mut sorted_hints: Vec<u64> = hint_offsets.iter().copied().collect();
    sorted_hints.sort();
    let mut next_hint = 0usize;
    let mut offset = 12u64;
    let mut parsed = 0u32;

    while parsed < count {
        let start = offset as usize;
        let mut next_known = None;
        while next_hint < sorted_hints.len() && sorted_hints[next_hint] <= offset { next_hint += 1; }
        if next_hint < sorted_hints.len() { next_known = Some(sorted_hints[next_hint] as usize); }
        if start >= data.len().saturating_sub(19) { errors.push(format!("entry at {start} runs past pack")); break; }
        let first = data[start];
        let raw_type = (first >> 4) & 7;
        let object_type = ObjectType::from_code(raw_type);
        let (size, after_size) = match read_pack_size(&data, start) {
            Ok(v) => v,
            Err(e) => { errors.push(format!("entry at {start}: {e}")); break; }
        };
        let mut pos = after_size;
        let mut base_offset = None;
        let mut base_oid = None;
        if object_type == ObjectType::OfsDelta {
            match read_ofs_distance(&data, pos) {
                Ok((distance, after)) => {
                    pos = after;
                    base_offset = Some(offset.checked_sub(distance).unwrap_or(u64::MAX));
                }
                Err(e) => { errors.push(format!("ofs-delta at {start}: {e}")); break; }
            }
        } else if object_type == ObjectType::RefDelta {
            if pos + 20 > data.len() { errors.push(format!("ref-delta at {start} is truncated")); break; }
            base_oid = Some(data[pos..pos + 20].try_into().unwrap());
            pos += 20;
        }
        let compressed_start = pos;
        let bounded = &data[compressed_start..next_known.or(known_trailer).unwrap_or(data.len())];
        let z = zlib_decompress_limited(bounded, Some(size), hard_limit);
        let mut entry = PackEntry {
            offset, header_end: compressed_start as u64, compressed_start: compressed_start as u64,
            compressed_end: 0, raw_type, object_type, declared_size: size, payload: None,
            base_offset, base_oid, parse_error: None,
        };
        match z {
            Ok(z) => {
                let end = compressed_start + z.consumed;
                entry.compressed_end = end as u64;
                entry.payload = Some(z.data);
                if let Some(error) = z.error {
                    entry.parse_error = Some(error.clone());
                    errors.push(format!("entry at {start}: {error}"));
                }
                offset = end as u64;
            }
            Err(e) => {
                entry.parse_error = Some(e.clone());
                if let Some(next) = next_known {
                    entry.compressed_end = next as u64;
                    entries.insert(offset, entry);
                    errors.push(format!("entry at {start}: {e}; recovered boundary at {next}"));
                    offset = next as u64;
                    parsed += 1;
                    continue;
                }
                entry.compressed_end = known_trailer.unwrap_or(data.len()) as u64;
                errors.push(format!("entry at {start}: {e}"));
                entries.insert(offset, entry);
                break;
            }
        }
        if base_offset == Some(u64::MAX) {
            entry.parse_error = Some("ofs-delta distance underflows before pack start".into());
            errors.push(format!("entry at {start}: ofs distance out of bounds"));
        }
        if let Some(base) = base_offset {
            if base < 12 || base >= offset {
                entry.parse_error = Some(format!("ofs-delta base {base} is outside reachable entry range"));
                errors.push(format!("entry at {start}: ofs base {base} is invalid"));
            }
        }
        entries.insert(entry.offset, entry);
        parsed += 1;
    }
    if entries.len() as u32 != count { errors.push(format!("parsed {} entries, header declared {count}", entries.len())); }
    if data.len() >= 20 {
        let mut h = Sha1::new(); h.update(&data[..data.len() - 20]);
        let actual: Oid = h.finalize().into();
        let expected_trailer: Oid = data[data.len() - 20..].try_into().unwrap();
        if actual != expected_trailer {
            errors.push(format!("pack checksum mismatch: actual {}", oid_hex(&actual)));
        }
    }
    ParsedPack { data, version, declared_count: count, entries, parse_errors: errors }
}

#[derive(Debug, Clone)]
pub struct IndexRecord { pub oid: Oid, pub offset: u64, pub crc: u32 }
#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub data: Vec<u8>,
    pub fanout: Vec<u32>,
    pub records: Vec<IndexRecord>,
    pub pack_checksum: Option<Oid>,
    pub index_checksum: Option<Oid>,
    pub errors: Vec<String>,
}

pub fn parse_index(data: Vec<u8>) -> ParsedIndex {
    let mut errors = Vec::new();
    if data.len() < 8 || &data[0..4] != b"\xfftOc" {
        return ParsedIndex { data, fanout: vec![], records: vec![], pack_checksum: None, index_checksum: None, errors: vec!["missing or unsupported idx header".into()] }
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if magic != 0xff744f63 || version != 2 { errors.push("only idx v2 is supported".into()); }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 { fanout.push(u32::from_be_bytes(data[8 + i * 4..12 + i * 4].try_into().unwrap())); }
    let count = *fanout.last().unwrap();
    let mut pos: usize = 8 + 1024;
    let needed = pos.checked_add(count as usize * 24).and_then(|v| v.checked_add(40));
    if needed.map_or(true, |needed| data.len() < needed) {
        return ParsedIndex { data, fanout, records: vec![], pack_checksum: None, index_checksum: None, errors: vec!["index is truncated".into()] };
    }
    let mut oids = Vec::new();
    for _ in 0..count {
        oids.push(data[pos..pos + 20].try_into().unwrap()); pos += 20;
    }
    let mut crcs = Vec::new();
    for _ in 0..count { crcs.push(u32::from_be_bytes(data[pos..pos+4].try_into().unwrap())); pos += 4; }
    let mut offsets = Vec::new();
    for _ in 0..count { offsets.push(u32::from_be_bytes(data[pos..pos+4].try_into().unwrap())); pos += 4; }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for (idx, oid) in oids.into_iter().enumerate() {
        if !seen.insert(oid) { errors.push(format!("duplicate oid {} inside index", oid_hex(&oid))); }
        records.push(IndexRecord { oid, offset: offsets[idx] as u64, crc: crcs[idx] });
    }
    let pack_checksum = data.get(pos..pos+20).map(|s| s.try_into().unwrap());
    let index_checksum = data.get(pos+20..pos+40).map(|s| s.try_into().unwrap());
    if let Some(checksum) = index_checksum {
        let mut h = Sha1::new(); h.update(&data[..data.len()-20]);
        let actual: Oid = h.finalize().into();
        if actual != checksum { errors.push(format!("index checksum mismatch: actual {}", oid_hex(&actual))); }
    }
    ParsedIndex { data, fanout, records, pack_checksum, index_checksum, errors }
}

pub fn verify_index_crcs(pack: &ParsedPack, index: &ParsedIndex) -> Vec<String> {
    let mut errors = Vec::new();
    for rec in &index.records {
        let Some(entry) = pack.entries.get(&rec.offset) else {
            errors.push(format!("index oid {} points to missing offset {}", oid_hex(&rec.oid), rec.offset));
            continue;
        };
        let start = entry.offset as usize;
        let end = entry.compressed_end.max(entry.header_end) as usize;
        if end > pack.data.len() || start >= end {
            errors.push(format!("oid {} CRC range {}..{} invalid", oid_hex(&rec.oid), start, end));
            continue;
        }
        let actual = crc32(&pack.data[start..end]);
        if actual != rec.crc {
            errors.push(format!("oid {} CRC mismatch: stored {:#010x}, calculated {:#010x}", oid_hex(&rec.oid), rec.crc, actual));
        }
    }
    errors
}

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub oid: Oid,
    pub kind: ObjectType,
    pub data: Vec<u8>,
    pub parse_error: Option<String>,
}

pub fn parse_loose(data: &[u8], expected: Option<Oid>, hard_limit: usize) -> LooseObject {
    let z = match zlib_decompress_limited(data, None, hard_limit) {
        Ok(z) => z,
        Err(e) => return LooseObject { oid: [0;20], kind: ObjectType::Blob, data: vec![], parse_error: Some(e) },
    };
    let nul = match z.data.iter().position(|b| *b == 0) { Some(p) => p, None => return LooseObject { oid: [0;20], kind: ObjectType::Blob, data: vec![], parse_error: Some("loose object lacks NUL header".into()) } };
    let header = String::from_utf8_lossy(&z.data[..nul]);
    let mut parts = header.split_whitespace();
    let kind = parts.next().and_then(ObjectType::parse_name);
    let size = parts.next().and_then(|v| v.parse::<u64>().ok());
    let (Some(kind), Some(size)) = (kind, size) else {
        return LooseObject { oid: [0;20], kind: ObjectType::Blob, data: vec![], parse_error: Some(format!("bad loose header {header}")) };
    };
    let body = z.data[nul+1..].to_vec();
    if body.len() as u64 != size {
        let body_len = body.len();
        return LooseObject { oid: [0;20], kind, data: body, parse_error: Some(format!("size spoof: header {size}, body {body_len}")) };
    }
    let actual = crate::git::git_oid(kind, &body);
    let err = expected.filter(|e| e != &actual).map(|e| format!("loose object id mismatch: expected {}, actual {}", oid_hex(&e), oid_hex(&actual)));
    LooseObject { oid: actual, kind, data: body, parse_error: err }
}
