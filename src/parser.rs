use crate::git::{inflate_zlib, read_pack_size, GitType};
use crc32fast::Hasher;
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct ContentSummary {
    pub len: usize,
    pub sha256: String,
    pub head_hex: String,
}

impl ContentSummary {
    pub fn new(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        Self {
            len: bytes.len(),
            sha256: hex::encode(digest),
            head_hex: hex::encode(&bytes[..bytes.len().min(32)]),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeltaRef {
    None,
    Ofs {
        negative_offset: u64,
        target_offset: u64,
    },
    Ref {
        base_oid: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedEntry {
    pub index: usize,
    pub header_offset: u64,
    pub data_offset: u64,
    pub next_offset: u64,
    pub pack_type_code: u8,
    pub type_name: String,
    pub declared_size: u64,
    pub inflated_len: usize,
    pub delta: DeltaRef,
    pub payload: Vec<u8>,
    pub crc32: Option<u32>,
    pub expected_crc32: Option<u32>,
    pub crc_ok: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fanout {
    pub first_bucket: i64,
    pub last_bucket: i64,
    pub count: i64,
    pub monotonic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedIndex {
    pub version: u32,
    pub object_count: u32,
    pub pack_checksum: Option<String>,
    pub fanout_last: u32,
    pub fanout_consistent: bool,
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedPack {
    pub version: u32,
    pub object_count: u32,
    pub entries: Vec<ParsedEntry>,
    pub pack_checksum: String,
    pub expected_checksum: Option<String>,
    pub checksum_ok: Option<bool>,
    pub trailer_offset: u64,
    pub errors: Vec<String>,
    pub index: Option<ParsedIndex>,
}

fn parse_idx(bytes: &[u8]) -> ParsedIndex {
    let mut errors = Vec::new();
    let invalid = |msg: String, errors: &mut Vec<String>| ParsedIndex {
        version: 0,
        object_count: 0,
        pack_checksum: None,
        fanout_last: 0,
        fanout_consistent: false,
        fanout: Vec::new(),
        entries: Vec::new(),
        errors: {
            errors.push(msg);
            std::mem::take(errors)
        },
    };
    if bytes.len() < 8 {
        return invalid("index is shorter than v2 header".into(), &mut errors);
    }
    if &bytes[..4] != b"\xfftOc" {
        return invalid("unsupported index magic (v1 .idx is not supported)".into(), &mut errors);
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if version != 2 {
        return invalid(format!("unsupported index version {version}"), &mut errors);
    }
    let mut pos = 8usize;
    if bytes.len() < pos + 1024 {
        return invalid("index is shorter than fanout table".into(), &mut errors);
    }
    let mut fanout = Vec::with_capacity(256);
    for _ in 0..256 {
        fanout.push(u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()));
        pos += 4;
    }
    let count = fanout[255];
    let mut monotonic = true;
    let mut previous = 0u32;
    for value in &fanout {
        if *value < previous {
            monotonic = false;
        }
        previous = *value;
    }
    let mut entries = Vec::new();
    let need = 8 + 1024 + count as usize * (20 + 4 + 4) + 40;
    if bytes.len() < need {
        errors.push(format!("index declares {count} objects but is too short"));
        return ParsedIndex {
            version,
            object_count: count,
            pack_checksum: None,
            fanout_last: count,
            fanout_consistent: monotonic && fanout[255] == count,
            fanout,
            entries,
            errors,
        };
    }
    let oid_start = pos;
    pos += count as usize * 20;
    let crc_start = pos;
    pos += count as usize * 4;
    let offset_start = pos;
    for i in 0..count as usize {
        let oid = hex::encode(&bytes[oid_start + i * 20..oid_start + (i + 1) * 20]);
        let crc = u32::from_be_bytes(
            bytes[crc_start + i * 4..crc_start + (i + 1) * 4]
                .try_into()
                .unwrap(),
        );
        let raw = u32::from_be_bytes(
            bytes[offset_start + i * 4..offset_start + (i + 1) * 4]
                .try_into()
                .unwrap(),
        );
        let offset = if raw & 0x8000_0000 != 0 {
            let table_pos = (raw & 0x7fff_ffff) as usize;
            let large_pos = offset_start + count as usize * 4 + table_pos * 8;
            if large_pos + 8 > bytes.len() - 40 {
                errors.push(format!("large offset table entry {table_pos} is out of bounds"));
                continue;
            }
            u64::from_be_bytes(bytes[large_pos..large_pos + 8].try_into().unwrap())
        } else {
            u64::from(raw)
        };
        entries.push(IndexEntry { oid, offset, crc32: crc });
    }
    let pack_checksum = Some(hex::encode(&bytes[bytes.len() - 40..bytes.len() - 20]));
    ParsedIndex {
        version,
        object_count: count,
        pack_checksum,
        fanout_last: count,
        fanout_consistent: monotonic,
        fanout,
        entries,
        errors,
    }
}

fn read_entry_header(bytes: &[u8], pos: usize) -> Result<(u8, u64, DeltaRef, usize), String> {
    let first = *bytes.get(pos).ok_or("truncated object header")?;
    let kind_code = (first >> 4) & 7;
    let (declared, size_len) = read_pack_size(first & 0x0f, &bytes[pos + 1..])?;
    let mut header_len = 1 + size_len;
    let delta = match kind_code {
        6 => {
            let mut value = 0u64;
            let mut offset_bytes = 0usize;
            loop {
                let byte = *bytes
                    .get(pos + header_len)
                    .ok_or("truncated ofs-delta offset")?;
                header_len += 1;
                offset_bytes += 1;
                if offset_bytes == 1 {
                    value = u64::from(byte & 0x7f);
                } else {
                    value = value.wrapping_add(1);
                    value = (value << 7) | u64::from(byte & 0x7f);
                }
                if byte & 0x80 == 0 {
                    break;
                }
                if offset_bytes > 8 {
                    return Err("ofs-delta offset is too long".into());
                }
            }
            let header_offset = pos as u64;
            let target = header_offset
                .checked_sub(value)
                .ok_or_else(|| format!("ofs-delta negative distance {value} points before pack"))?;
            if target < 12 {
                return Err(format!("ofs-delta target {target} is inside pack header"));
            }
            DeltaRef::Ofs {
                negative_offset: value,
                target_offset: target,
            }
        }
        7 => {
            let oid_bytes = bytes
                .get(pos + header_len..pos + header_len + 20)
                .ok_or("truncated ref-delta base id")?;
            header_len += 20;
            DeltaRef::Ref {
                base_oid: hex::encode(oid_bytes),
            }
        }
        _ => DeltaRef::None,
    };
    Ok((kind_code, declared, delta, header_len))
}

fn parse_pack_entry(bytes: &[u8], pos: usize, index: usize, idx: Option<&ParsedIndex>) -> ParsedEntry {
    let header_offset = pos as u64;
    let make_err = |message: String| ParsedEntry {
        index,
        header_offset,
        data_offset: header_offset,
        next_offset: header_offset,
        pack_type_code: 0,
        type_name: "bad".into(),
        declared_size: 0,
        inflated_len: 0,
        delta: DeltaRef::None,
        payload: Vec::new(),
        crc32: None,
        expected_crc32: None,
        crc_ok: None,
        error: Some(message),
    };
    let (code, declared, delta, header_len) = match read_entry_header(bytes, pos) {
        Ok(value) => value,
        Err(err) => return make_err(err),
    };
    let type_name = match code {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        6 => "ofs_delta",
        7 => "ref_delta",
        _ => "unknown",
    }
    .to_string();
    if !(1..=7).contains(&code) || code == 5 {
        return make_err(format!("invalid pack object type {code}"));
    }
    let data_offset = header_offset + header_len as u64;
    let mut error = None;
    let (payload, zlib_len) = match inflate_zlib(&bytes[data_offset as usize..]) {
        Ok(value) => value,
        Err(err) => {
            error = Some(err);
            (Vec::new(), 0usize)
        }
    };
    if error.is_none() && payload.len() as u64 != declared {
        error = Some(format!(
            "declared object size {declared} does not match inflated size {}",
            payload.len()
        ));
    }
    let next_offset = data_offset + zlib_len as u64;
    let range_end = if zlib_len == 0 {
        data_offset as usize
    } else {
        next_offset as usize
    };
    let mut hasher = Hasher::new();
    hasher.update(&bytes[pos..range_end]);
    let crc = hasher.clone().finalize();
    let expected = idx.and_then(|idx| {
        idx.entries
            .iter()
            .find(|entry| entry.offset == header_offset)
            .map(|entry| entry.crc32)
    });
    let crc_ok = expected.map(|expected| expected == crc);
    if let Some(false) = crc_ok {
        error = Some(format!(
            "index CRC mismatch: computed {crc:08x}, expected {expected:08x}",
            expected = expected.unwrap_or(0)
        ));
    }
    ParsedEntry {
        index,
        header_offset,
        data_offset,
        next_offset,
        pack_type_code: code,
        type_name,
        declared_size: declared,
        inflated_len: payload.len(),
        delta,
        payload,
        crc32: Some(crc),
        expected_crc32: expected,
        crc_ok,
        error,
    }
}

pub fn parse_pack(bytes: &[u8], idx_bytes: Option<&[u8]>) -> ParsedPack {
    let mut errors = Vec::new();
    if bytes.len() < 32 {
        return ParsedPack {
            version: 0,
            object_count: 0,
            entries: Vec::new(),
            pack_checksum: String::new(),
            expected_checksum: None,
            checksum_ok: None,
            trailer_offset: 0,
            errors: vec!["pack is shorter than header and trailer".into()],
            index: None,
        };
    }
    if &bytes[..4] != b"PACK" {
        return ParsedPack {
            version: 0,
            object_count: 0,
            entries: Vec::new(),
            pack_checksum: String::new(),
            expected_checksum: None,
            checksum_ok: None,
            trailer_offset: 0,
            errors: vec!["missing PACK magic".into()],
            index: None,
        };
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let object_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let trailer_offset = bytes.len() as u64 - 20;
    let mut hasher = Sha1::new();
    hasher.update(&bytes[..bytes.len() - 20]);
    let pack_checksum = hex::encode(hasher.finalize());
    let expected_checksum = hex::encode(&bytes[bytes.len() - 20..]);
    if version != 2 {
        errors.push(format!("unsupported pack version {version}"));
    }
    let mut index = idx_bytes.map(parse_idx);
    if let Some(idx) = &mut index {
        if idx.pack_checksum.as_deref() != Some(&expected_checksum) {
            idx.fanout_consistent = false;
            idx.errors.push(format!(
                "index pack checksum {} does not match pack trailer {}",
                idx.pack_checksum.as_deref().unwrap_or("<missing>"),
                expected_checksum
            ));
        }
    }
    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut broken_stream = false;
    for ordinal in 0..object_count as usize {
        if broken_stream || pos >= trailer_offset as usize {
            errors.push(format!(
                "object {ordinal} is unavailable because a previous object lacks a zlib boundary"
            ));
            break;
        }
        let entry = parse_pack_entry(bytes, pos, ordinal, index.as_ref());
        if let Some(message) = &entry.error {
            errors.push(format!(
                "object {ordinal} at offset {}: {message}",
                entry.header_offset
            ));
        }
        if entry.next_offset > entry.header_offset {
            pos = entry.next_offset as usize;
        } else {
            if let Some(idx) = index.as_ref() {
                if let Some(next) = idx
                    .entries
                    .iter()
                    .map(|item| item.offset as usize)
                    .filter(|offset| *offset > pos)
                    .min()
                {
                    pos = next;
                } else {
                    broken_stream = true;
                }
            } else {
                broken_stream = true;
            }
        }
        entries.push(entry);
    }
    if pos != trailer_offset as usize && !broken_stream {
        errors.push(format!(
            "entry stream ends at {pos}, pack trailer begins at {trailer_offset}"
        ));
    }
    if pack_checksum != expected_checksum {
        errors.push("pack SHA-1 trailer mismatch".into());
    }
    ParsedPack {
        version,
        object_count,
        entries,
        pack_checksum,
        expected_checksum: Some(expected_checksum),
        checksum_ok: Some(pack_checksum == expected_checksum_trailer(bytes)),
        trailer_offset,
        errors,
        index,
    }
}

fn expected_checksum_trailer(bytes: &[u8]) -> String {
    hex::encode(&bytes[bytes.len() - 20..])
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedLoose {
    pub type_name: String,
    pub declared_size: usize,
    pub inflated_len: usize,
    pub payload: Vec<u8>,
    pub error: Option<String>,
}

pub fn parse_loose(bytes: &[u8]) -> ParsedLoose {
    let (header, payload_compressed) = match bytes.iter().position(|byte| *byte == 0) {
        Some(null) => (&bytes[..null], &bytes[null + 1..]),
        None => {
            return ParsedLoose {
                type_name: "bad".into(),
                declared_size: 0,
                inflated_len: 0,
                payload: Vec::new(),
                error: Some("loose object has no NUL header terminator".into()),
            }
        }
    };
    let header_text = String::from_utf8_lossy(header);
    let mut parts = header_text.split_whitespace();
    let type_name = parts.next().unwrap_or("bad").to_string();
    let declared_size = parts
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let known_type = GitType::parse(&type_name).is_some();
    let mut error = (!known_type)
        .then(|| format!("loose object has unsupported type {type_name}"));
    let (payload, _consumed) = match inflate_zlib(payload_compressed) {
        Ok(value) => value,
        Err(inflate_error) => (Vec::new(), 0),
    };
    if payload.is_empty() && type_name != "blob" {
        error = Some(error.unwrap_or_else(|| "loose zlib payload could not be inflated".into()));
    }
    if payload.len() != declared_size && error.is_none() {
        error = Some(format!(
            "loose header declares {declared_size} bytes but inflated payload is {} bytes",
            payload.len()
        ));
    }
    ParsedLoose {
        type_name,
        declared_size,
        inflated_len: payload.len(),
        payload,
        error,
    }
}

pub fn content_summary(bytes: &[u8]) -> ContentSummary {
    ContentSummary::new(bytes)
}
