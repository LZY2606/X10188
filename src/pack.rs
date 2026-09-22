use std::path::Path;

use crate::delta::{object_frame, read_size_encoding, ObjectType};
use crate::error::{Error, Result};
use crate::hash::sha1_hex;
use crate::inflate::inflate_limited;

#[derive(Debug, Clone)]
pub struct PackObject {
    pub offset: u64,
    pub header_end: u64,
    pub data_end: u64,
    pub compressed_len: u64,
    pub type_code: u8,
    pub object_type: ObjectType,
    pub declared_size: u64,
    pub actual_size: Option<u64>,
    pub actual_oid: Option<String>,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub data_end: u64,
    pub checksum_expected: String,
    pub checksum_actual: String,
    pub checksum_ok: bool,
    pub objects: Vec<PackObject>,
    pub fatal_error: Option<String>,
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32> {
    data.get(pos..pos + 4)
        .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
        .ok_or_else(|| Error::Corrupt("pack truncated while reading u32".into()))
}

fn read_object_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize, Option<u64>, Option<String>)> {
    if pos >= data.len() {
        return Err(Error::Corrupt("missing object header".into()));
    }
    let first = data[pos];
    let type_code = (first >> 4) & 7;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4u32;
    let mut p = pos + 1;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if p >= data.len() {
            return Err(Error::Corrupt("truncated object header".into()));
        }
        byte = data[p];
        p += 1;
        size |= u64::from(byte & 0x7f).checked_shl(shift)
            .ok_or_else(|| Error::Corrupt("object size overflow".into()))?;
        shift += 7;
    }
    let object_type = ObjectType::from_pack(type_code)
        .ok_or_else(|| Error::Corrupt(format!("unsupported pack object type {type_code}")))?;
    let mut base_offset = None;
    let mut base_oid = None;
    match object_type {
        ObjectType::OfsDelta => {
            if p >= data.len() {
                return Err(Error::Corrupt("missing ofs-delta distance".into()));
            }
            let mut distance = u64::from(data[p] & 0x7f);
            p += 1;
            while data[p - 1] & 0x80 != 0 {
                if p >= data.len() {
                    return Err(Error::Corrupt("truncated ofs-delta distance".into()));
                }
                distance = distance
                    .checked_add(1)
                    .and_then(|v| v.checked_shl(7))
                    .ok_or_else(|| Error::Corrupt("ofs-delta distance overflow".into()))?;
                distance |= u64::from(data[p] & 0x7f);
                p += 1;
            }
            let current = pos as u64;
            if distance > current {
                return Err(Error::Corrupt(format!(
                    "ofs-delta distance {distance} is out of bounds at offset {current}"
                )));
            }
            base_offset = Some(current - distance);
        }
        ObjectType::RefDelta => {
            let end = p.checked_add(20).ok_or_else(|| Error::Corrupt("bad ref-delta".into()))?;
            if end > data.len() {
                return Err(Error::Corrupt("truncated ref-delta base oid".into()));
            }
            base_oid = Some(hex::encode(&data[p..p + 20]));
            p = end;
        }
        _ => {}
    }
    Ok((type_code, size, p, base_offset, base_oid))
}

pub fn parse_pack_path(path: &Path) -> Result<ParsedPack> {
    parse_pack(&std::fs::read(path)?, None)
}

pub fn parse_pack(data: &[u8], hard_object_limit: Option<u64>) -> Result<ParsedPack> {
    let object_limit = hard_object_limit.unwrap_or(256 * 1024 * 1024);
    if data.len() < 32 || &data[0..4] != b"PACK" {
        return Err(Error::Corrupt("missing PACK signature".into()));
    }
    let version = read_u32(data, 4)?;
    if version != 2 {
        return Err(Error::Corrupt(format!("unsupported pack version {version}")));
    }
    let count = read_u32(data, 8)?;
    let mut objects = Vec::with_capacity(count.min(1024 * 1024) as usize);
    let mut pos = 12usize;
    let mut fatal_error = None;

    for index in 0..count {
        let object_offset = pos as u64;
        match parse_one_object(data, &mut pos, object_limit) {
            Ok(object) => objects.push(object),
            Err(err) => {
                fatal_error = Some(format!("object {index} at offset {object_offset}: {err}"));
                break;
            }
        }
    }

    if data.len() < pos + 20 {
        let fatal = fatal_error
            .unwrap_or_else(|| "pack ends before 20-byte checksum".to_string());
        return Ok(finalize_with_error(data, version, count, pos, objects, fatal));
    }
    let data_end = data.len() - 20;
    let expected = hex::encode(&data[data_end..data_end + 20]);
    let actual = sha1_hex(&data[..data_end]);
    let checksum_ok = expected == actual;
    if pos != data_end && fatal_error.is_none() {
        fatal_error = Some(format!("object stream ended at {pos}, pack checksum starts at {data_end}"));
    }
    Ok(ParsedPack {
        version,
        count,
        data_end: data_end as u64,
        checksum_expected: expected,
        checksum_actual: actual,
        checksum_ok,
        objects,
        fatal_error,
    })
}

fn finalize_with_error(
    data: &[u8],
    version: u32,
    count: u32,
    data_end: usize,
    objects: Vec<PackObject>,
    fatal_error: String,
) -> ParsedPack {
    let (expected, actual, ok) = if data.len() >= 20 {
        let end = data.len() - 20;
        (
            hex::encode(&data[end..end + 20]),
            sha1_hex(&data[..end]),
            hex::encode(&data[end..end + 20]) == sha1_hex(&data[..end]),
        )
    } else {
        (String::new(), String::new(), false)
    };
    ParsedPack {
        version,
        count,
        data_end: data_end as u64,
        checksum_expected: expected,
        checksum_actual: actual,
        checksum_ok: ok,
        objects,
        fatal_error: Some(fatal_error),
    }
}

fn parse_one_object(data: &[u8], pos: &mut usize, object_limit: u64) -> Result<PackObject> {
    let offset = *pos;
    let (type_code, declared_size, header_end, base_offset, base_oid) = read_object_header(data, offset)?;
    let object_type = ObjectType::from_pack(type_code).unwrap();
    if declared_size > object_limit {
        return Err(Error::Corrupt(format!(
            "declared object size {declared_size} exceeds safety limit {object_limit}"
        )));
    }
    let inflated = inflate_limited(&data[header_end..], declared_size, object_limit);
    match inflated {
        Ok((body, consumed, size_warning)) => {
            let data_end = header_end + consumed;
            *pos = data_end;
            let (actual_size, actual_oid) = match object_type {
                ObjectType::OfsDelta | ObjectType::RefDelta => (Some(body.len() as u64), None),
                _ => {
                    let frame = object_frame(object_type.git_name(), &body);
                    let oid = sha1_hex(&frame);
                    (Some(body.len() as u64), Some(oid))
                }
            };
            Ok(PackObject {
                offset: offset as u64,
                header_end: header_end as u64,
                data_end: data_end as u64,
                compressed_len: consumed as u64,
                type_code,
                object_type,
                declared_size,
                actual_size,
                actual_oid,
                base_offset,
                base_oid,
                error: size_warning,
            })
        }
        Err(err) => {
            *pos = data.len().saturating_sub(20);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_header() {
        assert!(matches!(
            read_object_header(&[0b01110101], 0).unwrap_err(),
            Error::Corrupt(_)
        ));
    }
}
