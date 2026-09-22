use sha1::Digest;
use crate::git::{read_size, ObjectId, ObjectType};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub end_offset: u64,
    pub payload_offset: u64,
    pub header_size: u64,
    pub kind: ObjectType,
    pub declared_size: u64,
    pub inflated: Vec<u8>,
    pub compressed_len: u64,
    pub negative_offset: Option<u64>,
    pub base_offset: Option<u64>,
    pub ref_base: Option<ObjectId>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackParse {
    pub version: u32,
    pub object_count: u32,
    pub checksum_ok: bool,
    pub actual_checksum: ObjectId,
    pub stored_checksum: ObjectId,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<PackIssue>,
}

#[derive(Debug, Clone)]
pub struct PackIssue {
    pub offset: Option<u64>,
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct DecompressResult {
    pub data: Vec<u8>,
    pub consumed: u64,
    pub stopped: bool,
}

pub fn bounded_decompress(input: &[u8], upper_output: u64) -> Result<DecompressResult, String> {
    let mut decoder = ZlibDecoder::new(input);
    let mut limited = decoder.by_ref().take(upper_output.saturating_add(1));
    let mut data = Vec::new();
    let read = limited.read_to_end(&mut data).map_err(|e| e.to_string())?;
    let consumed = decoder.total_in();
    if read as u64 > upper_output {
        return Ok(DecompressResult { data, consumed, stopped: true });
    }
    Ok(DecompressResult { data, consumed, stopped: false })
}

pub fn read_ofs_negative_offset(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut pos = 0;
    let mut byte = *bytes.first()?;
    let mut value = (byte & 0x7f) as u64;
    pos += 1;
    while byte & 0x80 != 0 {
        value += 1;
        byte = *bytes.get(pos)?;
        pos += 1;
        value = (value << 7) | (byte & 0x7f) as u64;
    }
    Some((value, pos))
}

pub fn parse_pack(data: &[u8], index_claims: Option<&HashMap<u64, (ObjectId, u32)>>) -> PackParse {
    let mut errors = Vec::new();
    let mut fail = |offset: Option<u64>, code: &str, message: String| errors.push(PackIssue { offset, code: code.to_string(), message });

    if data.len() < 32 || &data[..4] != b"PACK" {
        fail(None, "bad_pack_header", "missing PACK magic or file too short".into());
        return PackParse {
            version: 0, object_count: 0, checksum_ok: false,
            actual_checksum: ObjectId::ZERO, stored_checksum: ObjectId::ZERO,
            entries: Vec::new(), errors,
        };
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let stored_checksum = ObjectId::new(data[data.len()-20..].try_into().unwrap());
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, &data[..data.len()-20]);
    let actual_checksum = ObjectId::new(sha1::Digest::finalize(hasher).into());
    let checksum_ok = actual_checksum == stored_checksum;
    if !checksum_ok {
        fail(None, "bad_pack_checksum", format!("pack SHA1 expected {stored_checksum}, computed {actual_checksum}"));
    }

    let mut entries = Vec::new();
    let mut pos = 12usize;
    for index in 0..object_count {
        if pos + 1 >= data.len() - 20 {
            fail(Some(pos as u64), "truncated_pack", format!("entry {index} header outside pack trailer"));
            break;
        }
        let offset = pos;
        let first = data[pos];
        let code = (first >> 4) & 7;
        let Some(kind) = ObjectType::from_code(code) else {
            fail(Some(offset as u64), "unknown_object_type", format!("type code {code}"));
            break;
        };
        let Some((declared_size, varint_len)) = read_size(&data[pos..], 4) else {
            fail(Some(offset as u64), "bad_size_varint", "truncated object size".into());
            break;
        };
        let mut header_size = varint_len;
        pos += varint_len;

        let mut negative_offset = None;
        let mut base_offset = None;
        let mut ref_base = None;
        if kind == ObjectType::OfsDelta {
            let Some((distance, used)) = read_ofs_negative_offset(&data[pos..]) else {
                fail(Some(offset as u64), "bad_ofs_delta", "truncated negative offset".into());
                break;
            };
            negative_offset = Some(distance);
            base_offset = Some(offset as u64 - distance);
            header_size += used;
            pos += used;
            if base_offset.unwrap() < 12 || base_offset.unwrap() >= offset as u64 {
                fail(Some(offset as u64), "ofs_out_of_bounds", format!("base offset {} is outside pack", base_offset.unwrap()));
            }
        } else if kind == ObjectType::RefDelta {
            if pos + 20 > data.len() - 20 {
                fail(Some(offset as u64), "bad_ref_delta", "truncated ref-delta base oid".into());
                break;
            }
            let oid = ObjectId::new(data[pos..pos+20].try_into().unwrap());
            ref_base = Some(oid);
            header_size += 20;
            pos += 20;
        }

        let payload_offset = pos as u64;
        let upper = if matches!(kind, ObjectType::OfsDelta | ObjectType::RefDelta) {
            declared_size.saturating_add(1)
        } else {
            declared_size.saturating_add(1)
        };
        let decompressed = bounded_decompress(&data[pos..data.len()-20], upper);
        let mut inflated = Vec::new();
        let mut compressed_len = 0u64;
        let mut entry_error = None;
        match decompressed {
            Ok(result) => {
                compressed_len = result.consumed;
                inflated = result.data;
                if result.stopped || inflated.len() as u64 != declared_size {
                    let message = format!("declared inflated size {declared_size}, actual at least/at {}", inflated.len());
                    entry_error = Some(message.clone());
                    fail(Some(offset as u64), "size_spoof", message);
                }
            }
            Err(message) => {
                entry_error = Some(message.clone());
                fail(Some(offset as u64), "zlib_error", message);
            }
        }
        pos = if compressed_len > 0 { (pos as u64 + compressed_len) as usize } else { pos + 1 };
        if pos > data.len() - 20 {
            fail(Some(offset as u64), "zlib_boundary", "compressed object crosses pack trailer".into());
            pos = data.len() - 20;
        }
        if let Some((_, expected_crc)) = index_claims.and_then(|map| map.get(&(offset as u64))) {
            let actual_crc = crc32fast::hash(&data[offset..pos]);
            if actual_crc != *expected_crc {
                let message = format!("CRC32 expected {expected_crc:08x}, computed {actual_crc:08x}");
                if entry_error.is_none() { entry_error = Some(message.clone()); }
                fail(Some(offset as u64), "crc_mismatch", message);
            }
        }
        entries.push(PackEntry {
            offset: offset as u64,
            end_offset: pos as u64,
            payload_offset,
            header_size: header_size as u64,
            kind,
            declared_size,
            inflated,
            compressed_len,
            negative_offset,
            base_offset,
            ref_base,
            error: entry_error,
        });
    }
    if entries.len() as u32 != object_count {
        fail(None, "object_count_mismatch", format!("header declares {object_count}, parsed {}", entries.len()));
    }
    PackParse { version, object_count, checksum_ok, actual_checksum, stored_checksum, entries, errors }
}
