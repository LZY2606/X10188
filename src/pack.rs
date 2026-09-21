//! Raw pack file parsing: header, entry headers, ofs/ref delta refs and
//! zlib boundaries. No object id resolution happens here.

use crate::git::ObjType;
use crate::zlibm;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PackEntry {
    pub index: usize,
    pub header_offset: usize,
    pub data_offset: usize,
    pub end_offset: usize,
    #[serde(serialize_with = "serialize_obj_type")]
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub crc32: u32,
    pub ref_base: Option<String>,
    pub negative_offset: Option<i64>,
    pub inflated_len: usize,
    pub inflate_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RawPack {
    pub version: u32,
    pub object_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_checksum: String,
    pub computed_checksum: String,
    /// Error that prevented parsing more entries (if any).
    pub fatal: Option<String>,
    pub bytes_len: usize,
}

pub struct ParseLimits {
    pub inflate_limit: usize,
    pub max_entries: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        ParseLimits {
            inflate_limit: 1 << 30,
            max_entries: 1_000_000,
        }
    }
}

pub fn parse_pack(data: &[u8], limits: &ParseLimits) -> Result<RawPack, String> {
    if data.len() < 12 + 20 {
        return Err("pack too small for header and trailer".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("bad pack signature".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if object_count as usize > limits.max_entries {
        return Err(format!("pack declares {} objects, over limit", object_count));
    }

    let mut entries = Vec::with_capacity(object_count as usize);
    let mut pos = 12usize;
    let mut fatal: Option<String> = None;

    for index in 0..object_count as usize {
        let header_offset = pos;
        if pos >= data.len() - 20 {
            fatal = Some(format!("entry {index}: header runs into trailer"));
            break;
        }
        let first = data[pos];
        let mut size = (first & 0x0f) as u64;
        let code = (first >> 4) & 0x07;
        let obj_type = ObjType::from_pack_code(code)
            .ok_or_else(|| format!("entry {index}: invalid type code {code}"))?;
        let mut shift = 4u32;
        pos += 1;
        let mut b = first;
        while b & 0x80 != 0 {
            if pos >= data.len() - 20 {
                fatal = Some(format!("entry {index}: truncated size header"));
                break;
            }
            b = data[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        if fatal.is_some() {
            break;
        }

        let mut ref_base: Option<String> = None;
        let mut negative_offset: Option<i64> = None;
        match obj_type {
            ObjType::RefDelta => {
                if pos + 20 > data.len() - 20 {
                    fatal = Some(format!("entry {index}: truncated ref-delta base oid"));
                    break;
                }
                ref_base = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            ObjType::OfsDelta => {
                if pos >= data.len() - 20 {
                    fatal = Some(format!("entry {index}: truncated ofs-delta distance"));
                    break;
                }
                let fb = data[pos];
                pos += 1;
                let mut dist: i64 = (fb & 0x7f) as i64;
                let mut cb = fb;
                while cb & 0x80 != 0 {
                    if pos >= data.len() - 20 {
                        fatal = Some(format!("entry {index}: truncated ofs-delta distance"));
                        break;
                    }
                    cb = data[pos];
                    pos += 1;
                    dist = (dist.wrapping_add(1) << 7) + (cb & 0x7f) as i64;
                }
                if fatal.is_some() {
                    break;
                }
                negative_offset = Some(dist);
            }
            _ => {}
        }

        let data_offset = pos;
        let inflated = zlibm::inflate_member(data, pos, limits.inflate_limit.max(size as usize + 1));
        let mut crc = crc32fast::Hasher::new();
        let (end_offset, inflated_len, inflate_error) = match &inflated {
            Ok(z) => {
                crc.update(&data[header_offset..data_offset + z.consumed]);
                let err = if z.data.len() as u64 != size {
                    Some(format!(
                        "size spoof: pack header declares {size} bytes but inflated {} bytes",
                        z.data.len()
                    ))
                } else {
                    None
                };
                (data_offset + z.consumed, z.data.len(), err)
            }
            Err(e) => {
                crc.update(&data[header_offset..data_offset]);
                (data_offset, 0, Some(e.clone()))
            }
        };
        let crc32 = crc.finalize();

        let fatal_here = inflate_error
            .as_ref()
            .filter(|_| inflated.is_err())
            .map(|e| format!("entry {index}: zlib boundary lost ({e})"));
        entries.push(PackEntry {
            index,
            header_offset,
            data_offset,
            end_offset,
            obj_type,
            declared_size: size,
            crc32,
            ref_base,
            negative_offset,
            inflated_len,
            inflate_error: inflate_error.clone(),
        });
        if let Some(msg) = fatal_here {
            fatal = Some(msg);
            break;
        }
        pos = end_offset;
    }

    let computed = sha1_at_bytes(&data[..pos.max(12)]);
    let trailer = if data.len() >= 20 {
        hex::encode(&data[data.len() - 20..])
    } else {
        String::new()
    };
    let computed_checksum = if fatal.is_none() {
        hex::encode(sha1_of(&data[..data.len() - 20]))
    } else {
        hex::encode(computed)
    };

    Ok(RawPack {
        version,
        object_count,
        entries,
        trailer_checksum: trailer,
        computed_checksum,
        fatal,
        bytes_len: data.len(),
    })
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    out
}

fn sha1_at_bytes(data: &[u8]) -> [u8; 20] {
    sha1_of(data)
}

fn serialize_obj_type<S: serde::Serializer>(t: &ObjType, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(t.name())
}
