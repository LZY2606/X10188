use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use std::io::Read;

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackHeader {
    pub version: u32,
    pub object_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackObjectHeader {
    pub kind: u8,
    pub declared_size: u64,
    pub header_end: usize,
    pub ofs_distance: Option<u64>,
    pub ref_base: Option<[u8; 20]>,
}

pub fn type_name(kind: u8) -> &'static str {
    match kind {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn read_size_encoding(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        if pos >= data.len() {
            return Err("truncated size encoding".into());
        }
        let byte = data[pos];
        pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding is too long".into());
        }
    }
}

pub fn write_size_encoding(mut value: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value != 0 {
        let last = bytes.last_mut().unwrap();
        *last |= 0x80;
        bytes.push((value & 0x7f) as u8);
        value >>= 7;
    }
    out.extend_from_slice(&bytes);
}

pub fn parse_pack_header(data: &[u8]) -> Result<PackHeader, String> {
    if data.len() < 12 {
        return Err("pack header is truncated".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("missing PACK magic".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    Ok(PackHeader { version, object_count })
}

pub fn parse_object_header(data: &[u8], offset: usize) -> Result<PackObjectHeader, String> {
    if offset >= data.len() {
        return Err("object offset is outside pack".into());
    }
    let (first_word, mut pos) = read_size_encoding(data, offset)?;
    let kind = ((first_word >> 4) & 0x07) as u8;
    let declared_size = (first_word & 0x0f) | (first_word >> 7);
    if !(1..=7).contains(&kind) || kind == 5 {
        return Err(format!("reserved or invalid object type {kind}"));
    }
    let mut ofs_distance = None;
    let mut ref_base = None;
    if kind == OBJ_OFS_DELTA {
        let mut pos_byte = pos;
        if pos_byte >= data.len() {
            return Err("truncated ofs-delta header".into());
        }
        let mut byte = data[pos_byte];
        pos_byte += 1;
        let mut distance = u64::from(byte & 0x7f);
        while byte & 0x80 != 0 {
            if pos_byte >= data.len() {
                return Err("truncated ofs-delta distance".into());
            }
            byte = data[pos_byte];
            pos_byte += 1;
            distance = distance.wrapping_add(1);
            distance = distance.wrapping_shl(7);
            distance |= u64::from(byte & 0x7f);
        }
        pos = pos_byte;
        ofs_distance = Some(distance);
    } else if kind == OBJ_REF_DELTA {
        if pos + 20 > data.len() {
            return Err("truncated ref-delta base name".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[pos..pos + 20]);
        pos += 20;
        ref_base = Some(oid);
    }
    Ok(PackObjectHeader {
        kind,
        declared_size,
        header_end: pos,
        ofs_distance,
        ref_base,
    })
}

pub fn zlib_inflate_from(data: &[u8], start: usize) -> Result<(Vec<u8>, usize, Option<String>), String> {
    let mut decoder = ZlibDecoder::new(&data[start..]);
    let mut out = Vec::new();
    match decoder.read_to_end(&mut out) {
        Ok(_) => {
            let consumed = decoder.total_in() as usize;
            Ok((out, start + consumed, None))
        }
        Err(err) => {
            let consumed = decoder.total_in() as usize;
            Err(format!("{err}|partial={consumed}"))
        }
    }
}

pub fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, data).unwrap();
    encoder.finish().unwrap()
}

pub fn git_hash(kind: &str, data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(kind.as_bytes());
    hasher.update(b" ");
    hasher.update(data.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hex_to_oid(hex: &str) -> Result<[u8; 20], String> {
    let bytes = hex::decode(hex).map_err(|err| err.to_string())?;
    if bytes.len() != 20 {
        return Err("object id must be 20 bytes".into());
    }
    Ok(bytes.try_into().unwrap())
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn preview_bytes(data: &[u8], limit: usize) -> String {
    let shown = &data[..data.len().min(limit)];
    let mut value = String::new();
    for &byte in shown {
        if (0x20..=0x7e).contains(&byte) || byte == b'\n' || byte == b'\t' {
            value.push(byte as char);
        } else {
            value.push_str(&format!("\\x{byte:02x}"));
        }
    }
    if data.len() > shown.len() {
        value.push('…');
    }
    value
}
