//! Low-level Git object format helpers: object ids, varints, zlib.
//! Pure Rust, never shells out to the system `git`.

use flate2::{Decompress, Compression, write::ZlibEncoder};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        other => match other {
            5 => "reserved-5",
            _ => "unknown",
        },
    }
}

pub fn canonical_type_name(t: u8) -> Option<&'static str> {
    match t {
        OBJ_COMMIT => Some("commit"),
        OBJ_TREE => Some("tree"),
        OBJ_BLOB => Some("blob"),
        OBJ_TAG => Some("tag"),
        _ => None,
    }
}

/// Git's loose-object header: `<type> <size>\0`.
pub fn object_header(kind: u8, size: usize) -> Vec<u8> {
    format!("{} {}\0", type_name(kind), size).into_bytes()
}

/// Compute the Git object id (sha1 of `<type> <size>\0<content>`).
pub fn git_object_id(kind: u8, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(type_name(kind).as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Encode a size in the 7-bit continuation encoding used by loose object headers
/// of pack entries (the size part of the entry header).
pub fn encode_size(mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
    out
}

/// Decode a 7-bit size varint. Returns (value, bytes_consumed).
pub fn decode_size(data: &[u8]) -> Option<(u64, usize)> {
    let mut shift = 0u32;
    let mut value = 0u64;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Decode the ofs-delta negative-offset varint:
/// first byte: top bit set, then 7-bit groups with an implicit 1 prepended.
/// Returns the (positive) distance backwards and bytes consumed.
pub fn decode_ofs(data: &[u8]) -> Option<(u64, usize)> {
    let mut offset = 0u64;
    for (i, &b) in data.iter().enumerate() {
        if i == 0 {
            offset = (b & 0x7f) as u64;
        } else {
            offset = offset.wrapping_add(1).wrapping_shl(7) | (b & 0x7f) as u64;
        }
        if b & 0x80 == 0 {
            return Some((offset, i + 1));
        }
        if i >= 9 {
            return None;
        }
    }
    None
}

/// Encode the ofs-delta negative-offset varint.
pub fn encode_ofs(mut offset: u64) -> Vec<u8> {
    let mut bytes = vec![(offset & 0x7f) as u8];
    offset >>= 7;
    while offset != 0 {
        offset -= 1;
        bytes.push((0x80 | (offset & 0x7f)) as u8);
        offset >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Result of a zlib stream decode, including the exact compressed boundary.
pub struct ZlibResult {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub clean_end: bool,
}

/// Decode one zlib stream beginning at `input[pos]`. `max_output` guards against
/// decompression bombs / spoofed sizes. The returned `consumed` is the exact
/// number of compressed bytes up to and including the stream end marker.
pub fn zlib_decode_at(input: &[u8], pos: usize, max_output: usize) -> std::io::Result<ZlibResult> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut cur = pos;
    let clean_end;
    loop {
        let out_before = dec.total_out();
        let mut tmp = [0u8; 65536];
        let status = dec
            .decompress(&input[cur..], &mut tmp, flate2::FlushDecompress::None)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let consumed_now = (dec.total_in()) as usize - (cur - pos);
        cur = pos + dec.total_in() as usize;
        out.extend_from_slice(&tmp[..(dec.total_out() - out_before) as usize]);
        if out.len() > max_output {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("zlib output exceeds safety cap of {max_output} bytes"),
            ));
        }
        if status == flate2::Status::StreamEnd {
            clean_end = true;
            break;
        }
        if consumed_now == 0 && (dec.total_out() - out_before) == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zlib stream made no progress or is truncated",
            ));
        }
    }
    Ok(ZlibResult {
        data: out,
        consumed: cur - pos,
        clean_end,
    })
}

/// zlib-compress a payload (used by the in-repo synthetic pack builder/tests).
pub fn zlib_encode(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Git CRC used in pack index tables (CRC32 of the packed object record).
pub fn crc32(data: &[u8]) -> u32 {
    // Small dependency-free IEEE CRC32 to avoid pulling another crate.
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Build a loose-object file payload: zlib(`<type> <size>\0<content>`).
pub fn loose_payload(kind: u8, content: &[u8]) -> Vec<u8> {
    let mut full = object_header(kind, content.len());
    full.extend_from_slice(content);
    zlib_encode(&full)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_roundtrip() {
        for v in [0u64, 1, 127, 128, 16384, u64::MAX >> 3] {
            let enc = encode_size(v);
            let (dec, n) = decode_size(&enc).unwrap();
            assert_eq!(dec, v);
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn ofs_roundtrip() {
        for v in [1u64, 2, 127, 128, 255, 1000, 1 << 20, (1u64 << 30) + 123] {
            let enc = encode_ofs(v);
            let (dec, n) = decode_ofs(&enc).unwrap();
            assert_eq!(dec, v, "offset {v}");
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn zlib_boundary_exact() {
        let a = zlib_encode(b"hello world".as_slice());
        let b = zlib_encode(b"second object".as_slice());
        let mut combined = a.clone();
        combined.extend_from_slice(&b);
        let r1 = zlib_decode_at(&combined, 0, 1 << 20).unwrap();
        assert_eq!(r1.data, b"hello world");
        assert_eq!(r1.consumed, a.len());
        let r2 = zlib_decode_at(&combined, r1.consumed, 1 << 20).unwrap();
        assert_eq!(r2.data, b"second object");
        assert_eq!(r1.consumed + r2.consumed, combined.len());
    }

    #[test]
    fn blob_id_known_vector() {
        // Empty blob id is well known: e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
        let id = git_object_id(OBJ_BLOB, b"");
        assert_eq!(to_hex(&id), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }
}
