//! Low level Git binary format primitives.
//!
//! Everything here is implemented from the on-disk specification, without
//! shelling out to the system `git` binary.

use flate2::{Decompress, FlushDecompress};
use sha1::{Digest, Sha1};

/// Object type ids used inside pack object headers (3-bit field).
pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> String {
    match t {
        OBJ_COMMIT => "commit".to_string(),
        OBJ_TREE => "tree".to_string(),
        OBJ_BLOB => "blob".to_string(),
        OBJ_TAG => "tag".to_string(),
        OBJ_OFS_DELTA => "ofs-delta".to_string(),
        OBJ_REF_DELTA => "ref-delta".to_string(),
        other => format!("unknown({})", other),
    }
}

/// Decode a pack entry header starting at `buf[start]`.
///
/// Returns `(type_id, declared_size, header_end)`.
pub fn decode_pack_header(buf: &[u8], start: usize) -> Result<((u8, u64, usize)), String> {
    let mut i = start;
    let first = *buf.get(i).ok_or_else(|| "object header truncated".to_string())?;
    i += 1;
    let type_id = (first >> 4) & 0x7;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift = 4;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *buf.get(i).ok_or_else(|| "size varint truncated".to_string())?;
        i += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((type_id, size, i))
}

/// Decode the negative-offset varint used by ofs-delta.
/// Returns `(negative_distance, end)` where `base_offset = offset - distance`.
pub fn decode_ofs_distance(buf: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut i = start;
    let mut byte = *buf.get(i).ok_or_else(|| "ofs varint truncated".to_string())?;
    i += 1;
    let mut distance: u64 = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if distance > (u64::MAX >> 7) - 1 {
            return Err("ofs distance overflow".to_string());
        }
        byte = *buf.get(i).ok_or_else(|| "ofs varint truncated".to_string())?;
        i += 1;
        distance = ((distance + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok((distance, i))
}

/// Decode a plain LSB 7-bit varint as used by delta headers.
pub fn decode_size_varint(buf: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut i = start;
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(i).ok_or_else(|| "delta size varint truncated".to_string())?;
        i += 1;
        if shift >= 64 && (byte & 0x7f) != 0 {
            return Err("delta size overflow".to_string());
        }
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((size, i))
}

/// Compute the Git object id (`sha1("<type> <len>\0<content>")`).
pub fn git_object_id(type_str: &str, content: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(type_str.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    let out = hasher.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&out);
    id
}

// ---------------------------------------------------------------------------
// CRC32 (IEEE, reflected) — bytewise table, no external dependency needed.
// ---------------------------------------------------------------------------

struct Crc32 {
    table: [u32; 256],
}

impl Crc32 {
    fn new() -> Self {
        let mut table = [0u32; 256];
        for n in 0..256u32 {
            let mut c = n;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            table[n as usize] = c;
        }
        Crc32 { table }
    }

    fn checksum(&self, data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &b in data {
            let idx = ((crc ^ b as u32) & 0xff) as usize;
            crc = (crc >> 8) ^ self.table[idx];
        }
        crc ^ 0xffff_ffff
    }
}

/// Result of inflating one zlib stream embedded in a larger byte slice.
pub struct Inflated {
    pub data: Vec<u8>,
    /// Number of compressed bytes consumed (start of stream .. end of stream).
    pub consumed: usize,
    /// Expected inflated size (from the object header).
    pub declared: u64,
    /// True if the inflated output exceeded the hard cap (`cap`).
    pub overran_cap: bool,
}

/// Inflate exactly one zlib stream inside `buf[start..]`.
///
/// `cap` is a hard allocation ceiling used to defend against size spoofing:
/// decompression stops and `overran_cap = true` is reported if more than `cap`
/// bytes would be produced. The caller still learns the exact zlib boundary.
pub fn inflate_zlib(buf: &[u8], start: usize, declared: u64, cap: usize) -> Result<Inflated, String> {
    let mut decomp = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut input_pos = start;
    let hard_cap = cap.max(declared as usize);
    loop {
        let before_in = decomp.total_in();
        let in_before = input_pos;
        let chunk: &[u8] = &buf[input_pos..];
        if chunk.is_empty() {
            return Err("zlib stream truncated (no end marker)".to_string());
        }
        let out_before = out.len();
        let want = 4096.min(hard_cap.saturating_sub(out.len()).max(1));
        out.resize(out_before + want, 0);
        let result = decomp.decompress(chunk, &mut out[out_before..], FlushDecompress::None);
        let used = (decomp.total_in() - before_in) as usize;
        input_pos = in_before + used;
        let tail = match &result {
            Ok(flate2::Status::Ok) => 0,
            Ok(flate2::Status::StreamEnd) => 0,
            Ok(flate2::Status::BufError) => want,
            Ok(other) => return Err(format!("zlib status: {:?}", other)),
            Err(e) => return Err(format!("zlib error: {}", e)),
        };
        out.truncate(out_before + want - tail);
        if out.len() > hard_cap {
            out.truncate(hard_cap + 1);
            return Ok(Inflated {
                data: out,
                consumed: input_pos - start,
                declared,
                overran_cap: true,
            });
        }
        if let Ok(flate2::Status::StreamEnd) = result {
            break;
        }
    }
    Ok(Inflated {
        data: out,
        consumed: input_pos - start,
        declared,
        overran_cap: false,
    })
}

/// CRC32 over `data`, compatible with the per-object CRC stored in pack .idx.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Crc32> = OnceLock::new();
    TABLE.get_or_init(Crc32::new).checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn roundtrip_zlib_boundary() {
        let payload = b"hello world".repeat(100);
        let mut buf = vec![0u8, 0xff];
        buf.extend_from_slice(&zlib(&payload));
        buf.push(0xaa);
        let inf = inflate_zlib(&buf, 2, payload.len() as u64, 1 << 20).unwrap();
        assert_eq!(inf.data, payload);
        assert_eq!(&buf[2 + inf.consumed], &[0xaa]);
        assert!(!inf.overran_cap);
    }

    #[test]
    fn git_id_matches_known_blob() {
        // The well-known empty blob oid.
        let id = git_object_id("blob", b"");
        assert_eq!(hex::encode(id), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }
}
