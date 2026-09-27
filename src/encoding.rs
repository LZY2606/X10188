use flate2::write::ZlibEncoder;
use flate2::Compression;
use flate2::Decompress;
use sha1::{Digest, Sha1};
use std::io::Write;

use crate::types::{GitType, Oid};

/// Read the Git pack entry header varint: type in bits 4..6 of the first byte,
/// MSB continuation across following bytes (little-endian base-128).
pub fn read_entry_header(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= data.len() {
        return Err("unexpected end of pack entry header".into());
    }
    let first = data[pos];
    let kind = (first >> 4) & 0x07;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cur = first;
    while cur & 0x80 != 0 {
        pos += 1;
        if pos >= data.len() {
            return Err("truncated pack entry varint".into());
        }
        cur = data[pos];
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
    }
    pos += 1;
    Ok((kind, size, pos))
}

/// Encode a pack entry header (type code + inflated size).
pub fn write_entry_header(out: &mut Vec<u8>, kind: u8, size: u64) {
    let first = (size as u8 & 0x0f) | (kind << 4);
    let mut rest = size >> 4;
    out.push(first | if rest != 0 { 0x80 } else { 0 });
    while rest != 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

/// Read an n-byte big-endian unsigned integer (n <= 8).
pub fn read_be(data: &[u8], n: usize) -> u64 {
    let mut v = 0u64;
    for &b in data.iter().take(n) {
        v = (v << 8) | b as u64;
    }
    v
}

/// ofs-delta negative distance varint: every byte except the last has its MSB
/// set; each continuation adds 1 before the 7-bit shift.
pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= data.len() {
        return Err("missing ofs-delta distance".into());
    }
    let mut c = data[pos];
    let mut ofs = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        pos += 1;
        if pos >= data.len() {
            return Err("truncated ofs-delta distance".into());
        }
        c = data[pos];
        ofs = (ofs + 1) << 7 | (c & 0x7f) as u64;
    }
    pos += 1;
    Ok((ofs, pos))
}

pub fn write_ofs_distance(out: &mut Vec<u8>, distance: u64) {
    let mut bytes = vec![(distance & 0x7f) as u8];
    let mut rest = distance >> 7;
    while rest != 0 {
        rest -= 1;
        bytes.push((rest & 0x7f) as u8);
        rest >>= 7;
    }
    bytes.reverse();
    let last = bytes.len() - 1;
    for (i, b) in bytes.into_iter().enumerate() {
        out.push(b | if i != last { 0x80 } else { 0 });
    }
}

/// Incrementally decompress a zlib stream, reporting both the number of input
/// bytes consumed (the exact zlib boundary) and the inflated output.
pub fn zlib_inflate_range(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 16 * 1024;
    let mut input_pos = 0usize;
    loop {
        let mut tmp = vec![0u8; chunk];
        let out_before = dec.total_out();
        let in_before = dec.total_in();
        let status = dec
            .decompress(&data[input_pos..], &mut tmp, flate2::FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        input_pos += (dec.total_in() - in_before) as usize;
        let produced = (dec.total_out() - out_before) as usize;
        out.extend_from_slice(&tmp[..produced]);
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok if dec.total_in() == in_before => {
                return Err("zlib stalled without progress".into())
            }
            flate2::Status::Ok => {}
            flate2::Status::BufError => {
                return Err("zlib buffer error (truncated stream)".into())
            }
        }
    }
    Ok((out, dec.total_in() as usize))
}

pub fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Compute a Git object id: sha1("<type> <len>\0<content>").
pub fn git_object_id(kind: GitType, content: &[u8]) -> Oid {
    debug_assert!(!kind.is_delta());
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&h.finalize());
    oid
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("bad hex: {e}"))
}
