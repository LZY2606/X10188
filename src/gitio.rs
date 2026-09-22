//! Low-level Git binary helpers: type codes, variable integers, zlib
//! boundaries and object-id hashing. Everything in this file (and the
//! neighboring `pack`/`idx`/`loose`/`delta` modules) is a hand-written
//! implementation; the system `git` binary is never invoked.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

pub fn type_name(code: u8) -> String {
    match ObjType::from_code(code) {
        Some(t) => t.name().to_string(),
        None => format!("unknown({code})"),
    }
}

pub fn hex_oid(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn parse_hex_oid(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi << 4 | lo) as u8;
    }
    Some(out)
}

/// Read the 7-bit little-endian continuation encoding used for object
/// sizes. Returns `(value, bytes_consumed)`.
pub fn read_le_base128(b: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut value = 0u64;
    let mut i = pos;
    loop {
        if i >= b.len() {
            return Err("truncated size varint".into());
        }
        let byte = b[i];
        i += 1;
        if shift >= 64 && (byte & 0x7f) != 0 {
            return Err("size varint overflow".into());
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i - pos));
        }
        if shift > 70 {
            return Err("size varint too long".into());
        }
    }
}

/// Encode an object size (pack entry header / delta size table).
pub fn write_le_base128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Relative-offset encoding used by OFS_DELTA. The first byte contributes
/// bits 6..0 with both continuation bits (0x80 and 0x40) set; following
/// bytes contribute 7 bits each.
pub fn read_ofs_varint(b: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= b.len() {
        return Err("truncated ofs varint".into());
    }
    let first = b[pos];
    let mut i = pos + 1;
    let mut value = (first & 0x7f) as u64;
    if first & 0x80 != 0 {
        loop {
            if i >= b.len() {
                return Err("truncated ofs varint".into());
            }
            let byte = b[i];
            i += 1;
            value = ((value + 1) << 7) | (byte & 0x7f) as u64;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((value, i - pos))
}

pub fn write_ofs_varint(mut ofs: u64, out: &mut Vec<u8>) {
    let mut rev = Vec::new();
    rev.push((ofs & 0x7f) as u8);
    ofs >>= 7;
    while ofs != 0 {
        ofs -= 1;
        rev.push((ofs & 0x7f) as u8);
        ofs >>= 7;
    }
    rev.reverse();
    let last = rev.len() - 1;
    for (i, byte) in rev.into_iter().enumerate() {
        let mut byte = byte;
        if i != last {
            byte |= 0x80;
        }
        if i == 0 {
            byte |= 0x40;
        }
        out.push(byte);
    }
}

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Number of compressed bytes consumed from the input slice.
    pub compressed_len: usize,
    pub stream_end: bool,
    pub error: Option<String>,
}

/// Decompress a zlib stream beginning at `pos`, explicitly reporting the
/// exact byte at which the zlib stream ends (the zlib boundary). Partial
/// output is retained together with the error so callers can still record
/// evidence instead of aborting the whole pack scan.
pub fn inflate_at(b: &[u8], pos: usize) -> Inflated {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let mut stream_end = false;
    let mut error = None;
    loop {
        if pos + consumed >= b.len() {
            error = Some("zlib stream truncated before end".into());
            break;
        }
        let in_before = d.total_in();
        let out_before = d.total_out();
        let mut chunk = [0u8; 16 * 1024];
        match d.decompress(
            &b[pos + consumed..],
            &mut chunk,
            FlushDecompress::None,
        ) {
            Ok(status) => {
                consumed = d.total_in() as usize;
                let produced = (d.total_out() - out_before) as usize;
                let advanced = d.total_in() - in_before;
                out.extend_from_slice(&chunk[..produced]);
                if status == Status::StreamEnd {
                    stream_end = true;
                    break;
                }
                if advanced == 0 && produced == 0 {
                    error = Some("zlib made no progress (corrupt stream)".into());
                    break;
                }
            }
            Err(e) => {
                consumed = d.total_in() as usize;
                error = Some(format!("zlib error: {e}"));
                break;
            }
        }
    }
    Inflated {
        data: out,
        compressed_len: consumed,
        stream_end,
        error,
    }
}

/// Compute the Git object id: `sha1("<type> <len>\0" ++ content)`.
pub fn hash_object(kind: ObjType, content: &[u8]) -> [u8; 20] {
    let name = match kind {
        ObjType::Commit => "commit",
        ObjType::Tree => "tree",
        ObjType::Blob => "blob",
        ObjType::Tag => "tag",
        ObjType::OfsDelta | ObjType::RefDelta => panic!("delta objects are not hashed directly"),
    };
    let mut h = Sha1::new();
    h.update(name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofs_varint_roundtrip() {
        for ofs in [1u64, 2, 127, 128, 255, 256, 4096, 65535, 65536, 1 << 30] {
            let mut buf = Vec::new();
            write_ofs_varint(ofs, &mut buf);
            let (back, n) = read_ofs_varint(&buf, 0).unwrap();
            assert_eq!(back, ofs);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn le_base128_roundtrip() {
        for v in [0u64, 1, 127, 128, 16384, u64::MAX] {
            let mut buf = Vec::new();
            write_le_base128(v, &mut buf);
            let (back, _) = read_le_base128(&buf, 0).unwrap();
            assert_eq!(back, v);
        }
    }
}
