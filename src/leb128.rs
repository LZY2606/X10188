//! Git pack variable-length integer helpers (size headers + ofs-delta distances).

use std::io::{self, Read};

#[derive(Debug)]
pub struct LebError(pub String);

impl std::fmt::Display for LebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "leb128: {}", self.0)
    }
}
impl std::error::Error for LebError {}

/// Read a packfile size header given the already-consumed first byte.
/// Layout of first byte: MSB=continuation, bits 4..6=type, low 4 bits=size.
pub fn read_pack_size(first: u8, data: &[u8], pos: &mut usize) -> Result<u64, LebError> {
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cur = first;
    while cur & 0x80 != 0 {
        if *pos >= data.len() {
            return Err(LebError("truncated size header".into()));
        }
        cur = data[*pos];
        *pos += 1;
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err(LebError("size header overflow".into()));
        }
    }
    Ok(size)
}

/// Encode a packfile entry header (type + size).
pub fn write_pack_header(obj_type: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = (obj_type << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest != 0 {
        let mut b = (rest as u8) & 0x7f;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Decode an ofs-delta negative-offset distance starting at `data[*pos]`.
pub fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Result<u64, LebError> {
    let first = read_u8(data, pos)?;
    let mut dist = (first & 0x7f) as u64;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = read_u8(data, pos)?;
        dist = dist
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| LebError("ofs distance overflow".into()))?;
        dist |= (cur & 0x7f) as u64;
    }
    Ok(dist)
}

/// Encode an ofs-delta negative-offset distance (Git's +1 encoding).
pub fn write_ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut buf = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        buf.push(0x80 | (((distance - 1) & 0x7f) as u8));
        distance >>= 7;
    }
    buf.reverse();
    buf
}

/// Generic unsigned LEB128 used inside delta payloads (base/result sizes).
pub fn read_delta_varint(data: &[u8], pos: &mut usize) -> Result<u64, LebError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = read_u8(data, pos)?;
        if shift >= 64 {
            return Err(LebError("delta varint overflow".into()));
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

pub fn write_delta_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
    out
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, LebError> {
    if *pos >= data.len() {
        return Err(LebError("unexpected end of data".into()));
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}

/// Read from a `Read` exactly enough bytes (used by loose object parsing).
pub fn read_delta_varint_r<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        result |= ((b[0] & 0x7f) as u64) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}
