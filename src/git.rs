//! Low-level git primitives implemented from scratch (no system git):
//! CRC32 (IEEE), pack size/offset varints, zlib-boundary-aware inflate,
//! loose object parsing, and delta instruction decoding/application.

use crate::error::Result;

// ---------------- CRC32 (IEEE 802.3, as used by git pack indexes) ----------------

pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        Crc32 { state: 0xffff_ffff }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let mut c = self.state ^ b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            self.state = c;
        }
    }
    pub fn finish(&self) -> u32 {
        self.state ^ 0xffff_ffff
    }
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(bytes);
    c.finish()
}

// ---------------- pack header varints ----------------

/// Decode the type + size header of a packed object.
/// Returns `(object_type_id, size, header_len_bytes)`.
pub fn decode_pack_header(data: &[u8]) -> Result<(u8, u64, usize)> {
    if data.is_empty() {
        return Err("truncated pack object header".into());
    }
    let type_id = (data[0] >> 4) & 0x7;
    let mut size: u64 = (data[0] & 0x0f) as u64;
    let mut shift: u32 = 4;
    let mut i = 1usize;
    while data[i - 1] & 0x80 != 0 {
        let b = *data.get(i).ok_or("truncated pack object size varint")?;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        i += 1;
        if i > 10 {
            return Err("object size varint too long".into());
        }
    }
    Ok((type_id, size, i))
}

/// Decode an ofs-delta negative-offset varint beginning at `data[0]`.
pub fn decode_ofs_delta(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err("truncated ofs-delta offset".into());
    }
    let mut offset: u64 = (data[0] & 0x7f) as u64;
    let mut i = 0usize;
    while data[i] & 0x80 != 0 {
        i += 1;
        let b = *data.get(i).ok_or("truncated ofs-delta offset varint")?;
        offset = offset.wrapping_add(1);
        offset = (offset << 7) | (b & 0x7f) as u64;
    }
    Ok((offset, i + 1))
}

// ---------------- zlib boundary-aware inflate ----------------

pub struct Inflated {
    pub out: Vec<u8>,
    pub consumed: usize,
}

/// Inflate a single zlib stream from the front of `data`, returning the exact
/// number of compressed input bytes consumed (the zlib stream boundary) so the
/// next pack object's offset is known.
pub fn inflate_stream(data: &[u8]) -> Result<Inflated> {
    use flate2::{Decompress, FlushDecompress};
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut in_pos = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        let out_before = dec.total_out();
        let status = dec
            .decompress(&data[in_pos..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        in_pos = dec.total_in() as usize;
        out.extend_from_slice(&buf[..(dec.total_out() - out_before) as usize]);
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok => {
                if in_pos >= data.len() {
                    return Err("zlib stream ended without terminator".into());
                }
            }
            flate2::Status::BufError => {
                return Err("zlib buffer error (likely truncated stream)".into());
            }
        }
    }
    Ok(Inflated { out, consumed: in_pos })
}

/// Deflate `data` as a zlib stream (used by the test pack builder).
pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

// ---------------- loose objects ----------------

/// Parse a loose object's inflated body: `"<type> <size>\0<payload>"`.
pub fn parse_loose_body(body: &[u8]) -> Result<(crate::types::ObjType, Vec<u8>)> {
    use crate::types::ObjType;
    let nul = body
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object missing NUL terminator")?;
    let header = std::str::from_utf8(&body[..nul]).map_err(|_| "loose header not utf8")?;
    let (t, l) = header
        .split_once(' ')
        .ok_or("loose header malformed")?;
    let typ = ObjType::parse(t).ok_or("loose header unknown type")?;
    let claimed: u64 = l.parse().map_err(|_| "loose header bad size")?;
    let payload = &body[nul + 1..];
    if claimed as usize != payload.len() {
        return Err(format!(
            "loose object size deception: header claims {claimed} bytes, actual {}",
            payload.len()
        )
        .into());
    }
    Ok((typ, payload.to_vec()))
}

// ---------------- delta decoding/application ----------------

#[derive(Clone, Debug)]
pub struct DeltaCmd {
    pub kind: &'static str,
    /// Byte range within the delta stream this instruction occupies.
    pub cmd_start: usize,
    pub cmd_end: usize,
    /// For copy: range in the base; for insert: the inserted literal bytes.
    pub src_off: usize,
    pub src_len: usize,
}

#[derive(Debug)]
pub struct AppliedDelta {
    pub base_size: usize,
    pub result_size: usize,
    pub cmds: Vec<DeltaCmd>,
    pub out: Vec<u8>,
}

/// Decode and apply a git delta against `base`, recording every instruction's
/// delta-stream range, base range and output length.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta> {
    let mut p = 0usize;
    let mut read_var = |p: &mut usize| -> Result<u64> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = *delta
                .get(*p)
                .ok_or("delta varint truncated")?;
            *p += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(v)
    };
    let base_size = read_var(&mut p)? as usize;
    let result_size = read_var(&mut p)? as usize;
    if base_size != base.len() {
        return Err(format!(
            "delta base size mismatch: delta header says {base_size}, base is {} (size deception?)",
            base.len()
        )
        .into());
    }
    let mut cmds = Vec::new();
    let mut out = Vec::with_capacity(result_size);
    while p < delta.len() {
        let cmd_start = p;
        let op = delta[p];
        p += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut off: u32 = 0;
            let mut len: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    off |= (*delta.get(p).ok_or("copy opcode truncated")? as u32) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    len |= (*delta.get(p).ok_or("copy opcode truncated")? as u32) << (8 * i);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let end = off as usize + len as usize;
            if end > base.len() {
                return Err(format!(
                    "copy opcode out of base range: off={off} len={len} base_len={}",
                    base.len()
                )
                .into());
            }
            out.extend_from_slice(&base[off as usize..end]);
            cmds.push(DeltaCmd {
                kind: "copy",
                cmd_start,
                cmd_end: p,
                src_off: off as usize,
                src_len: len as usize,
            });
        } else if op != 0 {
            // insert literal
            let len = op as usize;
            if p + len > delta.len() {
                return Err("insert opcode truncated".into());
            }
            out.extend_from_slice(&delta[p..p + len]);
            cmds.push(DeltaCmd {
                kind: "insert",
                cmd_start,
                cmd_end: p + len,
                src_off: 0,
                src_len: len,
            });
            p += len;
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
    }
    if out.len() != result_size {
        return Err(format!(
            "delta result size mismatch: header claims {result_size}, produced {} (size deception?)",
            out.len()
        )
        .into());
    }
    Ok(AppliedDelta {
        base_size,
        result_size,
        cmds,
        out,
    })
}
