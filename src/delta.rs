//! Git delta encoding (the format used inside ofs-delta/ref-delta objects).
//! Every instruction is recorded with its byte range so analysis steps
//! can be audited later.

use serde::Serialize;

pub fn read_size_varint(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() {
            return Err("truncated size varint in delta".into());
        }
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err("size varint too long".into());
        }
    }
    Ok((size, pos))
}

#[derive(Debug, Clone, Serialize)]
pub struct Instr {
    /// Instruction index within the delta (0 based).
    pub index: usize,
    /// Byte range in the raw delta payload.
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub src_offset: Option<usize>,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct Applied {
    pub output: Vec<u8>,
    pub instructions: Vec<Instr>,
    pub declared_base_size: usize,
    pub declared_target_size: usize,
    pub header_end: usize,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Applied, String> {
    let (base_size, mut pos) = read_size_varint(delta, 0)?;
    let (target_size, after) = read_size_varint(delta, pos)?;
    pos = after;
    let header_end = pos;

    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: header says {base_size}, input is {}",
            base.len()
        ));
    }
    let target = target_size as usize;
    if target_size > (1u64 << 40) {
        return Err("delta target size implausibly large".into());
    }
    let mut out = Vec::with_capacity(target.min(1 << 20));
    let mut instructions = Vec::new();
    let mut idx = 0usize;

    while pos < delta.len() {
        let start = pos;
        let op = delta[pos];
        pos += 1;
        if op == 0 {
            return Err(format!("reserved delta opcode 0 at byte {start}"));
        }
        if op & 0x80 != 0 {
            let mut off: usize = 0;
            let mut size: usize = 0;
            if op & 0x01 != 0 {
                off |= (delta.get(pos).copied().ok_or("truncated copy offset")?) as usize;
                pos += 1;
            }
            if op & 0x02 != 0 {
                off |= ((delta.get(pos).copied().ok_or("truncated copy offset")?) as usize) << 8;
                pos += 1;
            }
            if op & 0x04 != 0 {
                off |= ((delta.get(pos).copied().ok_or("truncated copy offset")?) as usize) << 16;
                pos += 1;
            }
            if op & 0x08 != 0 {
                off |= ((delta.get(pos).copied().ok_or("truncated copy offset")?) as usize) << 24;
                pos += 1;
            }
            if op & 0x10 != 0 {
                size |= (delta.get(pos).copied().ok_or("truncated copy size")?) as usize;
                pos += 1;
            }
            if op & 0x20 != 0 {
                size |= ((delta.get(pos).copied().ok_or("truncated copy size")?) as usize) << 8;
                pos += 1;
            }
            if op & 0x40 != 0 {
                size |= ((delta.get(pos).copied().ok_or("truncated copy size")?) as usize) << 16;
                pos += 1;
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off.checked_add(size).ok_or("copy range overflow")?;
            if end > base.len() {
                return Err(format!(
                    "copy out of base bounds: offset {off} size {size} (base len {})",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off..end]);
            instructions.push(Instr {
                index: idx,
                start,
                end: pos,
                kind: "copy",
                src_offset: Some(off),
                length: size,
            });
        } else {
            let len = op as usize;
            if pos + len > delta.len() {
                return Err("truncated literal insert".into());
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            instructions.push(Instr {
                index: idx,
                start,
                end: pos,
                kind: "insert",
                src_offset: None,
                length: len,
            });
        }
        idx += 1;
    }

    if out.len() != target {
        return Err(format!(
            "size spoof: delta declared target size {target} but instructions produced {}",
            out.len()
        ));
    }
    Ok(Applied {
        output: out,
        instructions,
        declared_base_size: base_size as usize,
        declared_target_size: target,
        header_end,
    })
}

/// Build a minimal delta: literal-only instructions covering `target`.
/// Used by the test fixture kit, never by the parser.
pub fn encode_literal_delta(base_size: usize, target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut write_size = |mut size: usize, buf: &mut Vec<u8>| {
        loop {
            let mut b = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if size == 0 {
                break;
            }
        }
    };
    write_size(base_size, &mut out);
    write_size(target.len(), &mut out);
    for chunk in target.chunks(127) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}
