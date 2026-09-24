//! Git delta instruction parsing, application and serialization.

use crate::leb128::{read_delta_varint, write_delta_varint};

#[derive(Debug, Clone)]
pub enum DeltaOp {
    Copy {
        offset: usize,
        size: usize,
    },
    Insert {
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct ParsedDelta {
    pub base_size: u64,
    pub result_size: u64,
    pub ops: Vec<DeltaOp>,
    /// Byte range of each instruction within the delta payload.
    pub op_ranges: Vec<std::ops::Range<usize>>,
    /// Byte range of the trailing varint headers.
    pub header_range: std::ops::Range<usize>,
}

#[derive(Debug)]
pub struct DeltaError(pub String);

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "delta: {}", self.0)
    }
}
impl std::error::Error for DeltaError {}

pub fn parse(delta: &[u8]) -> Result<ParsedDelta, DeltaError> {
    let mut pos = 0usize;
    let h0 = 0usize;
    let base_size = read_delta_varint(delta, &mut pos)
        .map_err(|e| DeltaError(format!("base size: {}", e)))?;
    let result_size = read_delta_varint(delta, &mut pos)
        .map_err(|e| DeltaError(format!("result size: {}", e)))?;
    let header_end = pos;

    let mut ops = Vec::new();
    let mut op_ranges = Vec::new();
    while pos < delta.len() {
        let start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for i in 0..4 {
                if opcode & (1 << i) != 0 {
                    offset |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if opcode & (1 << (4 + i)) != 0 {
                    size |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push(DeltaOp::Copy { offset, size });
        } else if opcode != 0 {
            let size = opcode as usize;
            if pos + size > delta.len() {
                return Err(DeltaError("insert overruns delta buffer".into()));
            }
            let data = delta[pos..pos + size].to_vec();
            pos += size;
            ops.push(DeltaOp::Insert { data });
        } else {
            return Err(DeltaError("invalid opcode 0x00".into()));
        }
        op_ranges.push(start..pos);
    }
    Ok(ParsedDelta {
        base_size,
        result_size,
        ops,
        op_ranges,
        header_range: h0..header_end,
    })
}

pub fn apply(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, DeltaError> {
    let parsed = parse(delta)?;
    apply_parsed(base, &parsed)
}

pub fn apply_parsed(base: &[u8], parsed: &ParsedDelta) -> Result<Vec<u8>, DeltaError> {
    if base.len() as u64 != parsed.base_size {
        return Err(DeltaError(format!(
            "base size mismatch: header says {} but base is {}",
            parsed.base_size,
            base.len()
        )));
    }
    let mut out = Vec::with_capacity(parsed.result_size as usize);
    for op in &parsed.ops {
        match op {
            DeltaOp::Insert { data } => out.extend_from_slice(data),
            DeltaOp::Copy { offset, size } => {
                let end = offset
                    .checked_add(*size)
                    .ok_or_else(|| DeltaError("copy offset overflow".into()))?;
                if end > base.len() {
                    return Err(DeltaError(format!(
                        "copy out of bounds: base[{}..{}] but base len {}",
                        offset, end, base.len()
                    )));
                }
                out.extend_from_slice(&base[*offset..end]);
            }
        }
        if out.len() as u64 > parsed.result_size {
            return Err(DeltaError(format!(
                "output overruns declared result size {}",
                parsed.result_size
            )));
        }
    }
    if out.len() as u64 != parsed.result_size {
        return Err(DeltaError(format!(
            "output short: declared {} produced {}",
            parsed.result_size,
            out.len()
        )));
    }
    Ok(out)
}

/// Build a minimal delta payload (used by tests / fixture builders).
pub fn make_insert_delta(base_size: u64, result: &[u8]) -> Vec<u8> {
    let mut d = write_delta_varint(base_size);
    d.extend(write_delta_varint(result.len() as u64));
    let mut i = 0usize;
    while i < result.len() {
        let n = (result.len() - i).min(127);
        d.push(n as u8);
        d.extend_from_slice(&result[i..i + n]);
        i += n;
    }
    d
}

/// A delta that copies the whole base then appends `extra` (chaining test).
pub fn make_copy_append_delta(base_size: u64, extra: &[u8]) -> Vec<u8> {
    let mut d = write_delta_varint(base_size);
    let result_size = base_size + extra.len() as u64;
    d.extend(write_delta_varint(result_size));
    let mut size = base_size as usize;
    let mut offset = 0usize;
    // opcode 0x80 with offset low bits + size low bits, avoiding the 0x10000 default.
    while size > 0 {
        let chunk = size.min(0xffff);
        let mut opcode = 0x80u8;
        let mut off_part = [0u8; 4];
        let mut off_len = 0;
        let mut v = offset;
        for i in 0..4 {
            if v & 0xff != 0 || (i == 3 && off_len == 0 && v == 0) {
                off_part[off_len] = (v & 0xff) as u8;
                off_len += 1;
                opcode |= 1 << i;
            }
            v >>= 8;
        }
        let mut size_part = [0u8; 3];
        let mut size_len = 0;
        let mut sv = chunk;
        // size 0x10000 would be encoded with no size bits; avoid ambiguity
        for i in 0..3 {
            if sv & 0xff != 0 {
                size_part[size_len] = (sv & 0xff) as u8;
                size_len += 1;
                opcode |= 1 << (4 + i);
            }
            sv >>= 8;
        }
        d.push(opcode);
        d.extend_from_slice(&off_part[..off_len]);
        d.extend_from_slice(&size_part[..size_len]);
        offset += chunk;
        size -= chunk;
    }
    if !extra.is_empty() {
        let mut i = 0;
        while i < extra.len() {
            let n = (extra.len() - i).min(127);
            d.push(n as u8);
            d.extend_from_slice(&extra[i..i + n]);
            i += n;
        }
    }
    d
}
