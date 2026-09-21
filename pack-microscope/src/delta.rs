use crate::git::{read_delta_varint, ParseError};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct DeltaOp {
    pub kind: &'static str,
    pub offset: usize,
    pub end: usize,
    pub src_off: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct DeltaTrace {
    pub header_end: usize,
    pub base_size_declared: u64,
    pub result_size_declared: u64,
    pub instruction_range: (usize, usize),
    pub input_len: usize,
    pub output_len: usize,
    pub copies: u64,
    pub inserts: u64,
    pub ops: Vec<DeltaOp>,
}

#[derive(Debug, serde::Serialize)]
pub enum DeltaError {
    Truncated,
    BaseSizeMismatch { declared: u64, actual: u64 },
    ResultSizeMismatch { declared: u64, actual: u64 },
    CopyOutOfRange { src_off: u64, len: u64, base_len: u64 },
    InsertOutOfRange { offset: usize, len: usize, remain: usize },
    ReservedOpcode(u8, usize),
    BadTrailer,
    BadHeader(String),
}

impl From<ParseError> for DeltaError {
    fn from(e: ParseError) -> Self {
        DeltaError::BadHeader(format!("{:?}", e))
    }
}

pub fn delta_headers(data: &[u8]) -> Result<(u64, u64, usize), DeltaError> {
    let (base_size, p1) = read_delta_varint(data, 0)?;
    let (result_size, p2) = read_delta_varint(data, p1)?;
    Ok((base_size, result_size, p2))
}

pub fn apply_delta(base: &[u8], data: &[u8]) -> Result<(Vec<u8>, DeltaTrace), DeltaError> {
    let (base_size, result_size, p2) = delta_headers(data)?;
    if base_size != base.len() as u64 {
        return Err(DeltaError::BaseSizeMismatch {
            declared: base_size,
            actual: base.len() as u64,
        });
    }
    let mut trace = DeltaTrace {
        header_end: p2,
        base_size_declared: base_size,
        result_size_declared: result_size,
        ..Default::default()
    };
    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(1 << 20) as usize);
    let mut pos = p2;
    while pos < data.len() {
        let op_start = pos;
        let opcode = data[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut src_off = 0u64;
            let mut length = 0u64;
            for i in 0..4 {
                if opcode & (1 << i) != 0 {
                    src_off |= (*data.get(pos).ok_or(DeltaError::Truncated)? as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if opcode & (1 << (4 + i)) != 0 {
                    length |= (*data.get(pos).ok_or(DeltaError::Truncated)? as u64) << (8 * i);
                    pos += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            trace.ops.push(DeltaOp {
                kind: "copy",
                offset: op_start,
                end: pos,
                src_off,
                len: length,
            });
            trace.copies += 1;
            if src_off
                .checked_add(length)
                .map(|end| end > base.len() as u64)
                .unwrap_or(true)
            {
                return Err(DeltaError::CopyOutOfRange {
                    src_off,
                    len: length,
                    base_len: base.len() as u64,
                });
            }
            let s = src_off as usize;
            out.extend_from_slice(&base[s..s + length as usize]);
        } else if opcode != 0 {
            let len = opcode as usize;
            trace.ops.push(DeltaOp {
                kind: "insert",
                offset: op_start,
                end: pos,
                src_off: 0,
                len: len as u64,
            });
            trace.inserts += 1;
            if pos.checked_add(len).map(|e| e > data.len()).unwrap_or(true) {
                return Err(DeltaError::InsertOutOfRange {
                    offset: pos,
                    len,
                    remain: data.len().saturating_sub(pos),
                });
            }
            out.extend_from_slice(&data[pos..pos + len]);
            pos += len;
        } else {
            return Err(DeltaError::ReservedOpcode(opcode, op_start));
        }
    }
    trace.instruction_range = (p2, pos);
    trace.input_len = base.len();
    trace.output_len = out.len();
    if out.len() as u64 != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_size,
            actual: out.len() as u64,
        });
    }
    Ok((out, trace))
}

pub fn make_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    fn enc_size(mut size: u64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                b |= 0x80;
            }
            v.push(b);
            if size == 0 {
                break;
            }
        }
        v
    }
    let mut out = enc_size(base.len() as u64);
    out.extend(enc_size(target.len() as u64));
    let mut rest = target;
    while rest.len() >= 127 {
        out.push(127);
        out.extend_from_slice(&rest[..127]);
        rest = &rest[127..];
    }
    if !rest.is_empty() {
        out.push(rest.len() as u8);
        out.extend_from_slice(rest);
    }
    out
}
