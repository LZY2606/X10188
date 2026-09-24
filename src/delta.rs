//! Git delta instruction parsing and application, with forensic op recording.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Serialize)]
pub enum DeltaOp {
    /// Copy `len` bytes from base[src_off..src_off+len] to out[dst_off..].
    Copy { dst_off: u64, src_off: u64, len: u64 },
    /// Insert literal bytes from delta[delta_off..delta_off+len].
    Insert { dst_off: u64, delta_off: u64, len: u64 },
}

#[derive(Debug)]
pub enum DeltaError {
    Truncated(&'static str),
    BaseSizeMismatch { expected: u64, actual: u64 },
    CopyOutOfRange { src_off: u64, len: u64, base_len: u64 },
    InsertOutOfRange { delta_off: u64, len: u64, delta_len: u64 },
    ResultSizeMismatch { expected: u64, actual: u64 },
    ReservedOpcode,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeltaError::Truncated(w) => write!(f, "delta 数据截断: {w}"),
            DeltaError::BaseSizeMismatch { expected, actual } => {
                write!(f, "delta 声明的 base 大小 {expected} 与实际 {actual} 不符")
            }
            DeltaError::CopyOutOfRange { src_off, len, base_len } => write!(
                f,
                "copy 指令越界: base[{src_off}..{}] 但 base 长度 {base_len}",
                src_off + len
            ),
            DeltaError::InsertOutOfRange { delta_off, len, delta_len } => write!(
                f,
                "insert 指令越界: delta[{delta_off}..{}] 但 delta 长度 {delta_len}",
                delta_off + len
            ),
            DeltaError::ResultSizeMismatch { expected, actual } => {
                write!(f, "delta 目标大小欺骗: 声明 {expected} 实际产出 {actual}")
            }
            DeltaError::ReservedOpcode => write!(f, "遇到保留操作码 0x00"),
        }
    }
}

impl std::error::Error for DeltaError {}

/// 7-bit little-endian-group varint used by delta headers.
pub fn read_delta_varint(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated("varint"));
        }
        let b = data[*pos];
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        if shift > 63 {
            return Err(DeltaError::Truncated("varint 过长"));
        }
    }
}

pub struct DeltaOutcome {
    pub result: Vec<u8>,
    pub ops: Vec<DeltaOp>,
    /// Declared source (base) size from the delta header.
    pub declared_src_size: u64,
    /// Declared target size from the delta header.
    pub declared_dst_size: u64,
}

/// Parse and apply a git delta against `base`, recording every instruction.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, DeltaError> {
    let mut pos = 0usize;
    let declared_src = read_delta_varint(delta, &mut pos)?;
    let declared_dst = read_delta_varint(delta, &mut pos)?;
    if declared_src != base.len() as u64 {
        return Err(DeltaError::BaseSizeMismatch {
            expected: declared_src,
            actual: base.len() as u64,
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(declared_dst.min(1 << 24) as usize);
    let mut ops = Vec::new();
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut src_off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy offset"));
                    }
                    src_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy size"));
                    }
                    len |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let end = src_off.checked_add(len).ok_or(DeltaError::CopyOutOfRange {
                src_off,
                len,
                base_len: base.len() as u64,
            })?;
            if end > base.len() as u64 {
                return Err(DeltaError::CopyOutOfRange {
                    src_off,
                    len,
                    base_len: base.len() as u64,
                });
            }
            let dst_off = out.len() as u64;
            out.extend_from_slice(&base[src_off as usize..end as usize]);
            ops.push(DeltaOp::Copy { dst_off, src_off, len });
        } else if cmd != 0 {
            let len = cmd as u64;
            let end = pos + len as usize;
            if end > delta.len() {
                return Err(DeltaError::InsertOutOfRange {
                    delta_off: pos as u64,
                    len,
                    delta_len: delta.len() as u64,
                });
            }
            let dst_off = out.len() as u64;
            out.extend_from_slice(&delta[pos..end]);
            ops.push(DeltaOp::Insert {
                dst_off,
                delta_off: pos as u64,
                len,
            });
            pos = end;
        } else {
            return Err(DeltaError::ReservedOpcode);
        }
    }
    if out.len() as u64 != declared_dst {
        return Err(DeltaError::ResultSizeMismatch {
            expected: declared_dst,
            actual: out.len() as u64,
        });
    }
    Ok(DeltaOutcome {
        result: out,
        ops,
        declared_src_size: declared_src,
        declared_dst_size: declared_dst,
    })
}
