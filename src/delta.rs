//! Git delta instruction parsing and application, with per-instruction
//! range records for forensic display.

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaOp {
    /// "copy" (from base) or "insert" (literal from delta stream).
    pub kind: String,
    /// Offset in the base object (copy) or in the delta stream (insert).
    pub src_off: u64,
    /// Offset in the output buffer.
    pub out_off: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaReport {
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    pub ops: Vec<DeltaOp>,
    pub in_len: u64,
    pub out_len: u64,
    pub base_size_ok: bool,
    pub result_size_ok: bool,
}

#[derive(Debug, Error)]
pub enum DeltaError {
    #[error("truncated delta stream")]
    Truncated,
    #[error("base size mismatch: delta expects {declared}, base is {actual}")]
    BaseSize { declared: u64, actual: u64 },
    #[error("copy out of base range: off={off} len={len} base={base}")]
    CopyOutOfRange { off: u64, len: u64, base: u64 },
    #[error("result size mismatch: delta declares {declared}, produced {actual}")]
    ResultSize { declared: u64, actual: u64 },
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(DeltaError::Truncated)?;
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err(DeltaError::Truncated);
        }
    }
}

/// Apply a git delta to `base`, returning the result and a full report of
/// instruction ranges and size checks.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaReport), DeltaError> {
    let mut pos = 0usize;
    let declared_base = read_varint(delta, &mut pos)?;
    let declared_result = read_varint(delta, &mut pos)?;
    let base_size_ok = declared_base == base.len() as u64;
    if !base_size_ok {
        return Err(DeltaError::BaseSize {
            declared: declared_base,
            actual: base.len() as u64,
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(declared_result as usize);
    let mut ops = Vec::new();
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or(DeltaError::Truncated)?;
                    pos += 1;
                    off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or(DeltaError::Truncated)?;
                    pos += 1;
                    len |= (b as u64) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if off + len > base.len() as u64 {
                return Err(DeltaError::CopyOutOfRange {
                    off,
                    len,
                    base: base.len() as u64,
                });
            }
            ops.push(DeltaOp {
                kind: "copy".into(),
                src_off: off,
                out_off: out.len() as u64,
                len,
            });
            out.extend_from_slice(&base[off as usize..(off + len) as usize]);
        } else if cmd != 0 {
            let len = cmd as usize;
            if pos + len > delta.len() {
                return Err(DeltaError::Truncated);
            }
            ops.push(DeltaOp {
                kind: "insert".into(),
                src_off: pos as u64,
                out_off: out.len() as u64,
                len: len as u64,
            });
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        } else {
            return Err(DeltaError::Truncated);
        }
    }
    let result_size_ok = out.len() as u64 == declared_result;
    if !result_size_ok {
        return Err(DeltaError::ResultSize {
            declared: declared_result,
            actual: out.len() as u64,
        });
    }
    let report = DeltaReport {
        declared_base_size: declared_base,
        declared_result_size: declared_result,
        ops,
        in_len: delta.len() as u64,
        out_len: out.len() as u64,
        base_size_ok,
        result_size_ok,
    };
    Ok((out, report))
}
