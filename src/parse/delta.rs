//! Git delta format: two varint sizes (base/result) followed by a stream
//! of copy (opcode with MSB set) and insert instructions. Every applied
//! instruction records its exact byte range inside the delta stream so
//! the UI can show forensic step evidence.

use crate::model::error_code;
use crate::parse::varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Copy,
    Insert,
}

#[derive(Debug, Clone)]
pub struct DeltaOp {
    pub kind: OpKind,
    /// Byte range of this instruction within the full delta blob.
    pub range: std::ops::Range<usize>,
    pub src_offset: u64,
    pub length: u64,
    /// Position range this instruction produces in the target object.
    pub out_range: std::ops::Range<usize>,
}

#[derive(Debug)]
pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub base_size: u64,
    pub result_size: u64,
    pub header_range: std::ops::Range<usize>,
    pub ops: Vec<DeltaOp>,
}

#[derive(Debug)]
pub struct DeltaError {
    pub code: &'static str,
    pub message: String,
    /// Byte offset inside the delta where the failure was detected.
    pub at: usize,
}

fn err(code: &'static str, at: usize, msg: impl Into<String>) -> DeltaError {
    DeltaError { code, message: msg.into(), at }
}

/// Apply `delta` to `base`, with strict bounds checking.
pub fn apply(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, DeltaError> {
    let base_v = varint::read(delta)
        .ok_or_else(|| err(error_code::BAD_VARINT, 0, "bad base size varint"))?;
    let result_v = varint::read(&delta[base_v.len..])
        .ok_or_else(|| err(error_code::BAD_VARINT, base_v.len, "bad result size varint"))?;
    let header_end = base_v.len + result_v.len;

    if base_v.value as usize != base.len() {
        return Err(err(
            error_code::DELTA_BASE_SIZE,
            0,
            format!("delta expects base of {} bytes, got {}", base_v.value, base.len()),
        ));
    }

    let mut ops = Vec::new();
    let mut output: Vec<u8> = Vec::with_capacity(result_v.value as usize);
    let mut pos = header_end;

    while pos < delta.len() {
        let opcode = delta[pos];
        let op_start = pos;
        pos += 1;
        if opcode & 0x80 != 0 {
            // COPY: opcode + up to 7 little-endian argument bytes.
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for bit in 0u32..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(err(error_code::DELTA_TRUNCATED, pos, "copy offset arg missing"));
                    }
                    cp_off |= u32::from(delta[pos]) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0u32..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(err(error_code::DELTA_TRUNCATED, pos, "copy size arg missing"));
                    }
                    cp_size |= u32::from(delta[pos]) << (8 * bit);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off.checked_add(cp_size).ok_or_else(|| {
                err(error_code::DELTA_COPY_RANGE, op_start, "copy offset+size overflow")
            })?;
            if end as usize > base.len() {
                return Err(err(
                    error_code::DELTA_COPY_RANGE,
                    op_start,
                    format!("copy {}..{} outside base of {}", cp_off, end, base.len()),
                ));
            }
            let out_start = output.len();
            output.extend_from_slice(&base[cp_off as usize..end as usize]);
            ops.push(DeltaOp {
                kind: OpKind::Copy,
                range: op_start..pos,
                src_offset: u64::from(cp_off),
                length: u64::from(cp_size),
                out_range: out_start..out_start + cp_size as usize,
            });
        } else if opcode != 0 {
            // INSERT: the low 7 bits are the byte count (1..=127).
            let take = opcode as usize;
            if pos + take > delta.len() {
                return Err(err(
                    error_code::DELTA_INSERT_RANGE,
                    op_start,
                    "insert runs past end of delta",
                ));
            }
            let out_start = output.len();
            output.extend_from_slice(&delta[pos..pos + take]);
            ops.push(DeltaOp {
                kind: OpKind::Insert,
                range: op_start..pos + take,
                src_offset: 0,
                length: take as u64,
                out_range: out_start..out_start + take,
            });
            pos += take;
        } else {
            return Err(err(error_code::DELTA_BAD_OP, op_start, "opcode 0 is reserved"));
        }
    }

    if output.len() as u64 != result_v.value {
        return Err(err(
            error_code::DELTA_RESULT_SIZE,
            pos,
            format!("produced {} bytes, delta header says {}", output.len(), result_v.value),
        ));
    }

    Ok(AppliedDelta {
        output,
        base_size: base_v.value,
        result_size: result_v.value,
        header_range: 0..header_end,
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::varint::write;

    fn insert(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 127);
        let mut d = vec![data.len() as u8];
        d.extend_from_slice(data);
        d
    }

    fn copy(off: u32, size: u32) -> Vec<u8> {
        let mut op = 0x80u8;
        let mut args = Vec::new();
        for bit in 0u32..4 {
            if off & (0xff << (8 * bit)) != 0 {
                op |= 1 << bit;
                args.push(((off >> (8 * bit)) & 0xff) as u8);
            }
        }
        for bit in 0u32..3 {
            if size & (0xff << (8 * bit)) != 0 {
                op |= 1 << (4 + bit);
                args.push(((size >> (8 * bit)) & 0xff) as u8);
            }
        }
        let mut d = vec![op];
        d.extend(args);
        d
    }

    #[test]
    fn insert_and_copy() {
        let base = b"hello world!!";
        let target = b"hello brave world!!";
        let mut delta = Vec::new();
        write(base.len() as u64, &mut delta);
        write(target.len() as u64, &mut delta);
        delta.extend(copy(0, 6)); // "hello "
        delta.extend(insert(b"brave "));
        delta.extend(copy(6, 7)); // "world!!"
        let got = apply(base, &delta).unwrap();
        assert_eq!(got.output, target);
        assert_eq!(got.ops.len(), 3);
        assert_eq!(got.ops[0].kind, OpKind::Copy);
        assert_eq!(got.ops[2].out_range, 12..19);
    }

    #[test]
    fn base_size_mismatch() {
        let mut delta = Vec::new();
        write(99, &mut delta);
        write(0, &mut delta);
        let e = apply(b"abc", &delta).unwrap_err();
        assert_eq!(e.code, error_code::DELTA_BASE_SIZE);
    }

    #[test]
    fn copy_out_of_base() {
        let base = b"abc";
        let mut delta = Vec::new();
        write(3, &mut delta);
        write(3, &mut delta);
        delta.extend(copy(1, 5));
        let e = apply(base, &delta).unwrap_err();
        assert_eq!(e.code, error_code::DELTA_COPY_RANGE);
    }

    #[test]
    fn zero_opcode_rejected() {
        let mut delta = Vec::new();
        write(0, &mut delta);
        write(0, &mut delta);
        delta.push(0);
        let e = apply(&[], &delta).unwrap_err();
        assert_eq!(e.code, error_code::DELTA_BAD_OP);
    }
}
