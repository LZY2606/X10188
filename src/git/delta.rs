//! Git delta (ofs/ref shared payload) instruction parser and applier.

use super::types::decode_delta_varint;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Copy { offset: usize, size: usize },
    Insert { data: Vec<u8> },
    Zero,
}

#[derive(Debug, Clone)]
pub struct OpRecord {
    pub op: Op,
    /// Byte range inside the delta payload covered by this instruction
    /// (including its opcode and arguments).
    pub start: usize,
    pub end: usize,
    /// Output bytes produced by this instruction.
    pub out_len: usize,
}

#[derive(Debug, Clone)]
pub struct DeltaApplication {
    pub base_size: u64,
    pub result_size: u64,
    pub ops: Vec<OpRecord>,
    pub output: Vec<u8>,
    pub header_len: usize,
}

#[derive(Debug, Clone)]
pub struct DeltaBudgets {
    pub max_result: u64,
    pub total_remaining: u64,
}

const COPY_OFF_BYTES: [u8; 4] = [1, 2, 4, 8];
const COPY_SIZE_BYTES: [u8; 3] = [16, 32, 64];

/// Parse the two size varints and all instructions. No application happens
/// here, so malformed instruction ranges can be reported precisely.
pub fn parse_ops(delta: &[u8]) -> Result<(u64, u64, usize, Vec<OpRecord>)> {
    let (base_size, n1) = decode_delta_varint(delta)?;
    let (result_size, n2) = decode_delta_varint(&delta[n1..])?;
    let header_len = n1 + n2;
    let mut p = header_len;
    let mut ops = Vec::new();

    while p < delta.len() {
        let start = p;
        let opcode = delta[p];
        p += 1;
        if opcode == 0 {
            return Err(Error::bad(format!("invalid opcode 0x00 at delta offset {start}")));
        }
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            for (i, mask) in COPY_OFF_BYTES.iter().enumerate() {
                if opcode & mask != 0 {
                    if p >= delta.len() {
                        return Err(Error::bad("truncated copy offset"));
                    }
                    offset |= (delta[p] as usize) << (8 * i);
                    p += 1;
                }
            }
            let mut size = 0usize;
            for (i, mask) in COPY_SIZE_BYTES.iter().enumerate() {
                if opcode & mask != 0 {
                    if p >= delta.len() {
                        return Err(Error::bad("truncated copy size"));
                    }
                    size |= (delta[p] as usize) << (8 * i);
                    p += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push(OpRecord {
                op: Op::Copy { offset, size },
                start,
                end: p,
                out_len: size,
            });
        } else {
            let size = opcode as usize;
            if p + size > delta.len() {
                return Err(Error::bad(format!(
                    "insert of {size} bytes at delta offset {start} overruns delta (have {} bytes)",
                    delta.len() - p
                )));
            }
            let data = delta[p..p + size].to_vec();
            p += size;
            ops.push(OpRecord {
                op: Op::Insert { data },
                start,
                end: p,
                out_len: size,
            });
        }
    }

    Ok((base_size, result_size, header_len, ops))
}

pub fn apply_with_budgets(
    base: &[u8],
    delta: &[u8],
    budgets: &DeltaBudgets,
) -> Result<DeltaApplication> {
    let (base_size, result_size, header_len, ops) = parse_ops(delta)?;
    if base_size as usize != base.len() {
        return Err(Error::bad(format!(
            "delta base size {base_size} does not match actual base length {}",
            base.len()
        )));
    }
    if result_size > budgets.max_result {
        return Err(Error::BudgetPaused {
            kind: "max_result_bytes".into(),
            limit: budgets.max_result,
            used: result_size,
            retryable: true,
        });
    }
    if result_size > budgets.total_remaining {
        return Err(Error::BudgetPaused {
            kind: "total_expansion".into(),
            limit: budgets.total_remaining,
            used: result_size,
            retryable: true,
        });
    }

    let mut output: Vec<u8> = Vec::with_capacity(result_size.min(64 * 1024 * 1024) as usize);
    for rec in &ops {
        match &rec.op {
            Op::Insert { data } => output.extend_from_slice(data),
            Op::Copy { offset, size } => {
                let end = offset.checked_add(*size).ok_or_else(|| {
                    Error::bad("copy offset+size overflows usize")
                })?;
                if end > base.len() {
                    return Err(Error::bad(format!(
                        "copy instruction at delta offset {} reads base[{}..{}] but base is {} bytes",
                        rec.start, offset, end, base.len()
                    )));
                }
                output.extend_from_slice(&base[*offset..end]);
            }
            Op::Zero => unreachable!(),
        }
        if output.len() as u64 > result_size {
            return Err(Error::bad(format!(
                "instruction stream wrote {} bytes before end, exceeding advertised result size {result_size}",
                output.len()
            )));
        }
    }

    if output.len() as u64 != result_size {
        return Err(Error::bad(format!(
            "instructions produce {} bytes but delta header promised {result_size}",
            output.len()
        )));
    }

    Ok(DeltaApplication {
        base_size,
        result_size,
        ops,
        output,
        header_len,
    })
}

pub fn apply(base: &[u8], delta: &[u8]) -> Result<DeltaApplication> {
    apply_with_budgets(
        base,
        delta,
        &DeltaBudgets {
            max_result: u64::MAX,
            total_remaining: u64::MAX,
        },
    )
}

/// Encode a minimal delta: one or more insert/copy operations. Used by the
/// test pack builder, but also useful diagnostically.
pub fn encode(base_size: u64, result_size: u64, ops: &[Op]) -> Vec<u8> {
    use super::types::encode_delta_varint;
    let mut out = encode_delta_varint(base_size);
    out.extend(encode_delta_varint(result_size));
    for op in ops {
        match op {
            Op::Insert { data } => {
                assert!(data.len() < 128);
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
            Op::Copy { offset, size } => {
                let mut opcode = 0x80u8;
                let mut args = Vec::new();
                for (i, mask) in COPY_OFF_BYTES.iter().enumerate() {
                    let byte = ((*offset >> (8 * i)) & 0xff) as u8;
                    if byte != 0 {
                        opcode |= mask;
                        args.push(byte);
                    }
                }
                for (i, mask) in COPY_SIZE_BYTES.iter().enumerate() {
                    let byte = ((*size >> (8 * i)) & 0xff) as u8;
                    if byte != 0 {
                        opcode |= mask;
                        args.push(byte);
                    }
                }
                out.push(opcode);
                out.extend(args);
            }
            Op::Zero => unreachable!(),
        }
    }
    out
}
