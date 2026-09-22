use std::error::Error;
use crate::git::{read_delta_size, ObjectId};

#[derive(Debug, Clone)]
pub struct DeltaInstructionRange {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
}

#[derive(Debug)]
pub enum DeltaError {
    TruncatedHeader,
    BaseSizeMismatch { header: u64, actual: u64 },
    ResultBudget { declared: u64, budget: u64 },
    TruncatedInstruction,
    BadCopyRange { offset: usize, size: usize, base_len: usize },
    BadInsertLength { len: usize, remaining: usize },
    OutputSizeMismatch { declared: u64, actual: usize },
    EmptyOutput,
    OutputTooLong { declared: u64 },
}

macro_rules! delta_error_boilerplate {
    () => {
        impl std::fmt::Display for DeltaError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::TruncatedHeader => write!(f, "truncated delta header"),
                    Self::BaseSizeMismatch { header, actual } => write!(f, "base size mismatch: header {header}, actual {actual}"),
                    Self::ResultBudget { declared, budget } => write!(f, "declared result size {declared} exceeds object byte budget {budget}"),
                    Self::TruncatedInstruction => write!(f, "truncated delta instruction"),
                    Self::BadCopyRange { offset, size, base_len } => write!(f, "invalid copy range offset={offset} size={size} base_len={base_len}"),
                    Self::BadInsertLength { len, remaining } => write!(f, "insert instruction length {len} exceeds available {remaining} delta bytes"),
                    Self::OutputSizeMismatch { declared, actual } => write!(f, "output size {actual} differs from declared size {declared}"),
                    Self::EmptyOutput => write!(f, "delta produced no output"),
                    Self::OutputTooLong { declared } => write!(f, "output exceeded declared size {declared}"),
                }
            }
        }
        impl std::error::Error for DeltaError {}
    };
}
delta_error_boilerplate!();

pub fn parse_delta(
    delta: &[u8],
    base: &[u8],
    byte_budget: u64,
    base_oid: Option<ObjectId>,
) -> Result<(Vec<u8>, Vec<DeltaInstructionRange>), DeltaError> {
    let _ = base_oid;
    let (base_size, pos1) = read_delta_size(delta).ok_or(DeltaError::TruncatedHeader)?;
    if base_size as usize != base.len() {
        return Err(DeltaError::BaseSizeMismatch { header: base_size, actual: base.len() as u64 });
    }
    let (result_size, header_len) = read_delta_size(&delta[pos1..]).ok_or(DeltaError::TruncatedHeader)?;
    let header_len = pos1 + header_len;
    if result_size > byte_budget {
        return Err(DeltaError::ResultBudget { declared: result_size, budget: byte_budget });
    }
    if result_size == 0 {
        return Err(DeltaError::EmptyOutput);
    }
    let mut output = Vec::with_capacity(result_size as usize);
    let mut ranges = Vec::new();
    let mut pos = header_len;
    while pos < delta.len() {
        let start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4u32 {
                if opcode & (1 << bit) != 0 {
                    let value = *delta.get(pos).ok_or(DeltaError::TruncatedInstruction)?;
                    pos += 1;
                    offset |= (value as usize) << (8 * bit);
                }
            }
            for bit in 0..3u32 {
                if opcode & (1 << (4 + bit)) != 0 {
                    let value = *delta.get(pos).ok_or(DeltaError::TruncatedInstruction)?;
                    pos += 1;
                    size |= (value as usize) << (8 * bit);
                }
            }
            if opcode & 0x10 == 0 { size = 0x10000; }
            if size == 0 || offset.checked_add(size).map_or(true, |end| end > base.len()) {
                return Err(DeltaError::BadCopyRange { offset, size, base_len: base.len() });
            }
            if output.len() as u64 + size as u64 > result_size {
                return Err(DeltaError::OutputTooLong { declared: result_size });
            }
            output.extend_from_slice(&base[offset..offset + size]);
            ranges.push(DeltaInstructionRange { start, end: pos, kind: "copy" });
        } else if opcode != 0 {
            let len = opcode as usize;
            if len > delta.len() - pos {
                return Err(DeltaError::BadInsertLength { len, remaining: delta.len() - pos });
            }
            if output.len() as u64 + len as u64 > result_size {
                return Err(DeltaError::OutputTooLong { declared: result_size });
            }
            output.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            ranges.push(DeltaInstructionRange { start, end: pos, kind: "insert" });
        } else {
            return Err(DeltaError::TruncatedInstruction);
        }
    }
    if output.len() as u64 != result_size {
        return Err(DeltaError::OutputSizeMismatch { declared: result_size, actual: output.len() });
    }
    Ok((output, ranges))
}
