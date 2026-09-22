//! Git delta instructions (`ofs-delta` / `ref-delta` payloads).
//!
//! Delta payload layout:
//!   <varint base size><varint result size><instructions>
//! Instructions are either a copy from the base (opcode top bit 1, optional
//! offset/size bytes) or an insert of literal bytes (opcode = length).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    TruncatedHeader,
    ZeroSizeHeader,
    TruncatedCopyOperand,
    TruncatedInsert { need: usize, have: usize },
    CopyOutOfRange {
        offset: usize,
        size: usize,
        base_len: usize,
    },
    CopyZeroSize,
    UnknownOpcode(u8),
    BaseSizeMismatch {
        declared: u64,
        actual: u64,
    },
    ResultSizeMismatch {
        declared: u64,
        actual: u64,
    },
}

impl DeltaError {
    pub fn code(&self) -> &'static str {
        match self {
            DeltaError::TruncatedHeader => "delta-header-truncated",
            DeltaError::ZeroSizeHeader => "delta-zero-size-header",
            DeltaError::TruncatedCopyOperand => "delta-copy-operand-truncated",
            DeltaError::TruncatedInsert { .. } => "delta-insert-truncated",
            DeltaError::CopyOutOfRange { .. } => "delta-copy-out-of-range",
            DeltaError::CopyZeroSize => "delta-copy-zero-size",
            DeltaError::UnknownOpcode(_) => "delta-unknown-opcode",
            DeltaError::BaseSizeMismatch { .. } => "delta-base-size-mismatch",
            DeltaError::ResultSizeMismatch { .. } => "delta-result-size-mismatch",
        }
    }
}

/// Decode a little-endian, 7-bit-per-byte varint (MSB = continuation).
pub fn read_size(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut shift = 0u32;
    let mut size = 0u64;
    loop {
        if *pos >= data.len() {
            return Err(DeltaError::TruncatedHeader);
        }
        let b = data[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DeltaError::TruncatedHeader);
        }
    }
    Ok(size)
}

/// Encode the same varint (used by the test pack builder).
pub fn write_size(mut size: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaOp {
    Copy { offset: usize, size: usize },
    Insert { len: usize },
}

#[derive(Debug, Clone)]
pub struct ParsedDelta {
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    pub header_len: usize,
    pub ops: Vec<(DeltaOp, std::ops::Range<usize>)>,
    /// Total byte span of the instruction section.
    pub instr_len: usize,
}

/// Parse a delta payload without applying it. Each op is paired with the exact
/// input byte range (`instr` coordinates) it occupied, for evidence display.
pub fn parse_delta(data: &[u8]) -> Result<ParsedDelta, DeltaError> {
    let mut pos = 0usize;
    let base_size = read_size(data, &mut pos)?;
    let result_size = read_size(data, &mut pos)?;
    if base_size == 0 || result_size == 0 {
        return Err(DeltaError::ZeroSizeHeader);
    }
    let header_len = pos;
    let mut ops: Vec<(DeltaOp, std::ops::Range<usize>)> = Vec::new();
    let mut emitted: u64 = 0;
    while pos < data.len() {
        let op_start = pos;
        let opcode = data[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for i in 0..4u32 {
                if opcode & (1 << i) != 0 {
                    if pos >= data.len() {
                        return Err(DeltaError::TruncatedCopyOperand);
                    }
                    offset |= (data[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3u32 {
                if opcode & (1 << (4 + i)) != 0 {
                    if pos >= data.len() {
                        return Err(DeltaError::TruncatedCopyOperand);
                    }
                    size |= (data[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push((
                DeltaOp::Copy {
                    offset: offset as usize,
                    size: size as usize,
                },
                op_start..pos,
            ));
            emitted += size as u64;
        } else if opcode != 0 {
            let len = opcode as usize;
            if pos + len > data.len() {
                return Err(DeltaError::TruncatedInsert {
                    need: len,
                    have: data.len() - pos,
                });
            }
            ops.push((DeltaOp::Insert { len }, op_start..(pos + len)));
            pos += len;
            emitted += len as u64;
        } else {
            return Err(DeltaError::UnknownOpcode(0));
        }
    }
    if emitted != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_size,
            actual: emitted,
        });
    }
    Ok(ParsedDelta {
        declared_base_size: base_size,
        declared_result_size: result_size,
        header_len,
        ops,
        instr_len: pos - header_len,
    })
}

/// Apply a parsed delta to `base`, producing the target object payload.
pub fn apply_delta(base: &[u8], parsed: &ParsedDelta) -> Result<Vec<u8>, DeltaError> {
    if parsed.declared_base_size as usize != base.len() {
        return Err(DeltaError::BaseSizeMismatch {
            declared: parsed.declared_base_size,
            actual: base.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(parsed.declared_result_size as usize);
    for (op, _range) in &parsed.ops {
        match *op {
            DeltaOp::Copy { offset, size } => {
                if size == 0 {
                    return Err(DeltaError::CopyZeroSize);
                }
                if offset.checked_add(size).map_or(true, |end| end > base.len()) {
                    return Err(DeltaError::CopyOutOfRange {
                        offset,
                        size,
                        base_len: base.len(),
                    });
                }
                out.extend_from_slice(&base[offset..offset + size]);
            }
            DeltaOp::Insert { len: _ } => {
                // inserts are verified during parse; range points at literals
                let range = match parsed
                    .ops
                    .iter()
                    .find(|(_, r)| false)
                {
                    _ => unreachable!(),
                };
                let _ = range;
            }
        }
    }
    Ok(out)
}
