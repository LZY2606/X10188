//! Apply Git delta instructions with full trace / boundary checking.

/// A single reconstructed delta instruction.
#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub index: usize,
    pub kind: &'static str,
    /// Byte offset of this instruction inside the delta stream.
    pub instr_offset: usize,
    /// Byte length of the instruction encoding.
    pub instr_len: usize,
    /// Range in the base object (copy) / None for insert.
    pub src_offset: Option<usize>,
    pub length: usize,
    /// Output offset at which the instruction starts writing.
    pub dst_offset: usize,
}

#[derive(Debug, Clone)]
pub struct DeltaTrace {
    pub base_size: usize,
    pub result_size: usize,
    /// Bytes consumed by the two varint sizes.
    pub header_len: usize,
    pub instructions: Vec<DeltaInstruction>,
}

#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub trace: DeltaTrace,
}

#[derive(Debug, Clone)]
pub enum DeltaError {
    /// Malformed/truncated delta stream (with message and byte offset).
    Malformed(String, usize),
    /// Copy instruction reads outside the base object.
    CopyOutOfBounds {
        index: usize,
        instr_offset: usize,
        src_offset: usize,
        length: usize,
        base_size: usize,
    },
    /// Insert/copy writes outside the declared result size.
    WriteOutOfBounds {
        index: usize,
        instr_offset: usize,
        dst_offset: usize,
        length: usize,
        result_size: usize,
    },
    /// Actual produced length differs from the declared result size.
    SizeMismatch {
        declared: usize,
        actual: usize,
    },
    /// Refusing to expand beyond the caller supplied safety cap (budget).
    CapExceeded {
        cap: usize,
        needed: usize,
    },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Malformed(m, p) => write!(f, "malformed delta at byte {p}: {m}"),
            DeltaError::CopyOutOfBounds {
                index,
                src_offset,
                length,
                base_size,
                ..
            } => write!(
                f,
                "instruction #{index} copies {length} bytes from offset {src_offset} but base is only {base_size} bytes"
            ),
            DeltaError::WriteOutOfBounds {
                index,
                dst_offset,
                length,
                result_size,
                ..
            } => write!(
                f,
                "instruction #{index} writes {length} bytes at offset {dst_offset}, outside declared result size {result_size}"
            ),
            DeltaError::SizeMismatch { declared, actual } => write!(
                f,
                "delta declares result size {declared} but instructions produce {actual} bytes"
            ),
            DeltaError::CapExceeded { cap, needed } => write!(
                f,
                "expansion would need {needed} bytes beyond the safety cap of {cap}"
            ),
        }
    }
}

fn read_varint(delta: &[u8], pos: &mut usize) -> Result<usize, DeltaError> {
    let mut size: usize = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= delta.len() {
            return Err(DeltaError::Malformed(
                "truncated size varint".into(),
                *pos,
            ));
        }
        let c = delta[*pos];
        *pos += 1;
        size |= ((c & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or_else(|| DeltaError::Malformed("size varint overflow".into(), *pos))?;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DeltaError::Malformed("size varint too long".into(), *pos));
        }
    }
    Ok(size)
}

/// Apply `delta` to `base`, honoring `cap` as the maximum allowed output size.
pub fn apply_delta(base: &[u8], delta: &[u8], cap: usize) -> Result<DeltaOutcome, DeltaError> {
    let mut pos = 0;
    let base_size = read_varint(delta, &mut pos)?;
    let result_size = read_varint(delta, &mut pos)?;
    if base_size != base.len() {
        return Err(DeltaError::Malformed(
            format!("delta base size {base_size} does not match actual base length {}", base.len()),
            0,
        ));
    }
    if result_size > cap {
        return Err(DeltaError::CapExceeded {
            cap,
            needed: result_size,
        });
    }
    let header_len = pos;

    let mut output = Vec::with_capacity(result_size.min(1 << 20));
    let mut instructions = Vec::new();
    let mut index = 0usize;

    while pos < delta.len() {
        let instr_offset = pos;
        let opcode = delta[pos];
        pos += 1;

        if opcode == 0 {
            return Err(DeltaError::Malformed(
                "invalid zero opcode".into(),
                instr_offset,
            ));
        }

        if opcode & 0x80 != 0 {
            // COPY
            let mut src_offset: usize = 0;
            let mut length: usize = 0;
            let mut shift: u32 = 0;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Malformed(
                            "truncated copy offset".into(),
                            pos,
                        ));
                    }
                    src_offset |= (delta[pos] as usize) << shift;
                    pos += 1;
                }
                shift += 8;
            }
            let mut shift: u32 = 0;
            for bit in 4..7 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Malformed(
                            "truncated copy length".into(),
                            pos,
                        ));
                    }
                    length |= (delta[pos] as usize) << shift;
                    pos += 1;
                }
                shift += 8;
            }
            if length == 0 {
                length = 0x10000;
            }
            let dst_offset = output.len();
            let end_src = src_offset.checked_add(length).ok_or_else(|| {
                DeltaError::CopyOutOfBounds {
                    index,
                    instr_offset,
                    src_offset,
                    length,
                    base_size: base.len(),
                }
            })?;
            if end_src > base.len() {
                return Err(DeltaError::CopyOutOfBounds {
                    index,
                    instr_offset,
                    src_offset,
                    length,
                    base_size: base.len(),
                });
            }
            let end_dst = dst_offset.checked_add(length).ok_or_else(|| {
                DeltaError::WriteOutOfBounds {
                    index,
                    instr_offset,
                    dst_offset,
                    length,
                    result_size,
                }
            })?;
            if end_dst > result_size {
                return Err(DeltaError::WriteOutOfBounds {
                    index,
                    instr_offset,
                    dst_offset,
                    length,
                    result_size,
                });
            }
            output.extend_from_slice(&base[src_offset..end_src]);
            instructions.push(DeltaInstruction {
                index,
                kind: "copy",
                instr_offset,
                instr_len: pos - instr_offset,
                src_offset: Some(src_offset),
                length,
                dst_offset,
            });
        } else {
            // INSERT
            let length = opcode as usize;
            if pos + length > delta.len() {
                return Err(DeltaError::Malformed(
                    "insert runs past end of delta".into(),
                    instr_offset,
                ));
            }
            let dst_offset = output.len();
            let end_dst = dst_offset + length;
            if end_dst > result_size {
                return Err(DeltaError::WriteOutOfBounds {
                    index,
                    instr_offset,
                    dst_offset,
                    length,
                    result_size,
                });
            }
            output.extend_from_slice(&delta[pos..pos + length]);
            pos += length;
            instructions.push(DeltaInstruction {
                index,
                kind: "insert",
                instr_offset,
                instr_len: pos - instr_offset,
                src_offset: None,
                length,
                dst_offset,
            });
        }
        index += 1;
    }

    if output.len() != result_size {
        return Err(DeltaError::SizeMismatch {
            declared: result_size,
            actual: output.len(),
        });
    }

    Ok(DeltaOutcome {
        output,
        trace: DeltaTrace {
            base_size,
            result_size,
            header_len,
            instructions,
        },
    })
}
