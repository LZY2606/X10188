//! Git delta instruction streams (insert / copy), with forensic tracing.

use super::types::read_size_encoding;

/// One decoded delta instruction, with its raw byte range in the delta body
/// and the buffer offsets it touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaInstr {
    Insert {
        /// byte range of the instruction (including opcode/length) in delta
        range: (usize, usize),
        /// inserted byte range in the delta payload
        data_range: (usize, usize),
        /// output offset / length produced
        out_pos: usize,
        len: usize,
    },
    Copy {
        range: (usize, usize),
        /// source offset/length this instruction reads
        src_pos: usize,
        src_len: usize,
        out_pos: usize,
        len: usize,
    },
}

#[derive(Debug, Clone)]
pub struct DeltaError {
    pub code: &'static str,
    pub message: String,
    /// Instruction index that failed, if instruction-level.
    pub instr: Option<usize>,
    /// Byte range in the delta payload associated with the failure.
    pub at: Option<(usize, usize)>,
}

impl DeltaError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        DeltaError {
            code,
            message: message.into(),
            instr: None,
            at: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeltaResult {
    pub output: Vec<u8>,
    pub instrs: Vec<DeltaInstr>,
}

/// Apply a git delta against `base`. Every instruction is recorded with its
/// raw range and input/output footprint. No partial output is returned on
/// failure.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaResult, DeltaError> {
    let mut pos = 0usize;
    let (base_size, n1) = read_size_encoding(delta)
        .ok_or_else(|| DeltaError::new("delta_header", "missing base size varint"))?;
    pos += n1;
    let (result_size, n2) = read_size_encoding(&delta[pos..])
        .ok_or_else(|| DeltaError::new("delta_header", "missing result size varint"))?;
    pos += n2;

    if base_size as usize != base.len() {
        return Err(DeltaError::new(
            "delta_base_size_mismatch",
            format!(
                "delta claims base size {} but actual base is {} bytes",
                base_size,
                base.len()
            ),
        ));
    }

    let header_len = pos;
    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(1usize << 28) as usize);
    let mut instrs: Vec<DeltaInstr> = Vec::new();
    let mut instr_idx = 0usize;

    while pos < delta.len() {
        let instr_start = pos;
        let opcode = delta[pos];
        pos += 1;

        if opcode & 0x80 != 0 {
            // COPY: up to 4 offset bytes + up to 3 size bytes, little endian.
            let mut src_pos: usize = 0;
            let mut src_len: usize = 0;
            for shift in 0..4u32 {
                if opcode & (1 << shift) != 0 {
                    let b = *delta
                        .get(pos)
                        .ok_or_else(|| truncated(instr_idx, (instr_start, delta.len())))?;
                    pos += 1;
                    src_pos |= (b as usize) << (shift * 8);
                }
            }
            for shift in 0..3u32 {
                if opcode & (1 << (4 + shift)) != 0 {
                    let b = *delta
                        .get(pos)
                        .ok_or_else(|| truncated(instr_idx, (instr_start, delta.len())))?;
                    pos += 1;
                    src_len |= (b as usize) << (shift * 8);
                }
            }
            if src_len == 0 {
                src_len = 0x10000;
            }
            let end = src_pos.checked_add(src_len).ok_or_else(|| {
                DeltaError::new("copy_overflow", "src offset + length overflow")
            })?;
            if end > base.len() {
                let mut e = DeltaError::new(
                    "copy_out_of_base",
                    format!(
                        "copy [{}, {}) runs past base of {} bytes",
                        src_pos,
                        end,
                        base.len()
                    ),
                );
                e.instr = Some(instr_idx);
                e.at = Some((instr_start, pos));
                return Err(e);
            }
            let out_pos = out.len();
            out.extend_from_slice(&base[src_pos..end]);
            instrs.push(DeltaInstr::Copy {
                range: (instr_start, pos),
                src_pos,
                src_len,
                out_pos,
                len: src_len,
            });
        } else if opcode != 0 {
            // INSERT
            let take = opcode as usize;
            if pos + take > delta.len() {
                let mut e = DeltaError::new(
                    "insert_truncated",
                    format!("insert of {} bytes truncated in delta", take),
                );
                e.instr = Some(instr_idx);
                e.at = Some((instr_start, delta.len().min(pos + take)));
                return Err(e);
            }
            let data_range = (pos, pos + take);
            let out_pos = out.len();
            out.extend_from_slice(&delta[pos..pos + take]);
            pos += take;
            instrs.push(DeltaInstr::Insert {
                range: (instr_start, pos),
                data_range,
                out_pos,
                len: take,
            });
        } else {
            let mut e = DeltaError::new("reserved_opcode", "delta opcode 0x00 is reserved");
            e.instr = Some(instr_idx);
            e.at = Some((instr_start, pos));
            return Err(e);
        }

        if out.len() > result_size as usize {
            let mut e = DeltaError::new(
                "result_size_exceeded",
                format!(
                    "instructions produced {} bytes, header promised {}",
                    out.len(),
                    result_size
                ),
            );
            e.instr = Some(instr_idx);
            e.at = Some((instr_start, pos));
            return Err(e);
        }
        instr_idx += 1;
    }

    if pos != delta.len() || out.len() != result_size as usize {
        return Err(DeltaError::new(
            "result_size_mismatch",
            format!(
                "output is {} bytes but delta header declared {}",
                out.len(),
                result_size
            ),
        ));
    }
    debug_assert!(header_len <= delta.len());
    Ok(DeltaResult {
        output: out,
        instrs,
    })
}

fn truncated(idx: usize, at: (usize, usize)) -> DeltaError {
    let mut e = DeltaError::new("delta_truncated", "instruction runs past delta body");
    e.instr = Some(idx);
    e.at = Some(at);
    e
}
