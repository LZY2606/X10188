//! Git delta instruction parsing and application, with forensic bookkeeping:
//! every applied delta reports its instruction byte range, input/output sizes
//! and whether all internal size checksums held.

#[derive(Debug, Clone)]
pub struct DeltaInfo {
    /// Byte range of the instruction stream inside the delta payload
    /// (after the two size varints).
    pub instr_start: usize,
    pub instr_end: usize,
    pub copy_ops: usize,
    pub insert_ops: usize,
    /// Declared source size matched the actual base length.
    pub source_size_ok: bool,
    /// Declared target size matched the produced output length.
    pub target_size_ok: bool,
}

#[derive(Debug, Clone)]
pub enum DeltaError {
    Truncated(&'static str),
    /// The delta declares a source size different from the actual base.
    SourceSizeMismatch { declared: u64, actual: usize },
    /// A copy instruction reads outside the base object.
    CopyOutOfRange { offset: u64, size: u64, base_len: usize },
    /// Output length does not match the declared target size.
    TargetSizeMismatch { declared: u64, actual: usize },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated(w) => write!(f, "truncated delta while reading {w}"),
            DeltaError::SourceSizeMismatch { declared, actual } => write!(
                f,
                "delta source size {declared} != actual base size {actual} (size fraud)"
            ),
            DeltaError::CopyOutOfRange {
                offset,
                size,
                base_len,
            } => write!(
                f,
                "copy [{offset}..{}] exceeds base length {base_len}",
                offset + size
            ),
            DeltaError::TargetSizeMismatch { declared, actual } => write!(
                f,
                "delta produced {actual} bytes, header promised {declared} (size fraud)"
            ),
        }
    }
}

fn read_varint(delta: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut v: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated("size varint"));
        }
        let b = delta[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err(DeltaError::Truncated("oversized varint"));
        }
    }
}

/// Apply `delta` to `base`, returning the reconstructed bytes plus forensic
/// details about the instruction stream.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInfo), DeltaError> {
    let mut pos = 0usize;
    let src_size = read_varint(delta, &mut pos)?;
    let tgt_size = read_varint(delta, &mut pos)?;
    let source_size_ok = src_size == base.len() as u64;
    if !source_size_ok {
        return Err(DeltaError::SourceSizeMismatch {
            declared: src_size,
            actual: base.len(),
        });
    }
    let instr_start = pos;
    let mut out = Vec::with_capacity(tgt_size.min(64 * 1024 * 1024) as usize);
    let mut copy_ops = 0usize;
    let mut insert_ops = 0usize;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy offset"));
                    }
                    offset |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy size"));
                    }
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            if offset + size > base.len() as u64 {
                return Err(DeltaError::CopyOutOfRange {
                    offset,
                    size,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[offset as usize..(offset + size) as usize]);
            copy_ops += 1;
        } else if cmd != 0 {
            // insert literal
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err(DeltaError::Truncated("insert literal"));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            insert_ops += 1;
        } else {
            return Err(DeltaError::Truncated("reserved opcode 0"));
        }
    }
    let target_size_ok = out.len() as u64 == tgt_size;
    if !target_size_ok {
        return Err(DeltaError::TargetSizeMismatch {
            declared: tgt_size,
            actual: out.len(),
        });
    }
    Ok((
        out,
        DeltaInfo {
            instr_start,
            instr_end: delta.len(),
            copy_ops,
            insert_ops,
            source_size_ok,
            target_size_ok,
        },
    ))
}
