//! Git delta (thin/standard) instruction decoder and applier.

use crate::git::ParseError;

#[derive(Debug, Clone)]
pub struct DeltaStep {
    /// Source of the base for this hop.
    pub base_oid: String,
    /// Byte range of the instruction inside the delta payload.
    pub instr_start: usize,
    pub instr_end: usize,
    pub opcode: u8,
    /// Human-readable instruction summary.
    pub detail: String,
    pub input_len: usize,
    pub output_len: usize,
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub enum DeltaError {
    Parse(ParseError),
    BudgetExceeded { produced: usize, cap: usize },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Parse(p) => write!(f, "{p}"),
            DeltaError::BudgetExceeded { produced, cap } => write!(
                f,
                "resource budget exceeded while applying delta: {produced} > cap {cap}"
            ),
        }
    }
}

fn read_varint(delta: &[u8], pos: &mut usize) -> Result<u64, ParseError> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= delta.len() {
            return Err(ParseError::Truncated("delta varint"));
        }
        let b = delta[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(val)
}

/// Apply `delta` to `base`, honoring `hard_cap` expanded bytes. Every
/// instruction is recorded with its exact byte range and i/o lengths.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    hard_cap: usize,
) -> Result<(Vec<u8>, Vec<DeltaStep>), DeltaError> {
    let mut pos = 0usize;
    let source_size = read_varint(delta, &mut pos).map_err(DeltaError::Parse)?;
    let target_size = read_varint(delta, &mut pos).map_err(DeltaError::Parse)?;
    if source_size as usize != base.len() {
        return Err(DeltaError::Parse(ParseError::InvalidDelta(format!(
            "delta source size {source_size} != base length {}",
            base.len()
        ))));
    }
    let mut out: Vec<u8> = Vec::with_capacity(target_size.min(hard_cap as u64) as usize);
    let mut steps: Vec<DeltaStep> = Vec::new();

    while pos < delta.len() {
        let instr_start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // copy from source
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return err_step(
                            steps,
                            base,
                            &out,
                            instr_start,
                            pos,
                            op,
                            ParseError::Truncated("copy offset byte"),
                        );
                    }
                    offset |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return err_step(
                            steps,
                            base,
                            &out,
                            instr_start,
                            pos,
                            op,
                            ParseError::Truncated("copy size byte"),
                        );
                    }
                    size |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let instr_end = pos;
            let end = offset as u64 + size as u64;
            if end > base.len() as u64 {
                steps.push(DeltaStep {
                    base_oid: String::new(),
                    instr_start,
                    instr_end,
                    opcode: op,
                    detail: format!("copy offset={offset} size={size} OUT OF BOUNDS (base {})", base.len()),
                    input_len: base.len(),
                    output_len: out.len(),
                    ok: false,
                });
                return Err(DeltaError::Parse(ParseError::InvalidDelta(format!(
                    "copy reads offset {offset} size {size} beyond base of {}",
                    base.len()
                ))));
            }
            out.extend_from_slice(&base[offset as usize..(offset + size) as usize]);
            steps.push(DeltaStep {
                base_oid: String::new(),
                instr_start,
                instr_end,
                opcode: op,
                detail: format!("copy offset={offset} size={size}"),
                input_len: base.len(),
                output_len: out.len(),
                ok: true,
            });
        } else if op != 0 {
            // insert literal
            let size = op as usize;
            if pos + size > delta.len() {
                steps.push(DeltaStep {
                    base_oid: String::new(),
                    instr_start,
                    instr_end: delta.len().min(pos + size),
                    opcode: op,
                    detail: format!("insert size={size} but only {} delta bytes left", delta.len().saturating_sub(pos)),
                    input_len: base.len(),
                    output_len: out.len(),
                    ok: false,
                });
                return Err(DeltaError::Parse(ParseError::InvalidDelta(format!(
                    "insert opcode {op} overruns delta stream at {pos}"
                ))));
            }
            out.extend_from_slice(&delta[pos..pos + size]);
            pos += size;
            steps.push(DeltaStep {
                base_oid: String::new(),
                instr_start,
                instr_end: pos,
                opcode: op,
                detail: format!("insert {} literal bytes", size),
                input_len: base.len(),
                output_len: out.len(),
                ok: true,
            });
        } else {
            steps.push(DeltaStep {
                base_oid: String::new(),
                instr_start,
                instr_end: pos,
                opcode: op,
                detail: "opcode 0 is reserved".into(),
                input_len: base.len(),
                output_len: out.len(),
                ok: false,
            });
            return Err(DeltaError::Parse(ParseError::InvalidDelta(
                "delta opcode 0 is reserved".into(),
            )));
        }
        if out.len() > hard_cap {
            return Err(DeltaError::BudgetExceeded {
                produced: out.len(),
                cap: hard_cap,
            });
        }
    }

    if out.len() as u64 != target_size {
        return Err(DeltaError::Parse(ParseError::InvalidDelta(format!(
            "reconstructed {} bytes but delta target size is {target_size}",
            out.len()
        ))));
    }
    Ok((out, steps))
}

fn err_step(
    mut steps: Vec<DeltaStep>,
    base: &[u8],
    out: &[u8],
    start: usize,
    end: usize,
    op: u8,
    e: ParseError,
) -> Result<(Vec<u8>, Vec<DeltaStep>), DeltaError> {
    steps.push(DeltaStep {
        base_oid: String::new(),
        instr_start: start,
        instr_end: end,
        opcode: op,
        detail: e.to_string(),
        input_len: base.len(),
        output_len: out.len(),
        ok: false,
    });
    Err(DeltaError::Parse(e))
}
