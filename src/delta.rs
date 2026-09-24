//! Delta application engine. Records every instruction range, verifies sizes, and
//! supports budget-limited, resumable execution.

use crate::gitutil::decode_varint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaInstr {
    /// Byte range of this instruction inside the delta payload.
    pub delta_off: usize,
    pub delta_len: usize,
    pub kind: String, // "copy" | "insert"
    pub src_off: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaReport {
    pub declared_base_size: u64,
    pub declared_target_size: u64,
    pub actual_base_size: u64,
    pub output_size: u64,
    pub base_size_ok: bool,
    pub target_size_ok: bool,
    pub instructions: Vec<DeltaInstr>,
    /// Number of instructions applied when the run stopped (== instructions.len()
    /// unless budget-paused mid-delta).
    pub completed: bool,
}

#[derive(Debug, Error)]
pub enum DeltaError {
    #[error("delta header truncated")]
    Truncated,
    #[error("base size mismatch: delta expects {expected}, base is {actual}")]
    BaseSizeMismatch { expected: u64, actual: u64 },
    #[error("copy out of range: offset {offset} size {size}, base len {base_len}")]
    CopyOutOfRange {
        offset: u64,
        size: u64,
        base_len: u64,
    },
    #[error("insert overruns delta payload")]
    InsertOverrun,
    #[error("output size {actual} != declared target size {declared} (size fraud)")]
    TargetSizeMismatch { declared: u64, actual: u64 },
    #[error("budget exhausted after {instructions} instructions, {bytes} output bytes")]
    BudgetExhausted { instructions: usize, bytes: u64 },
}

pub struct DeltaBudget {
    /// Max output bytes this delta step may add (shared across a whole chain).
    pub remaining_bytes: u64,
    /// Max instructions per delta step (sanity guard).
    pub max_instructions: u64,
}

pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub report: DeltaReport,
}

/// Apply a git delta to `base`. On `BudgetExhausted` the caller may retry from
/// scratch with a larger budget; the report inside the error path is returned via
/// `apply_delta_partial` when resumable state is needed.
pub fn apply_delta(base: &[u8], delta: &[u8], budget: &mut DeltaBudget) -> Result<DeltaOutcome, DeltaError> {
    let (outcome, _) = apply_delta_inner(base, delta, budget, 0, Vec::new())?;
    Ok(outcome)
}

/// Like `apply_delta`, but on budget exhaustion returns the partial state so the
/// caller can persist it and resume later.
pub fn apply_delta_partial(
    base: &[u8],
    delta: &[u8],
    budget: &mut DeltaBudget,
) -> Result<DeltaOutcome, (DeltaError, PartialDelta)> {
    match apply_delta_inner(base, delta, budget, 0, Vec::new()) {
        Ok((outcome, _)) => Ok(outcome),
        Err((e, partial)) => Err((e, partial)),
    }
}

/// Resume a previously budget-paused delta application.
pub fn resume_delta(
    base: &[u8],
    delta: &[u8],
    partial: PartialDelta,
    budget: &mut DeltaBudget,
) -> Result<DeltaOutcome, (DeltaError, PartialDelta)> {
    let start = partial.instructions_applied;
    let prefix = partial.output_prefix;
    match apply_delta_inner(base, delta, budget, start, prefix) {
        Ok((outcome, _)) => Ok(outcome),
        Err((e, p)) => Err((e, p)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDelta {
    pub instructions_applied: usize,
    pub output_prefix: Vec<u8>,
    pub report_so_far: DeltaReport,
}

fn apply_delta_inner(
    base: &[u8],
    delta: &[u8],
    budget: &mut DeltaBudget,
    resume_at: usize,
    prefix: Vec<u8>,
) -> Result<(DeltaOutcome, PartialDelta), (DeltaError, PartialDelta)> {
    // Parse header (cheap, redo on resume).
    let (decl_base, n1) = match decode_varint(delta) {
        Some(v) => v,
        None => return Err((DeltaError::Truncated, empty_partial())),
    };
    let (decl_tgt, n2) = match decode_varint(&delta[n1..]) {
        Some(v) => v,
        None => return Err((DeltaError::Truncated, empty_partial())),
    };
    if decl_base != base.len() as u64 {
        return Err((
            DeltaError::BaseSizeMismatch {
                expected: decl_base,
                actual: base.len() as u64,
            },
            empty_partial(),
        ));
    }
    let mut report = DeltaReport {
        declared_base_size: decl_base,
        declared_target_size: decl_tgt,
        actual_base_size: base.len() as u64,
        output_size: 0,
        base_size_ok: true,
        target_size_ok: false,
        instructions: Vec::new(),
        completed: false,
    };

    // Walk instructions once to know their boundaries (parse-only, no output cost).
    let mut pos = n1 + n2;
    let mut parsed: Vec<DeltaInstr> = Vec::new();
    while pos < delta.len() {
        let instr_start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err((DeltaError::Truncated, empty_partial()));
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err((DeltaError::Truncated, empty_partial()));
                    }
                    cp_size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            parsed.push(DeltaInstr {
                delta_off: instr_start,
                delta_len: pos - instr_start,
                kind: "copy".into(),
                src_off: cp_off,
                size: cp_size,
            });
        } else if op != 0 {
            let size = op as u64;
            if pos + size as usize > delta.len() {
                return Err((DeltaError::InsertOverrun, empty_partial()));
            }
            parsed.push(DeltaInstr {
                delta_off: instr_start,
                delta_len: 1 + size as usize,
                kind: "insert".into(),
                src_off: pos as u64,
                size,
            });
            pos += size as usize;
        } else {
            return Err((DeltaError::Truncated, empty_partial())); // opcode 0 reserved
        }
    }

    let mut out = prefix;
    let start = resume_at.min(parsed.len());
    report.instructions = parsed[..start].to_vec();
    for (idx, instr) in parsed.iter().enumerate().skip(start) {
        if parsed.len() as u64 > budget.max_instructions {
            let partial = PartialDelta {
                instructions_applied: idx,
                output_prefix: out.clone(),
                report_so_far: report.clone(),
            };
            return Err((
                DeltaError::BudgetExhausted {
                    instructions: idx,
                    bytes: out.len() as u64,
                },
                partial,
            ));
        }
        if instr.size > budget.remaining_bytes {
            let partial = PartialDelta {
                instructions_applied: idx,
                output_prefix: out.clone(),
                report_so_far: report.clone(),
            };
            return Err((
                DeltaError::BudgetExhausted {
                    instructions: idx,
                    bytes: out.len() as u64,
                },
                partial,
            ));
        }
        match instr.kind.as_str() {
            "copy" => {
                let end = instr.src_off.checked_add(instr.size).ok_or((
                    DeltaError::CopyOutOfRange {
                        offset: instr.src_off,
                        size: instr.size,
                        base_len: base.len() as u64,
                    },
                    empty_partial(),
                ))?;
                if end > base.len() as u64 {
                    return Err((
                        DeltaError::CopyOutOfRange {
                            offset: instr.src_off,
                            size: instr.size,
                            base_len: base.len() as u64,
                        },
                        empty_partial(),
                    ));
                }
                out.extend_from_slice(&base[instr.src_off as usize..end as usize]);
            }
            "insert" => {
                let s = instr.src_off as usize;
                out.extend_from_slice(&delta[s..s + instr.size as usize]);
            }
            _ => unreachable!(),
        }
        budget.remaining_bytes -= instr.size;
        report.instructions.push(instr.clone());
    }
    report.output_size = out.len() as u64;
    report.target_size_ok = out.len() as u64 == decl_tgt;
    report.completed = true;
    if !report.target_size_ok {
        return Err((
            DeltaError::TargetSizeMismatch {
                declared: decl_tgt,
                actual: out.len() as u64,
            },
            empty_partial(),
        ));
    }
    Ok((
        DeltaOutcome {
            output: out,
            report: report.clone(),
        },
        PartialDelta {
            instructions_applied: parsed.len(),
            output_prefix: Vec::new(),
            report_so_far: report,
        },
    ))
}

fn empty_partial() -> PartialDelta {
    PartialDelta {
        instructions_applied: 0,
        output_prefix: Vec::new(),
        report_so_far: DeltaReport {
            declared_base_size: 0,
            declared_target_size: 0,
            actual_base_size: 0,
            output_size: 0,
            base_size_ok: false,
            target_size_ok: false,
            instructions: Vec::new(),
            completed: false,
        },
    }
}

/// Build a delta that copies `base` fully then inserts `extra` (test helper).
pub fn build_delta(base_len: usize, target_len: usize, extra: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    encode_varint(base_len as u64, &mut d);
    encode_varint(target_len as u64, &mut d);
    if base_len > 0 {
        // copy offset 0, size base_len
        let mut op = 0x80u8;
        let mut size_bytes = [0u8; 3];
        let mut n = base_len;
        let mut nb = 0;
        while n > 0 && nb < 3 {
            size_bytes[nb] = (n & 0xff) as u8;
            n >>= 8;
            nb += 1;
        }
        for i in 0..nb {
            op |= 0x10 << i;
        }
        d.push(op);
        for i in 0..nb {
            d.push(size_bytes[i]);
        }
    }
    let mut rest = extra;
    while !rest.is_empty() {
        let take = rest.len().min(127);
        d.push(take as u8);
        d.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
    }
    d
}

pub fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}
