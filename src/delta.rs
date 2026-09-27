use serde::Serialize;

/// Read a little-endian base-128 size used inside git delta data.
pub fn read_delta_size(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut size = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return Err("truncated delta size".into());
        }
        let b = data[pos];
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok((size, pos))
}

pub fn write_delta_size(out: &mut Vec<u8>, mut size: u64) {
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

#[derive(Clone, Debug, Serialize)]
pub struct DeltaStep {
    /// Zero-based instruction index within this delta application.
    pub index: usize,
    pub op: String,
    /// Raw byte range of the instruction within the inflated delta.
    pub instr_start: usize,
    pub instr_end: usize,
    /// Copy: range inside the base object; insert: 0.
    pub base_start: usize,
    pub input_len: usize,
    /// Bytes appended to the output by this instruction.
    pub output_len: usize,
    /// Total output length after the instruction.
    pub output_total: usize,
    pub check: String,
}

#[derive(Clone, Debug)]
pub enum PauseReason {
    TotalBudget,
    SingleRatio,
    MaxDepth,
}

impl PauseReason {
    pub fn name(&self) -> &'static str {
        match self {
            PauseReason::TotalBudget => "total_expand_bytes",
            PauseReason::SingleRatio => "single_object_ratio",
            PauseReason::MaxDepth => "max_depth",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApplyCheckpoint {
    pub next_instr_pos: usize,
    pub output_len: usize,
    pub next_step_index: usize,
}

#[derive(Clone, Debug)]
pub struct ApplyBudget {
    /// Bytes still available in the global expansion budget.
    pub remaining_total: u64,
    /// Maximum output length allowed for this one object.
    pub single_cap: u64,
}

pub enum DeltaError {
    Spoof {
        message: String,
    },
    BadInstruction {
        message: String,
        instr_start: usize,
        instr_end: usize,
        steps: Vec<DeltaStep>,
    },
    Paused {
        reason: PauseReason,
        checkpoint: ApplyCheckpoint,
        output: Vec<u8>,
        steps: Vec<DeltaStep>,
    },
}

pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub steps: Vec<DeltaStep>,
    pub declared_source: u64,
    pub declared_target: u64,
}

fn parse_delta_header(delta: &[u8]) -> Result<(u64, u64, usize), String> {
    let (source, p1) = read_delta_size(delta, 0)?;
    let (target, p2) = read_delta_size(delta, p1)?;
    Ok((source, target, p2))
}

/// Apply `delta` to `base`, starting from a previously persisted checkpoint.
/// Every instruction is recorded with its raw range, IO lengths and check.
pub fn apply_resume(
    base: &[u8],
    delta: &[u8],
    budget: ApplyBudget,
    resume: Option<(ApplyCheckpoint, Vec<u8>)>,
) -> Result<DeltaOutcome, DeltaError> {
    let (declared_source, declared_target, header_end) =
        parse_delta_header(delta).map_err(|m| DeltaError::Spoof { message: m })?;

    if declared_source as usize != base.len() {
        return Err(DeltaError::Spoof {
            message: format!(
                "delta declares source size {declared_source} but base is {} bytes",
                base.len()
            ),
        });
    }

    let mut steps: Vec<DeltaStep> = Vec::new();
    let (mut pos, mut output, mut step_index) = match resume {
        Some((cp, partial)) => {
            if partial.len() != cp.output_len {
                return Err(DeltaError::Spoof {
                    message: "checkpoint output length mismatch".into(),
                });
            }
            (cp.next_instr_pos, partial, cp.next_step_index)
        }
        None => (header_end, Vec::new(), 0usize),
    };
    let mut remaining_total = budget.remaining_total;
    let mut used_total: u64 = 0;

    let reserve = |need: usize| -> Result<(), DeltaError> {
        let new_len = output.len() + need;
        if new_len as u64 > budget.single_cap {
            return Err(DeltaError::Paused {
                reason: PauseReason::SingleRatio,
                checkpoint: ApplyCheckpoint {
                    next_instr_pos: pos,
                    output_len: output.len(),
                    next_step_index: step_index,
                },
                output: output.clone(),
                steps: steps.clone(),
            });
        }
        if need as u64 > remaining_total {
            return Err(DeltaError::Paused {
                reason: PauseReason::TotalBudget,
                checkpoint: ApplyCheckpoint {
                    next_instr_pos: pos,
                    output_len: output.len(),
                    next_step_index: step_index,
                },
                output: output.clone(),
                steps: steps.clone(),
            });
        }
        Ok(())
    };

    while pos < delta.len() {
        let instr_start = pos;
        let op = delta[pos];
        if op == 0 {
            return Err(DeltaError::BadInstruction {
                message: "opcode 0 is reserved".into(),
                instr_start,
                instr_end: pos + 1,
                steps,
            });
        }
        if op & 0x80 != 0 {
            // COPY from base.
            pos += 1;
            let mut copy_off: usize = 0;
            let mut copy_size: usize = 0;
            for bit in 0..4u8 {
                if op & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::BadInstruction {
                            message: "copy instruction truncated (offset)".into(),
                            instr_start,
                            instr_end: pos,
                            steps,
                        });
                    }
                    copy_off |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3u8 {
                if op & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::BadInstruction {
                            message: "copy instruction truncated (size)".into(),
                            instr_start,
                            instr_end: pos,
                            steps,
                        });
                    }
                    copy_size |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let instr_end = pos;
            let check = if copy_off.checked_add(copy_size).map_or(true, |e| e > base.len()) {
                let msg = format!(
                    "copy [{copy_off}..{}] outside base of {}",
                    copy_off + copy_size,
                    base.len()
                );
                steps.push(DeltaStep {
                    index: step_index,
                    op: "copy".into(),
                    instr_start,
                    instr_end,
                    base_start: copy_off,
                    input_len: copy_size,
                    output_len: 0,
                    output_total: output.len(),
                    check: format!("FAIL: {msg}"),
                });
                return Err(DeltaError::BadInstruction {
                    message: msg,
                    instr_start,
                    instr_end,
                    steps,
                });
            } else {
                "ok".to_string()
            };
            if let Err(e) = reserve(copy_size) {
                return Err(e);
            }
            output.extend_from_slice(&base[copy_off..copy_off + copy_size]);
            remaining_total -= copy_size as u64;
            used_total += copy_size as u64;
            steps.push(DeltaStep {
                index: step_index,
                op: "copy".into(),
                instr_start,
                instr_end,
                base_start: copy_off,
                input_len: copy_size,
                output_len: copy_size,
                output_total: output.len(),
                check,
            });
            step_index += 1;
        } else {
            // INSERT literal bytes.
            let take = op as usize;
            if pos + 1 + take > delta.len() {
                return Err(DeltaError::BadInstruction {
                    message: format!("insert instruction needs {take} bytes but delta ends"),
                    instr_start,
                    instr_end: delta.len(),
                    steps,
                });
            }
            if let Err(e) = reserve(take) {
                return Err(e);
            }
            output.extend_from_slice(&delta[pos + 1..pos + 1 + take]);
            remaining_total -= take as u64;
            used_total += take as u64;
            steps.push(DeltaStep {
                index: step_index,
                op: "insert".into(),
                instr_start,
                instr_end: pos + 1 + take,
                base_start: 0,
                input_len: 0,
                output_len: take,
                output_total: output.len(),
                check: "ok".to_string(),
            });
            pos += 1 + take;
            step_index += 1;
        }
    }

    if output.len() as u64 != declared_target {
        return Err(DeltaError::Spoof {
            message: format!(
                "delta declares target size {declared_target} but produced {} bytes",
                output.len()
            ),
        });
    }
    let _ = used_total;
    Ok(DeltaOutcome {
        output,
        steps,
        declared_source,
        declared_target,
    })
}

pub fn apply(base: &[u8], delta: &[u8], budget: ApplyBudget) -> Result<DeltaOutcome, DeltaError> {
    apply_resume(base, delta, budget, None)
}

/// Number of expansion bytes a successful application consumed (total output
/// bytes produced by copy/insert instructions).
pub fn expanded_bytes(steps: &[DeltaStep]) -> u64 {
    steps.iter().map(|s| s.output_len as u64).sum()
}
