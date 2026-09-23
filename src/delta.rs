//! Git delta instruction applier with per-instruction evidence, budget
//! enforcement and resumable checkpoints.
//!
//! Delta layout: two little-endian size varints (base size, target size),
//! followed by a stream of opcodes:
//!   * opcode with bit 7 set  -> copy a (offset,length) window from the base
//!   * opcode 1..=127         -> insert that many literal bytes
//!   * opcode 0               -> reserved / corrupt

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseReason {
    /// Delta chain longer than the depth budget.
    DepthExceeded { depth: usize, limit: usize },
    /// Total expanded bytes across all objects hit the global budget.
    TotalBudgetExhausted { used: u64, limit: u64, need: u64 },
    /// A single object's output exceeds its share of the global budget.
    ObjectCapExceeded { size: u64, cap: u64 },
}

impl std::fmt::Display for PauseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PauseReason::DepthExceeded { depth, limit } => {
                write!(f, "delta depth {depth} exceeds limit {limit}")
            }
            PauseReason::TotalBudgetExhausted { used, limit, need } => write!(
                f,
                "total expansion budget exhausted ({used}/{limit} used, {need} more bytes needed)"
            ),
            PauseReason::ObjectCapExceeded { size, cap } => write!(
                f,
                "single object size {size} exceeds per-object cap {cap}"
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pause {
    pub at_instr: usize,
    pub delta_pos: usize,
    pub out_len: usize,
    pub reason: PauseReason,
    /// Bytes already produced before the blocking instruction.
    pub output_so_far: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BadVarint,
    ReservedZeroOpcode,
    CopyOutOfRange {
        src_offset: usize,
        len: usize,
        src_len: usize,
    },
    InsertOutOfRange,
    TargetSizeExceeded {
        declared: usize,
        attempted: usize,
    },
    BaseSizeMismatch {
        declared: usize,
        actual: usize,
    },
    FinalSizeMismatch {
        declared: usize,
        actual: usize,
    },
    Paused(Pause),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated => write!(f, "delta truncated"),
            DeltaError::BadVarint => write!(f, "bad size varint in delta header"),
            DeltaError::ReservedZeroOpcode => write!(f, "reserved delta opcode 0"),
            DeltaError::CopyOutOfRange {
                src_offset,
                len,
                src_len,
            } => write!(
                f,
                "copy out of range: base[{src_offset}..{}] but base is {src_len} bytes",
                src_offset + len
            ),
            DeltaError::InsertOutOfRange => write!(f, "insert overruns delta stream"),
            DeltaError::TargetSizeExceeded { declared, attempted } => write!(
                f,
                "instructions produce {attempted} bytes but target declares {declared}"
            ),
            DeltaError::BaseSizeMismatch { declared, actual } => {
                write!(f, "delta base size {declared} != actual base {actual}")
            }
            DeltaError::FinalSizeMismatch { declared, actual } => write!(
                f,
                "delta target size spoof: declared {declared}, produced {actual}"
            ),
            DeltaError::Paused(p) => write!(f, "paused: {}", p.reason),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Evidence for one applied (or partially applied) delta instruction.
#[derive(Debug, Clone)]
pub struct DeltaStep {
    pub ordinal: usize,
    /// Byte range of the instruction (including copy operand bytes).
    pub instr_start: usize,
    pub instr_end: usize,
    pub kind: StepKind,
    /// Output window produced by this instruction.
    pub out_start: usize,
    pub out_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    Copy,
    Insert,
}

impl StepKind {
    pub fn label(self) -> &'static str {
        match self {
            StepKind::Copy => "copy",
            StepKind::Insert => "insert",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeltaHeader {
    pub base_size: usize,
    pub target_size: usize,
    pub header_len: usize,
}

pub fn read_header(delta: &[u8]) -> Result<DeltaHeader, DeltaError> {
    let (base_size, n1) = read_size_varint(delta, 0)?;
    let (target_size, n2) = read_size_varint(delta, n1)?;
    Ok(DeltaHeader {
        base_size,
        target_size,
        header_len: n1 + n2,
    })
}

fn read_size_varint(b: &[u8], start: usize) -> Result<(usize, usize), DeltaError> {
    let mut v = 0usize;
    let mut shift = 0u32;
    let mut pos = start;
    loop {
        if pos >= b.len() {
            return Err(DeltaError::Truncated);
        }
        let byte = b[pos];
        pos += 1;
        v |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DeltaError::BadVarint);
        }
    }
    // returns (value, bytes consumed)
    Ok((v, pos - start))
}

/// Parse the whole delta but do not apply it.
pub fn parse_delta(delta: &[u8]) -> Result<(DeltaHeader, Vec<RawInstr>), DeltaError> {
    let header = read_header(delta)?;
    let mut pos = header.header_len;
    let mut ordinal = 0usize;
    let mut out = Vec::new();
    while pos < delta.len() {
        let start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode == 0 {
            return Err(DeltaError::ReservedZeroOpcode);
        }
        if opcode & 0x80 != 0 {
            let mut src_offset = 0usize;
            let mut len = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    src_offset |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    len |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            out.push(RawInstr {
                ordinal,
                start,
                end: pos,
                kind: StepKind::Copy,
                src_offset: Some(src_offset),
                len,
            });
        } else {
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(DeltaError::InsertOutOfRange);
            }
            out.push(RawInstr {
                ordinal,
                start,
                end: pos + len,
                kind: StepKind::Insert,
                src_offset: None,
                len,
            });
            pos += len;
        }
        ordinal += 1;
    }
    Ok((header, out))
}

#[derive(Debug, Clone)]
pub struct RawInstr {
    pub ordinal: usize,
    pub start: usize,
    pub end: usize,
    pub kind: StepKind,
    pub src_offset: Option<usize>,
    pub len: usize,
}

/// Resource budgets enforced while resolving objects.
#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    /// Maximum number of deltas on any chain.
    pub max_depth: usize,
    /// Cumulative bytes that may be materialized during the whole run.
    pub total_bytes: u64,
    /// Maximum size of a single materialized object.
    pub object_cap: u64,
    /// Remaining portion of `total_bytes` on the current run.  The applier
    /// charges *newly produced* bytes against this, so each object's output is
    /// counted once even when a base feeds many deltas.
    pub remaining_bytes: u64,
}

impl Budgets {
    pub fn test_defaults() -> Self {
        Budgets {
            max_depth: 50,
            total_bytes: 256 * 1024 * 1024,
            object_cap: 64 * 1024 * 1024,
            remaining_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub output: Vec<u8>,
    pub steps: Vec<DeltaStep>,
}

/// A resumable checkpoint. `output` holds exactly `out_len` bytes.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub delta_pos: usize,
    pub out_len: usize,
    pub instr_ordinal: usize,
    pub output: Vec<u8>,
    pub base_size: usize,
    pub target_size: usize,
}

/// Apply `delta` against `base`.
///
/// `budget` is queried before each instruction:
///   * `depth` is the number of deltas already applied on this chain (the
///     caller checks the hard depth limit before calling).
///   * `check_total(extra_bytes)` returns Err(PauseReason) if growing by that
///     many bytes would exceed the global budget.
///
/// `resume` allows continuation from a previously paused checkpoint; in that
/// case `delta_pos`/`output` are taken from it and earlier steps are not
/// re-recorded (the stored evidence already covers them).
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    resume: Option<&Checkpoint>,
    mut budgets: Budgets,
    bytes_already_charged: u64,
) -> Result<ApplyOutcome, DeltaError> {
    let header = read_header(delta)?;
    if header.base_size != base.len() {
        return Err(DeltaError::BaseSizeMismatch {
            declared: header.base_size,
            actual: base.len(),
        });
    }

    // Per-object cap: the *final* size must fit.
    if header.target_size as u64 > budgets.object_cap {
        return Err(DeltaError::Paused(Pause {
            at_instr: 0,
            delta_pos: header.header_len,
            out_len: 0,
            reason: PauseReason::ObjectCapExceeded {
                size: header.target_size as u64,
                cap: budgets.object_cap,
            },
            output_so_far: Vec::new(),
        }));
    }

    let (mut pos, mut out, mut ordinal, mut steps, mut out_len);
    if let Some(cp) = resume {
        pos = cp.delta_pos;
        out = cp.output.clone();
        out_len = cp.out_len;
        ordinal = cp.instr_ordinal;
        steps = Vec::new();
    } else {
        pos = header.header_len;
        out = Vec::with_capacity(header.target_size.min(1 << 20));
        out_len = 0;
        ordinal = 0;
        steps = Vec::new();
    }
    let _ = &mut out_len;

    // The global budget is shared; a resume already charged the bytes it
    // produced, so subtract those from the remaining allowance.
    budgets.remaining_bytes = budgets
        .remaining_bytes
        .saturating_sub(bytes_already_charged);
    let mut local_used: u64 = 0;

    while pos < delta.len() {
        let instr_start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode == 0 {
            return Err(DeltaError::ReservedZeroOpcode);
        }

        if opcode & 0x80 != 0 {
            // ---- copy from base ----
            let mut src_offset = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    src_offset |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            let mut len = 0usize;
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    len |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if src_offset.checked_add(len).map_or(true, |end| end > base.len()) {
                return Err(DeltaError::CopyOutOfRange {
                    src_offset,
                    len,
                    src_len: base.len(),
                });
            }
            if out_len + len > header.target_size {
                return Err(DeltaError::TargetSizeExceeded {
                    declared: header.target_size,
                    attempted: out_len + len,
                });
            }
            // Budget gates (retryable pause).
            if local_used + len as u64 > budgets.remaining_bytes {
                return Err(DeltaError::Paused(Pause {
                    at_instr: ordinal,
                    delta_pos: instr_start,
                    out_len,
                    reason: PauseReason::TotalBudgetExhausted {
                        used: budgets.total_bytes - budgets.remaining_bytes + local_used,
                        limit: budgets.total_bytes,
                        need: len as u64,
                    },
                    output_so_far: out.clone(),
                }));
            }
            let piece = &base[src_offset..src_offset + len];
            out.extend_from_slice(piece);
            local_used += len as u64;
            steps.push(DeltaStep {
                ordinal,
                instr_start,
                instr_end: pos,
                kind: StepKind::Copy,
                out_start: out_len,
                out_end: out_len + len,
            });
            out_len += len;
        } else {
            // ---- insert literals ----
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(DeltaError::InsertOutOfRange);
            }
            if out_len + len > header.target_size {
                return Err(DeltaError::TargetSizeExceeded {
                    declared: header.target_size,
                    attempted: out_len + len,
                });
            }
            if local_used + len as u64 > budgets.remaining_bytes {
                return Err(DeltaError::Paused(Pause {
                    at_instr: ordinal,
                    delta_pos: instr_start,
                    out_len,
                    reason: PauseReason::TotalBudgetExhausted {
                        used: budgets.total_bytes - budgets.remaining_bytes + local_used,
                        limit: budgets.total_bytes,
                        need: len as u64,
                    },
                    output_so_far: out.clone(),
                }));
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            local_used += len as u64;
            pos += len;
            steps.push(DeltaStep {
                ordinal,
                instr_start,
                instr_end: pos,
                kind: StepKind::Insert,
                out_start: out_len,
                out_end: out_len + len,
            });
            out_len += len;
        }
        ordinal += 1;
    }

    if out.len() != header.target_size {
        return Err(DeltaError::FinalSizeMismatch {
            declared: header.target_size,
            actual: out.len(),
        });
    }

    Ok(ApplyOutcome { output: out, steps })
}

/// Turn a paused apply into a persisted checkpoint.
pub fn checkpoint_from(delta: &[u8], pause: &Pause) -> Checkpoint {
    let header = read_header(delta).expect("paused delta still has valid header");
    let mut output = pause.output_so_far.clone();
    output.truncate(pause.out_len);
    Checkpoint {
        delta_pos: pause.delta_pos,
        out_len: pause.out_len,
        instr_ordinal: pause.at_instr,
        output,
        base_size: header.base_size,
        target_size: header.target_size,
    }
}
