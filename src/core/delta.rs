// Git delta payload decoder (the "copy/insert" command sequence) and applier.

use super::git::read_delta_varint;
use super::git::ParseError;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmdKind {
    Copy { offset: usize, len: usize },
    Insert { len: usize },
}

#[derive(Clone, Debug)]
pub struct DeltaCmd {
    pub index: usize,
    /// Half-open byte range of this command inside the (inflated) delta payload.
    pub range: (usize, usize),
    pub kind: CmdKind,
}

#[derive(Clone, Debug)]
pub struct DeltaHeader {
    pub base_size: u64,
    pub target_size: u64,
    /// Byte offset where the command section starts.
    pub instr_start: usize,
}

#[derive(Debug)]
pub enum DeltaError {
    Parse(ParseError),
    BadCommand(String),
    OutputSizeMismatch { declared: u64, actual: usize },
    /// Reconstruction aborted before completion because a resource budget
    /// would be crossed. No output from this attempt is published.
    BudgetPaused { target_size: u64, reason: PauseReason },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PauseReason {
    /// Output would cross the per-object expansion allowance.
    SingleObject,
    /// Output would cross the global total-expansion allowance.
    TotalBytes,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Parse(p) => write!(f, "{p}"),
            DeltaError::BadCommand(s) => write!(f, "bad delta command: {s}"),
            DeltaError::OutputSizeMismatch { declared, actual } => write!(
                f,
                "delta declared target size {declared} but commands emitted {actual} bytes"
            ),
            DeltaError::BudgetPaused { target_size, reason } => write!(
                f,
                "reconstruction paused at {target_size} target bytes ({reason:?} budget)"
            ),
        }
    }
}

pub fn parse_header(delta: &[u8]) -> Result<DeltaHeader, DeltaError> {
    let (base_size, p1) = read_delta_varint(delta, 0).map_err(DeltaError::Parse)?;
    let (target_size, p2) = read_delta_varint(delta, p1).map_err(DeltaError::Parse)?;
    Ok(DeltaHeader {
        base_size,
        target_size,
        instr_start: p2,
    })
}

/// Apply `delta` onto `base`.
///
/// `single_allow` / `total_allow` are the maximum output bytes this
/// reconstruction may emit under the per-object ratio limit and the remaining
/// global expansion budget. Exceeding either aborts with `BudgetPaused`.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    single_allow: usize,
    total_allow: usize,
) -> Result<(Vec<u8>, Vec<DeltaCmd>, DeltaHeader), DeltaError> {
    let header = parse_header(delta)?;
    if header.base_size as usize != base.len() {
        return Err(DeltaError::BadCommand(format!(
            "delta wants base of {} bytes but base is {} bytes",
            header.base_size,
            base.len()
        )));
    }
    let target = header.target_size as usize;
    let allow = single_allow.min(total_allow);
    if target > allow {
        return Err(DeltaError::BudgetPaused {
            target_size: header.target_size,
            reason: if target > single_allow {
                PauseReason::SingleObject
            } else {
                PauseReason::TotalBytes
            },
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(target.min(1 << 20));
    let mut cmds: Vec<DeltaCmd> = Vec::new();
    let mut p = header.instr_start;
    let mut idx = 0usize;

    while p < delta.len() {
        let cmd_start = p;
        let op = delta[p];
        p += 1;

        if op & 0x80 != 0 {
            // COPY from base.
            let mut offset: usize = 0;
            let mut len: usize = 0;
            for bit in 0..7u8 {
                if op & (1 << bit) != 0 {
                    let byte = *delta
                        .get(p)
                        .ok_or_else(|| DeltaError::Parse(ParseError::Truncated(
                            "copy operand truncated".into(),
                        )))?;
                    p += 1;
                    let v = byte as usize;
                    if bit < 4 {
                        offset |= v << (bit * 8);
                    } else {
                        len |= v << ((bit - 4) * 8);
                    }
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if len == 0 {
                return Err(DeltaError::BadCommand("zero-length copy".into()));
            }
            let end = offset.checked_add(len).ok_or_else(|| {
                DeltaError::BadCommand("copy offset+len overflow".into())
            })?;
            if end > base.len() {
                return Err(DeltaError::BadCommand(format!(
                    "copy range [{offset}..{end}) exceeds base of {} bytes",
                    base.len()
                )));
            }
            if out.len() + len > target {
                return Err(DeltaError::BadCommand(format!(
                    "copy of {len} bytes overshoots declared target size {target}"
                )));
            }
            if out.len() + len > allow {
                return Err(DeltaError::BudgetPaused {
                    target_size: header.target_size,
                    reason: if out.len() + len > single_allow {
                        PauseReason::SingleObject
                    } else {
                        PauseReason::TotalBytes
                    },
                });
            }
            out.extend_from_slice(&base[offset..end]);
            cmds.push(DeltaCmd {
                index: idx,
                range: (cmd_start, p),
                kind: CmdKind::Copy { offset, len },
            });
        } else if op != 0 {
            // INSERT literal bytes.
            let len = op as usize;
            if p + len > delta.len() {
                return Err(DeltaError::Parse(ParseError::Truncated(
                    "insert literals truncated".into(),
                )));
            }
            if out.len() + len > target {
                return Err(DeltaError::BadCommand(format!(
                    "insert of {len} bytes overshoots declared target size {target}"
                )));
            }
            if out.len() + len > allow {
                return Err(DeltaError::BudgetPaused {
                    target_size: header.target_size,
                    reason: if out.len() + len > single_allow {
                        PauseReason::SingleObject
                    } else {
                        PauseReason::TotalBytes
                    },
                });
            }
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
            cmds.push(DeltaCmd {
                index: idx,
                range: (cmd_start, p),
                kind: CmdKind::Insert { len },
            });
        } else {
            return Err(DeltaError::BadCommand(
                "opcode 0 is reserved".into(),
            ));
        }
        idx += 1;
    }

    if out.len() != target {
        return Err(DeltaError::OutputSizeMismatch {
            declared: header.target_size,
            actual: out.len(),
        });
    }
    Ok((out, cmds, header))
}
