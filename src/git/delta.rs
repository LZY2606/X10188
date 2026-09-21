//! Git delta application (the "delta instruction stream").
//!
//! The stream starts with two size varints (base size, result size), followed
//! by copy/insert commands. Every step records the instruction byte range and
//! the input/output byte counts so the UI can show how an object was rebuilt.

use super::read_size_varint;

/// Outcome of applying one delta against one base.
#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub base_len: u64,
    pub declared_result_len: u64,
    /// (start, end) byte offsets inside the *decompressed delta stream*,
    /// one entry per executed command, tagged `copy`/`insert`.
    pub commands: Vec<DeltaCommand>,
}

#[derive(Debug, Clone)]
pub struct DeltaCommand {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
    pub src_offset: u64,
    pub src_len: u64,
    pub out_offset: u64,
    pub out_len: u64,
}

#[derive(Debug)]
pub enum DeltaError {
    /// The delta stream itself is malformed / truncated.
    Malformed(String),
    /// Declared base/result sizes disagree with reality (size spoofing).
    SizeMismatch {
        declared_base: u64,
        actual_base: u64,
        declared_result: u64,
    },
    /// Output would exceed the caller's budget.
    BudgetExceeded { declared_result: u64, budget: u64 },
    /// A copy command referenced bytes outside the base.
    CopyOutOfRange { offset: u64, len: u64, base_len: u64 },
    /// A copy ran past the declared (or budget-limited) result size.
    OutputOverflow { at: u64, need: u64, limit: u64 },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Malformed(m) => write!(f, "malformed delta stream: {m}"),
            DeltaError::SizeMismatch {
                declared_base,
                actual_base,
                declared_result,
            } => write!(
                f,
                "size spoof: header says base {declared_base}/result {declared_result}, actual base {actual_base}"
            ),
            DeltaError::BudgetExceeded {
                declared_result,
                budget,
            } => write!(
                f,
                "delta result size {declared_result} exceeds remaining budget {budget}"
            ),
            DeltaError::CopyOutOfRange {
                offset,
                len,
                base_len,
            } => write!(
                f,
                "copy out of range: offset {offset} len {len} but base is {base_len} bytes"
            ),
            DeltaError::OutputOverflow { at, need, limit } => write!(
                f,
                "output overflow at {at}: need {need} bytes, limit {limit}"
            ),
        }
    }
}

/// Apply `delta` to `base`, honouring an output budget in bytes.
///
/// `budget` is the maximum number of bytes the caller is still willing to
/// expand. If the declared result size exceeds it the function fails *before*
/// allocating (detecting size spoofing cheaply).
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    budget: u64,
) -> Result<DeltaOutcome, DeltaError> {
    let (declared_base, n1) = read_size(delta, 0).map_err(DeltaError::Malformed)?;
    let (declared_result, n2) =
        read_size(delta, n1).map_err(DeltaError::Malformed)?;

    if declared_base != base.len() as u64 {
        return Err(DeltaError::SizeMismatch {
            declared_base,
            actual_base: base.len() as u64,
            declared_result,
        });
    }
    if declared_result > budget {
        return Err(DeltaError::BudgetExceeded {
            declared_result,
            budget,
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(declared_result.min(1 << 20) as usize);
    let mut commands = Vec::new();
    let mut pos = n1 + n2;

    while pos < delta.len() {
        let cmd_start = pos;
        let opcode = delta[pos];
        pos += 1;

        if opcode & 0x80 != 0 {
            // COPY: seven optional offset/size bytes selected by bit flags.
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for bit in 0..4u8 {
                if opcode & (1 << bit) != 0 {
                    let b = *delta
                        .get(pos)
                        .ok_or_else(|| {
                            DeltaError::Malformed(
                                "truncated copy offset/size".to_string(),
                            )
                        })?;
                    pos += 1;
                    offset |= (b as u32) << (bit * 8);
                }
            }
            for bit in 0..3u8 {
                if opcode & (1 << (bit + 4)) != 0 {
                    let b = *delta
                        .get(pos)
                        .ok_or_else(|| {
                            DeltaError::Malformed(
                                "truncated copy offset/size".to_string(),
                            )
                        })?;
                    pos += 1;
                    size |= (b as u32) << (bit * 8);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let off = offset as u64;
            let len = size as u64;
            if off.checked_add(len).map_or(true, |end| end > base.len() as u64) {
                return Err(DeltaError::CopyOutOfRange {
                    offset: off,
                    len,
                    base_len: base.len() as u64,
                });
            }
            let out_off = out.len() as u64;
            if out_off + len > declared_result {
                return Err(DeltaError::OutputOverflow {
                    at: out_off,
                    need: out_off + len,
                    limit: declared_result,
                });
            }
            out.extend_from_slice(&base[off as usize..(off + len) as usize]);
            commands.push(DeltaCommand {
                kind: "copy",
                start: cmd_start,
                end: pos,
                src_offset: off,
                src_len: len,
                out_offset: out_off,
                out_len: len,
            });
        } else if opcode != 0 {
            // INSERT: next `opcode` bytes are copied literally.
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(DeltaError::Malformed(format!(
                    "insert of {len} bytes overruns delta stream at {pos}"
                )));
            }
            let out_off = out.len() as u64;
            if out_off as usize + len > declared_result as usize {
                return Err(DeltaError::OutputOverflow {
                    at: out_off,
                    need: out_off + len as u64,
                    limit: declared_result,
                });
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            commands.push(DeltaCommand {
                kind: "insert",
                start: cmd_start,
                end: pos,
                src_offset: 0,
                src_len: 0,
                out_offset: out_off,
                out_len: len as u64,
            });
        } else {
            return Err(DeltaError::Malformed(
                "delta opcode 0 is reserved".to_string(),
            ));
        }
    }

    if out.len() as u64 != declared_result {
        return Err(DeltaError::SizeMismatch {
            declared_base,
            actual_base: base.len() as u64,
            declared_result,
        });
    }

    Ok(DeltaOutcome {
        output: out,
        base_len: base.len() as u64,
        declared_result_len: declared_result,
        commands,
    })
}

/// Size varint at byte position `start` within the delta stream.
fn read_size(delta: &[u8], start: usize) -> Result<(u64, usize), String> {
    let first = *delta
        .get(start)
        .ok_or_else(|| "missing delta size varint".to_string())?;
    let mut size: u64 = (first & 0x7f) as u64;
    let mut shift = 7u32;
    let mut consumed = 1usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *delta
            .get(start + consumed)
            .ok_or_else(|| "truncated delta size varint".to_string())?;
        consumed += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("delta size varint too large".to_string());
        }
    }
    Ok((size, consumed))
}

/// Encode the two leading size varints of a delta stream (test/helper use).
pub fn encode_delta_sizes(base_size: u64, result_size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_size(&mut out, base_size);
    push_size(&mut out, result_size);
    out
}

fn push_size(out: &mut Vec<u8>, mut size: u64) {
    let mut bytes = vec![(size & 0x7f) as u8];
    size >>= 7;
    while size > 0 {
        bytes.push((size & 0x7f) as u8);
        size >>= 7;
    }
    let last = bytes.len() - 1;
    for (i, b) in bytes.into_iter().enumerate() {
        out.push(b | if i != last { 0x80 } else { 0 });
    }
}

/// Build an INSERT command (test/helper use).
pub fn insert_command(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 127);
    let mut out = vec![data.len() as u8];
    out.extend_from_slice(data);
    out
}

/// Build a COPY command (test/helper use).
pub fn copy_command(offset: u32, size: u32) -> Vec<u8> {
    let mut opcode = 0x80u8;
    let mut payload = Vec::new();
    for bit in 0..4u8 {
        let b = ((offset >> (bit * 8)) & 0xff) as u8;
        if b != 0 {
            opcode |= 1 << bit;
            payload.push(b);
        }
    }
    for bit in 0..3u8 {
        let b = ((size >> (bit * 8)) & 0xff) as u8;
        if b != 0 {
            opcode |= 1 << (bit + 4);
            payload.push(b);
        }
    }
    let mut out = vec![opcode];
    out.extend(payload);
    out
}

/// Read the (base_size, result_size) header pair without applying commands.
pub fn declared_sizes(delta: &[u8]) -> Result<(u64, u64), String> {
    let (base, n1) = read_size(delta, 0)?;
    let (result, _n2) = read_size(delta, n1)?;
    Ok((base, result))
}
