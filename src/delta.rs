//! Git copy/insert delta decoding. The applier is budget-aware and can be
//! paused/resumed mid-stream so a partial output is never treated as a result.

use crate::error::{Error, Result};
use crate::git::inflate_zlib;
use serde::Serialize;

/// A single decoded delta instruction, with its byte range inside the
/// (inflated) delta stream and the output bytes it produced.
#[derive(Debug, Clone, Serialize)]
pub struct DeltaInstr {
    pub index: usize,
    pub kind: &'static str, // "copy" | "insert"
    pub delta_start: usize,
    pub delta_end: usize,
    pub base_start: Option<u64>,
    pub len: u64,
    pub out_start: u64,
}

/// Parsed delta: sizes plus instructions.
#[derive(Debug, Clone)]
pub struct Delta {
    pub base_size: u64,
    pub result_size: u64,
    pub instructions: Vec<RawInstr>,
    pub total_delta_bytes: usize,
}

#[derive(Debug, Clone)]
pub enum RawInstr {
    Copy {
        delta_start: usize,
        delta_end: usize,
        offset: u64,
        len: u64,
    },
    Insert {
        delta_start: usize,
        delta_end: usize,
        data_start: usize,
        len: usize,
    },
}

fn read_delta_size(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut size: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return Err(Error::BadDelta("size varint runs past end".into()));
        }
        let b = data[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(size)
}

/// Inflate the delta bytes then fully parse them into validated instructions.
pub fn parse_delta_compressed(pack: &[u8], zlib_start: usize, zlib_len: usize) -> Result<Delta> {
    let (data, consumed) = inflate_zlib(pack, zlib_start)?;
    if consumed != zlib_len {
        return Err(Error::BadDelta(format!(
            "zlib boundary mismatch: header said {zlib_len}, consumed {consumed}"
        )));
    }
    parse_delta(&data)
}

pub fn parse_delta(data: &[u8]) -> Result<Delta> {
    let mut pos = 0;
    let base_size = read_delta_size(data, &mut pos)?;
    let result_size = read_delta_size(data, &mut pos)?;
    let mut instructions = Vec::new();
    while pos < data.len() {
        let opcode = data[pos];
        let delta_start = pos;
        pos += 1;
        if opcode & 0x80 != 0 {
            // COPY
            let mut offset: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if opcode & (1 << i) != 0 {
                    if pos >= data.len() {
                        return Err(Error::BadDelta("copy offset truncated".into()));
                    }
                    offset |= (data[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if opcode & (1 << (4 + i)) != 0 {
                    if pos >= data.len() {
                        return Err(Error::BadDelta("copy length truncated".into()));
                    }
                    len |= (data[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if offset.checked_add(len).map_or(true, |end| end > base_size) {
                return Err(Error::BadDelta(format!(
                    "copy overruns base: offset {offset} len {len} base_size {base_size}"
                )));
            }
            instructions.push(RawInstr::Copy {
                delta_start,
                delta_end: pos,
                offset,
                len,
            });
        } else if opcode > 0 {
            // INSERT
            let len = opcode as usize;
            if pos + len > data.len() {
                return Err(Error::BadDelta("insert data truncated".into()));
            }
            instructions.push(RawInstr::Insert {
                delta_start,
                delta_end: pos + len,
                data_start: pos,
                len,
            });
            pos += len;
        } else {
            return Err(Error::BadDelta("opcode 0 is reserved".into()));
        }
    }
    let declared_out: u64 = instructions
        .iter()
        .map(|i| match i {
            RawInstr::Copy { len, .. } => *len,
            RawInstr::Insert { len, .. } => *len as u64,
        })
        .sum();
    if declared_out != result_size {
        return Err(Error::BadDelta(format!(
            "delta result size spoof: header says {result_size}, instructions emit {declared_out}"
        )));
    }
    Ok(Delta {
        base_size,
        result_size,
        instructions,
        total_delta_bytes: data.len(),
    })
}

/// Resource budget governing reconstruction.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Budget {
    pub max_depth: usize,
    pub max_total_bytes: u64,
    pub max_object_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 16,
            max_total_bytes: 2 * 1024 * 1024,
            max_object_ratio: 64.0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BudgetCounters {
    pub bytes_used: u64,
}

/// Why an application stopped.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyOutcome {
    Complete,
    Paused,
}

#[derive(Debug)]
pub struct ApplyReport {
    pub outcome: ApplyOutcome,
    pub output: Vec<u8>,
    pub executed: Vec<DeltaInstr>,
    /// index of the next instruction to run on resume
    pub next_instr: usize,
    pub bytes_added_this_call: u64,
    pub pause_reason: Option<String>,
}

/// Apply (or resume applying) a delta. `existing_output`/`start_instr` are used
/// when resuming a previously paused application.
///
/// `object_cumulative_bytes` is the total expansion already charged to the
/// current target object on prior calls (for the per-object ratio gate).
pub fn apply_delta(
    delta: &Delta,
    delta_bytes: &[u8],
    base: &[u8],
    budget: Budget,
    counters: &mut BudgetCounters,
    object_cumulative_bytes: u64,
    existing_output: Vec<u8>,
    start_instr: usize,
) -> Result<ApplyReport> {
    if base.len() as u64 != delta.base_size {
        return Err(Error::BadDelta(format!(
            "base size mismatch: delta expects {}, got {}",
            delta.base_size,
            base.len()
        )));
    }
    let mut output = existing_output;
    let mut executed = Vec::new();
    let mut bytes_added = 0u64;
    let mut pause_reason = None;

    for (idx, instr) in delta.instructions.iter().enumerate().skip(start_instr) {
        let out_start = output.len() as u64;
        let (kind, dstart, dend, bstart, len) = match *instr {
            RawInstr::Copy {
                delta_start,
                delta_end,
                offset,
                len,
            } => {
                // Budget gates run before producing bytes.
                if let Some(reason) = gate(
                    budget,
                    counters,
                    object_cumulative_bytes + bytes_added,
                    delta.base_size,
                    len,
                ) {
                    pause_reason = Some(reason);
                    return Ok(stop(
                        output,
                        executed,
                        idx,
                        bytes_added,
                        pause_reason,
                    ));
                }
                let end = offset + len;
                output.extend_from_slice(&base[offset as usize..end as usize]);
                ("copy", delta_start, delta_end, Some(offset), len)
            }
            RawInstr::Insert {
                delta_start,
                delta_end,
                data_start,
                len,
            } => {
                if let Some(reason) = gate(
                    budget,
                    counters,
                    object_cumulative_bytes + bytes_added,
                    delta.base_size,
                    len as u64,
                ) {
                    pause_reason = Some(reason);
                    return Ok(stop(
                        output,
                        executed,
                        idx,
                        bytes_added,
                        pause_reason,
                    ));
                }
                output.extend_from_slice(
                    &delta_bytes[data_start..data_start + len],
                );
                (
                    "insert",
                    delta_start,
                    delta_end,
                    None,
                    len as u64,
                )
            }
        };
        counters.bytes_used += len;
        bytes_added += len;
        executed.push(DeltaInstr {
            index: idx,
            kind,
            delta_start: dstart,
            delta_end: dend,
            base_start: bstart,
            len,
            out_start,
        });
    }

    if output.len() as u64 != delta.result_size {
        return Err(Error::BadDelta(format!(
            "output length {} != result size {}",
            output.len(),
            delta.result_size
        )));
    }
    Ok(ApplyReport {
        outcome: ApplyOutcome::Complete,
        output,
        executed,
        next_instr: delta.instructions.len(),
        bytes_added_this_call: bytes_added,
        pause_reason: None,
    })
}

fn stop(
    output: Vec<u8>,
    executed: Vec<DeltaInstr>,
    next_instr: usize,
    bytes_added: u64,
    reason: Option<String>,
) -> ApplyReport {
    ApplyReport {
        outcome: ApplyOutcome::Paused,
        output,
        executed,
        next_instr,
        bytes_added_this_call: bytes_added,
        pause_reason: reason,
    }
}

fn gate(
    budget: Budget,
    counters: &BudgetCounters,
    object_cumulative: u64,
    base_size: u64,
    add: u64,
) -> Option<String> {
    if counters.bytes_used + add > budget.max_total_bytes {
        return Some(format!(
            "total expansion budget {} bytes exhausted",
            budget.max_total_bytes
        ));
    }
    // Per-object ratio compares the reconstructed target against the
    // originating base of this delta step.
    if base_size > 0 {
        let projected = object_cumulative + add;
        if projected as f64 / base_size as f64 > budget.max_object_ratio {
            return Some(format!(
                "single-object expansion ratio {:.1}x exceeds limit {:.1}x",
                projected as f64 / base_size as f64,
                budget.max_object_ratio
            ));
        }
    }
    None
}
