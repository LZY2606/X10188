use crate::error::{Error, ErrorCode, R};
use crate::gitenc::read_var_size;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaInstr {
    pub index: i64,
    pub op: String,
    pub delta_offset: i64,
    pub delta_len: i64,
    pub src_offset: Option<i64>,
    pub src_len: Option<i64>,
    pub out_offset: i64,
    pub out_len: i64,
}

pub struct Budget {
    pub used: u64,
    pub total: u64,
    pub single_cap: u64,
}

impl Budget {
    /// Reserve space for a single logical object; used as a preflight against
    /// the declared (therefore safe upper-bound) target size.
    pub fn preflight_object(&self, declared: u64) -> R<()> {
        if declared > self.single_cap {
            return Err(Error::new(
                ErrorCode::ObjectTooLarge,
                format!("object {} bytes exceeds single-object cap {}", declared, self.single_cap),
            ));
        }
        if self.used.saturating_add(declared) > self.total {
            return Err(Error::new(
                ErrorCode::BudgetExhausted,
                format!("object {} bytes would exceed expansion budget {}/{}", declared, self.used, self.total),
            ));
        }
        Ok(())
    }

    pub fn charge_chunk(&mut self, n: usize) -> R<()> {
        let n = n as u64;
        if self.used.saturating_add(n) > self.total {
            return Err(Error::new(
                ErrorCode::BudgetExhausted,
                format!("expansion budget exhausted at {} + {} > {}", self.used, n, self.total),
            ));
        }
        self.used += n;
        Ok(())
    }
}

pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub base_size: u64,
    pub result_size: u64,
    pub body_offset: usize,
    pub body_len: usize,
    pub instructions: Vec<DeltaInstr>,
}

/// Apply a Git delta to `base`, recording every instruction and enforcing the
/// expansion budget while the stream runs.
pub fn apply_delta(base: &[u8], delta: &[u8], budget: &mut Budget) -> R<AppliedDelta> {
    let (base_size, p1) = read_var_size(delta, 0)?;
    let (result_size, p2) = read_var_size(delta, p1)?;
    if base_size as usize != base.len() {
        return Err(Error::new(
            ErrorCode::DeltaSizeMismatch,
            format!("delta declares base {} but got {} bytes", base_size, base.len()),
        ));
    }
    // Preflight with the declared target size so the budget decision happens
    // before any output is materialized.
    budget.preflight_object(result_size)?;

    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(budget.single_cap) as usize);
    let mut pos = p2;
    let mut instrs: Vec<DeltaInstr> = Vec::new();
    let mut idx = 0i64;

    while pos < delta.len() {
        let start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(Error::new(ErrorCode::DeltaBadInstruction, "copy offset truncated"));
                    }
                    cp_off |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err(Error::new(ErrorCode::DeltaBadInstruction, "copy size truncated"));
                    }
                    cp_size |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = (cp_off as u64)
                .checked_add(cp_size as u64)
                .ok_or_else(|| Error::new(ErrorCode::DeltaCopyOutOfRange, "copy offset+size overflow"))?;
            if end > base.len() as u64 {
                return Err(Error::new(
                    ErrorCode::DeltaCopyOutOfRange,
                    format!("copy {}+{} exceeds base {}", cp_off, cp_size, base.len()),
                ));
            }
            if (out.len() as u64) + cp_size as u64 > result_size {
                return Err(Error::new(ErrorCode::DeltaResultTooLong, "copy would overflow declared result"));
            }
            budget.charge_chunk(cp_size as usize)?;
            let out_offset = out.len();
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            instrs.push(DeltaInstr {
                index: idx,
                op: "copy".into(),
                delta_offset: start as i64,
                delta_len: (pos - start) as i64,
                src_offset: Some(cp_off as i64),
                src_len: Some(cp_size as i64),
                out_offset: out_offset as i64,
                out_len: cp_size as i64,
            });
            idx += 1;
        } else if op != 0 {
            // INSERT
            let n = op as usize;
            if pos + n > delta.len() {
                return Err(Error::new(ErrorCode::DeltaBadInstruction, "insert body truncated"));
            }
            if out.len() + n > result_size as usize {
                return Err(Error::new(ErrorCode::DeltaResultTooLong, "insert would overflow declared result"));
            }
            budget.charge_chunk(n)?;
            let out_offset = out.len();
            out.extend_from_slice(&delta[pos..pos + n]);
            instrs.push(DeltaInstr {
                index: idx,
                op: "insert".into(),
                delta_offset: start as i64,
                delta_len: (1 + n) as i64,
                src_offset: None,
                src_len: None,
                out_offset: out_offset as i64,
                out_len: n as i64,
            });
            pos += n;
            idx += 1;
        } else {
            return Err(Error::new(ErrorCode::DeltaBadInstruction, "opcode 0 is reserved"));
        }
    }

    if out.len() != result_size as usize {
        return Err(Error::new(
            ErrorCode::DeltaSizeMismatch,
            format!("declared result {} but produced {} bytes", result_size, out.len()),
        ));
    }

    Ok(AppliedDelta {
        output: out,
        base_size,
        result_size,
        body_offset: p2,
        body_len: delta.len() - p2,
        instructions: instrs,
    })
}
