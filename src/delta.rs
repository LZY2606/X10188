//! Git delta instruction decoder and applier.
//!
//! Deltas consist of `<base_size><result_size>` (two LE-base128 values)
//! followed by COPY / INSERT / ZERO commands. Every applied command is
//! recorded with its raw instruction byte range and running input/output
//! positions, giving the "delta chain microscope" its per-step evidence.

use crate::gitio::{read_le_base128, ObjType};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeltaStep {
    pub index: i64,
    pub kind: String,
    /// Byte range of the encoded instruction within the delta payload.
    pub insn_start: i64,
    pub insn_end: i64,
    pub src_start: Option<i64>,
    pub src_len: Option<i64>,
    pub out_start: i64,
    pub out_end: i64,
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub base_size: u64,
    pub result_size: u64,
    pub output: Vec<u8>,
    pub steps: Vec<DeltaStep>,
}

fn check_size(actual: usize, declared: u64, what: &str) -> Result<(), String> {
    if actual as u64 != declared {
        return Err(format!(
            "{what} length {actual} disagrees with declared {declared} (size spoofing)"
        ));
    }
    Ok(())
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, String> {
    let (base_size, n1) = read_le_base128(delta, 0).map_err(|e| format!("base size: {e}"))?;
    let (result_size, n2) = read_le_base128(delta, n1).map_err(|e| format!("result size: {e}"))?;
    check_size(base.len(), base_size, "base")?;

    let mut pos = n1 + n2;
    let mut output: Vec<u8> = Vec::new();
    let mut steps: Vec<DeltaStep> = Vec::new();
    let mut idx = 0i64;

    while pos < delta.len() {
        let op = delta[pos];
        let insn_start = pos;
        if op == 0 {
            return Err(format!(
                "delta opcode 0x00 is reserved (at byte {pos})"
            ));
        }
        if op & 0x80 != 0 {
            // COPY: little-endian offset then length, each byte present per
            // the corresponding bit in the opcode.
            let mut copy_off: u32 = 0;
            for bit in 0..4u8 {
                pos += 1;
                if pos >= delta.len() {
                    return Err("truncated COPY offset bytes".into());
                }
                if op & (1 << bit) != 0 {
                    copy_off |= (delta[pos] as u32) << (8 * bit);
                }
            }
            let mut copy_len: u32 = 0;
            for bit in 0..3u8 {
                pos += 1;
                if pos >= delta.len() {
                    return Err("truncated COPY length bytes".into());
                }
                if op & (1 << (bit + 4)) != 0 {
                    copy_len |= (delta[pos] as u32) << (8 * bit);
                }
            }
            pos += 1; // operand bytes consumed; opcode counted implicitly
            if copy_len == 0 {
                copy_len = 0x10000;
            }
            let start = copy_off as usize;
            let len = copy_len as usize;
            let out_start = output.len() as i64;
            let ok = start
                .checked_add(len)
                .map(|end| end <= base.len())
                .unwrap_or(false);
            if ok {
                output.extend_from_slice(&base[start..start + len]);
            } else {
                return Err(format!(
                    "COPY command reads base[{start}..{}] but base is {} bytes",
                    start + len,
                    base.len()
                ));
            }
            steps.push(DeltaStep {
                index: idx,
                kind: "COPY".into(),
                insn_start: insn_start as i64,
                insn_end: pos as i64,
                src_start: Some(start as i64),
                src_len: Some(len as i64),
                out_start,
                out_end: output.len() as i64,
                ok: true,
            });
        } else {
            // INSERT: next `op` literal bytes.
            let len = op as usize;
            pos += 1;
            if pos + len > delta.len() {
                return Err("INSERT overruns delta payload".into());
            }
            let out_start = output.len() as i64;
            output.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            steps.push(DeltaStep {
                index: idx,
                kind: "INSERT".into(),
                insn_start: insn_start as i64,
                insn_end: pos as i64,
                src_start: None,
                src_len: None,
                out_start,
                out_end: output.len() as i64,
                ok: true,
            });
        }
        idx += 1;
    }

    check_size(output.len(), result_size, "result")?;
    Ok(AppliedDelta {
        base_size,
        result_size,
        output,
        steps,
    })
}

/// Read only the declared base/result sizes (used when recording evidence
/// for a candidate whose base cannot be resolved).
pub fn delta_header(delta: &[u8]) -> Result<(u64, u64), String> {
    let (base_size, n1) = read_le_base128(delta, 0).map_err(|e| format!("base size: {e}"))?;
    let (result_size, _) = read_le_base128(delta, n1).map_err(|e| format!("result size: {e}"))?;
    Ok((base_size, result_size))
}

pub fn resolve_kind(base_kind: ObjType) -> Result<ObjType, String> {
    match base_kind {
        ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => Ok(base_kind),
        other => Err(format!(
            "delta base must resolve to a concrete object, found {}",
            other.name()
        )),
    }
}
