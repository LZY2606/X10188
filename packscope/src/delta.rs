//! Git delta (thin-pack / ref-delta & ofs-delta) decoding and application.
//!
//! Delta layout:
//!   base_size   : varint (little-endian continuation encoding)
//!   result_size : varint
//!   instructions:
//!     MSB=0, value=0  : error ("0" insert opcode is illegal in git)
//!     MSB=0, value=v  : insert next v literal bytes
//!     MSB=1           : copy from base; bit fields give (offset, size),
//!                       size 0 meaning 0x10000.

use anyhow::{bail, Result};
use serde::Serialize;

use crate::gitfmt::{parse_size_encoding, OID_LEN};

/// One delta chain step's forensic record.
#[derive(Debug, Clone, Serialize)]
pub struct StepRecord {
    pub ordinal: usize,
    pub base_kind: String,
    pub base_ref: String,
    /// Byte span `[start,end)` of the instruction region inside the *delta* blob.
    pub instr_start: usize,
    pub instr_end: usize,
    pub copy_ops: usize,
    pub insert_ops: usize,
    pub base_len: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub expected_result_size: usize,
    pub check_ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub base_size: usize,
    pub result_size: usize,
    pub record: StepRecord,
}

/// Resource guard applied while reconstructing one object.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub max_expand_bytes: u64,
    /// Maximum decompressed size of any single object (bytes).
    pub max_single_bytes: u64,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<usize> {
    let (v, used) = parse_size_encoding(&data[*pos..])?;
    *pos += used;
    Ok(v as usize)
}

/// Apply `delta` to `base`, producing the result content and a forensic record.
///
/// `ordinal` is the position on the reconstructed chain; `base_ref`/`base_kind`
/// describe how the base was addressed. `spent_bytes` is the cumulative
/// decompressed bytes produced across the whole chain so far; the function
/// enforces both the per-object cap and the global expansion budget.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    ordinal: usize,
    base_kind: &str,
    base_ref: &str,
    budget: Budget,
    spent_bytes: u64,
) -> Result<AppliedDelta> {
    let mut pos = 0usize;
    let base_size = read_varint(delta, &mut pos)?;
    let result_size = read_varint(delta, &mut pos)?;
    let instr_start = pos;

    // Size spoofing guard #1: the declared base size must match reality.
    if base_size != base.len() {
        bail!(
            "delta base size mismatch: header declares {base_size} bytes, actual base is {} bytes",
            base.len()
        );
    }

    // Budget checks before doing work.
    if result_size as u64 > budget.max_single_bytes {
        bail!(
            "single-object budget exceeded: result would be {result_size} bytes (limit {})",
            budget.max_single_bytes
        );
    }
    if spent_bytes.saturating_add(result_size as u64) > budget.max_expand_bytes {
        bail!(
            "global expand budget exceeded: chain would produce {result_size} more bytes (spent {spent_bytes}, limit {})",
            budget.max_expand_bytes
        );
    }

    let mut out = Vec::with_capacity(result_size.min(1 << 20));
    let mut copy_ops = 0usize;
    let mut insert_ops = 0usize;

    while pos < delta.len() {
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            // Copy from base.
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            if opcode & 0x01 != 0 {
                cp_off |= delta[pos] as u32;
                pos += 1;
            }
            if opcode & 0x02 != 0 {
                cp_off |= (delta[pos] as u32) << 8;
                pos += 1;
            }
            if opcode & 0x04 != 0 {
                cp_off |= (delta[pos] as u32) << 16;
                pos += 1;
            }
            if opcode & 0x08 != 0 {
                cp_off |= (delta[pos] as u32) << 24;
                pos += 1;
            }
            if opcode & 0x10 != 0 {
                cp_size |= delta[pos] as u32;
                pos += 1;
            }
            if opcode & 0x20 != 0 {
                cp_size |= (delta[pos] as u32) << 8;
                pos += 1;
            }
            if opcode & 0x40 != 0 {
                cp_size |= (delta[pos] as u32) << 16;
                pos += 1;
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let start = cp_off as usize;
            let size = cp_size as usize;
            let end = start.checked_add(size);
            match end {
                Some(e) if e <= base.len() => {
                    out.extend_from_slice(&base[start..e]);
                }
                _ => bail!(
                    "copy out of bounds: offset {start} size {size} exceeds base of {} bytes",
                    base.len()
                ),
            }
            copy_ops += 1;
        } else if opcode == 0 {
            bail!("illegal delta opcode 0x00 (reserved)");
        } else {
            // Insert literal bytes.
            let size = opcode as usize;
            if pos + size > delta.len() {
                bail!("insert opcode demands {size} bytes but only {} remain", delta.len() - pos);
            }
            out.extend_from_slice(&delta[pos..pos + size]);
            pos += size;
            insert_ops += 1;
        }

        if out.len() as u64 > budget.max_single_bytes {
            bail!("single-object budget exceeded while applying delta (limit {})", budget.max_single_bytes);
        }
        if out.len() > result_size {
            bail!(
                "delta overrun: output {} bytes already exceeds declared result size {result_size}",
                out.len()
            );
        }
    }

    let instr_end = pos;
    let check_ok = out.len() == result_size;
    if !check_ok {
        bail!(
            "delta result size mismatch: produced {} bytes, header declares {result_size}",
            out.len()
        );
    }

    let detail = format!("{copy_ops} copy / {insert_ops} insert ops");
    Ok(AppliedDelta {
        output: out,
        base_size,
        result_size,
        record: StepRecord {
            ordinal,
            base_kind: base_kind.to_string(),
            base_ref: base_ref.to_string(),
            instr_start,
            instr_end,
            copy_ops,
            insert_ops,
            base_len: base.len(),
            input_len: base.len(),
            output_len: result_size,
            expected_result_size: result_size,
            check_ok,
            detail,
        },
    })
}

/// A synthetic delta instruction, used by the test pack builder.
#[derive(Debug, Clone)]
pub enum DeltaOp {
    Copy { offset: u32, size: u32 },
    Insert(Vec<u8>),
}

/// Encode base/result sizes + instructions into a git delta blob.
pub fn build_delta(base: &[u8], result: &[u8], ops: &[DeltaOp]) -> Vec<u8> {
    let mut out = crate::gitfmt::encode_size(base.len() as u64);
    out.extend(crate::gitfmt::encode_size(result.len() as u64));
    for op in ops {
        match op {
            DeltaOp::Insert(data) => {
                assert!(data.len() <= 127, "single insert max 127 bytes");
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
            DeltaOp::Copy { offset, size } => {
                let mut opcode = 0x80u8;
                let off = *offset;
                let siz = *size;
                if off & 0xff != 0 { opcode |= 0x01; }
                if off & 0xff00 != 0 { opcode |= 0x02; }
                if off & 0xff0000 != 0 { opcode |= 0x04; }
                if off & 0xff000000 != 0 { opcode |= 0x08; }
                if siz & 0xff != 0 { opcode |= 0x10; }
                if siz & 0xff00 != 0 { opcode |= 0x20; }
                if siz & 0xff0000 != 0 { opcode |= 0x40; }
                out.push(opcode);
                if off & 0xff != 0 { out.push((off & 0xff) as u8); }
                if off & 0xff00 != 0 { out.push(((off >> 8) & 0xff) as u8); }
                if off & 0xff0000 != 0 { out.push(((off >> 16) & 0xff) as u8); }
                if off & 0xff000000 != 0 { out.push(((off >> 24) & 0xff) as u8); }
                if siz & 0xff != 0 { out.push((siz & 0xff) as u8); }
                if siz & 0xff00 != 0 { out.push(((siz >> 8) & 0xff) as u8); }
                if siz & 0xff0000 != 0 { out.push(((siz >> 16) & 0xff) as u8); }
            }
        }
    }
    let _ = OID_LEN;
    out
}
