//! Git thin delta instruction decoding/application.
//!
//! Delta payload layout:
//!   base size: LE base-128 varint
//!   result size: LE base-128 varint
//!   instructions: copy-from-base (op >= 0x80) or insert literal (op < 0x80)

use crate::git::{read_le_varint, ObjType};

/// One applied delta instruction with raw byte range and observed lengths.
#[derive(Debug, Clone)]
pub struct DeltaInstr {
    pub index: usize,
    /// "copy" or "insert"
    pub kind: String,
    /// Byte range inside the *delta payload* covering this instruction.
    pub instr_start: usize,
    pub instr_end: usize,
    pub copy_offset: Option<u64>,
    pub copy_size: Option<u64>,
    pub insert_len: Option<usize>,
    /// Output window written by this instruction.
    pub out_start: usize,
    pub out_end: usize,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub result_type: ObjType,
    pub result: Vec<u8>,
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    pub header_len: usize,
    pub instructions: Vec<DeltaInstr>,
}

#[derive(Debug, Clone)]
pub struct DeltaError {
    pub message: String,
    /// Byte range inside the delta payload that triggered the error, if known.
    pub at: Option<(usize, usize)>,
}

impl DeltaError {
    fn msg(message: impl Into<String>) -> Self {
        DeltaError { message: message.into(), at: None }
    }
}

/// Apply `delta_payload` (the inflated delta object data) onto `base_raw`.
pub fn apply_delta(
    base_type: ObjType,
    base_raw: &[u8],
    payload: &[u8],
    result_cap: usize,
) -> Result<AppliedDelta, DeltaError> {
    let (declared_base, l1) =
        read_le_varint(payload, 0).map_err(DeltaError::msg)?;
    if declared_base as usize != base_raw.len() {
        return Err(DeltaError {
            message: format!(
                "delta base size mismatch: delta expects {} but base is {} bytes",
                declared_base,
                base_raw.len()
            ),
            at: Some((0, l1)),
        });
    }
    let (declared_result, l2) =
        read_le_varint(payload, l1).map_err(DeltaError::msg)?;
    if declared_result as usize > result_cap {
        return Err(DeltaError {
            message: format!(
                "delta result size {} exceeds per-object budget {}",
                declared_result, result_cap
            ),
            at: Some((l1, l1 + l2)),
        });
    }
    let header_len = l1 + l2;

    let mut out: Vec<u8> = Vec::with_capacity(declared_result as usize);
    let mut p = header_len;
    let mut instructions: Vec<DeltaInstr> = Vec::new();
    let mut idx = 0usize;

    while p < payload.len() {
        let instr_start = p;
        let op = payload[p];
        p += 1;
        if op & 0x80 != 0 {
            // Copy instruction: up to 4 offset bytes + up to 3 size bytes.
            let mut offset = 0u64;
            for (i, shift) in (0u32..4).enumerate() {
                if op & (1 << i) != 0 {
                    let b = *payload.get(p).ok_or_else(|| {
                        DeltaError::msg("copy instruction truncated: offset byte missing")
                    })?;
                    p += 1;
                    offset |= (b as u64) << (shift * 8);
                }
            }
            let mut size: u64 = 0;
            for (i, shift) in (4u32..7).enumerate() {
                if op & (1 << shift) != 0 {
                    let b = *payload.get(p).ok_or_else(|| {
                        DeltaError::msg("copy instruction truncated: size byte missing")
                    })?;
                    p += 1;
                    size |= (b as u64) << (i * 8);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or_else(|| {
                DeltaError::msg("copy instruction offset+size overflow")
            })? as usize;
            if end > base_raw.len() {
                return Err(DeltaError {
                    message: format!(
                        "copy out of bounds: offset={} size={} base_len={}",
                        offset, size, base_raw.len()
                    ),
                    at: Some((instr_start, p)),
                });
            }
            let out_start = out.len();
            out.extend_from_slice(&base_raw[offset as usize..end]);
            let out_end = out.len();
            instructions.push(DeltaInstr {
                index: idx,
                kind: "copy".to_string(),
                instr_start,
                instr_end: p,
                copy_offset: Some(offset),
                copy_size: Some(size),
                insert_len: None,
                out_start,
                out_end,
            });
        } else if op > 0 {
            // Insert literal: op bytes follow.
            let len = op as usize;
            if p + len > payload.len() {
                return Err(DeltaError {
                    message: format!("insert instruction truncated: needs {} bytes", len),
                    at: Some((instr_start, payload.len())),
                });
            }
            let out_start = out.len();
            out.extend_from_slice(&payload[p..p + len]);
            p += len;
            let out_end = out.len();
            instructions.push(DeltaInstr {
                index: idx,
                kind: "insert".to_string(),
                instr_start,
                instr_end: p,
                copy_offset: None,
                copy_size: None,
                insert_len: Some(len),
                out_start,
                out_end,
            });
        } else {
            return Err(DeltaError {
                message: "delta opcode 0 reserved".to_string(),
                at: Some((instr_start, p)),
            });
        }
        idx += 1;
        if out.len() > declared_result as usize {
            return Err(DeltaError {
                message: format!(
                    "size spoof: instructions produced {} bytes, declared result {}",
                    out.len(),
                    declared_result
                ),
                at: Some((instr_start, p)),
            });
        }
    }

    if out.len() as u64 != declared_result {
        return Err(DeltaError {
            message: format!(
                "size spoof: final output {} bytes != declared result {}",
                out.len(),
                declared_result
            ),
            at: None,
        });
    }

    Ok(AppliedDelta {
        result_type: base_type,
        result: out,
        declared_base_size: declared_base,
        declared_result_size: declared_result,
        header_len,
        instructions,
    })
}

/// Build a delta payload (used by tests): literal insert + copy primitives.
#[derive(Debug, Clone)]
pub enum BuildInstr {
    Insert(Vec<u8>),
    Copy { offset: u32, size: u32 },
}

pub fn build_delta(base_len: u64, result_len: u64, instrs: &[BuildInstr]) -> Vec<u8> {
    use crate::git::write_le_varint;
    let mut out = Vec::new();
    write_le_varint(base_len, &mut out);
    write_le_varint(result_len, &mut out);
    for ins in instrs {
        match ins {
            BuildInstr::Insert(data) => {
                assert!(data.len() <= 127, "literal too long: chain inserts instead");
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
            BuildInstr::Copy { offset, size } => {
                let mut op = 0x80u8;
                let off = *offset;
                let size = *size;
                if off & 0xff != 0 { op |= 0x01; }
                if off & 0xff00 != 0 { op |= 0x02; }
                if off & 0xff0000 != 0 { op |= 0x04; }
                if off & 0xff000000 != 0 { op |= 0x08; }
                if size != 0x10000 {
                    if size & 0xff != 0 { op |= 0x10; }
                    if size & 0xff00 != 0 { op |= 0x20; }
                    if size & 0xff0000 != 0 { op |= 0x40; }
                }
                out.push(op);
                if off & 0xff != 0 { out.push((off & 0xff) as u8); }
                if off & 0xff00 != 0 { out.push(((off >> 8) & 0xff) as u8); }
                if off & 0xff0000 != 0 { out.push(((off >> 16) & 0xff) as u8); }
                if off & 0xff000000 != 0 { out.push(((off >> 24) & 0xff) as u8); }
                if size != 0x10000 {
                    if size & 0xff != 0 { out.push((size & 0xff) as u8); }
                    if size & 0xff00 != 0 { out.push(((size >> 8) & 0xff) as u8); }
                    if size & 0xff0000 != 0 { out.push(((size >> 16) & 0xff) as u8); }
                }
            }
        }
    }
    out
}
