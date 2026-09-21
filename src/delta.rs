//! Git delta instruction decoding and application, with per-step evidence.

use crate::gitobj::read_delta_varint;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaInfo {
    pub base_size: u64,
    pub result_size: u64,
    pub instr_count: usize,
    pub copy_bytes: u64,
    pub insert_bytes: u64,
    /// Byte range of the instruction stream inside the delta buffer.
    pub instr_range: (usize, usize),
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInfo), String> {
    let mut pos = 0usize;
    let base_size = read_delta_varint(delta, &mut pos)?;
    if base_size != base.len() as u64 {
        return Err(format!(
            "delta base size mismatch: delta expects {base_size}, base is {}",
            base.len()
        ));
    }
    let result_size = read_delta_varint(delta, &mut pos)?;
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(result_size as usize);
    let mut instr_count = 0usize;
    let mut copy_bytes = 0u64;
    let mut insert_bytes = 0u64;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        instr_count += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy instruction truncated (offset)".into());
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy instruction truncated (size)".into());
                    }
                    cp_size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or("copy range overflow")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy range {cp_off}..{end} beyond base length {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            copy_bytes += cp_size;
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert instruction truncated".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            insert_bytes += n as u64;
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
        if out.len() as u64 > result_size {
            return Err(format!(
                "delta output overran declared result size {result_size}"
            ));
        }
    }
    if out.len() as u64 != result_size {
        return Err(format!(
            "size deception: delta declares result {result_size}, produced {}",
            out.len()
        ));
    }
    Ok((
        out,
        DeltaInfo {
            base_size,
            result_size,
            instr_count,
            copy_bytes,
            insert_bytes,
            instr_range: (instr_start, delta.len()),
        },
    ))
}
