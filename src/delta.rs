use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instr {
    /// Offset of the opcode byte inside the delta buffer.
    pub delta_off: u64,
    pub op: String,
    /// Source offset in base (copy only).
    pub src_off: Option<u64>,
    pub len: u64,
    /// Offset in the output buffer where this instruction writes.
    pub out_off: u64,
}

#[derive(Debug)]
pub struct DeltaOutcome {
    pub out: Vec<u8>,
    pub instrs: Vec<Instr>,
    pub declared_base_size: u64,
    pub declared_result_size: u64,
}

fn read_varint(delta: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *delta.get(*pos).ok_or_else(|| "delta truncated in varint".to_string())?;
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("delta varint too large".into());
        }
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(v)
}

/// Apply a git delta to `base`, recording every instruction range.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let declared_base_size = read_varint(delta, &mut pos)?;
    if declared_base_size != base.len() as u64 {
        return Err(format!(
            "delta base size mismatch: declared {}, actual {}",
            declared_base_size,
            base.len()
        ));
    }
    let declared_result_size = read_varint(delta, &mut pos)?;
    let mut out: Vec<u8> = Vec::with_capacity(declared_result_size.min(1 << 26) as usize);
    let mut instrs = Vec::new();
    while pos < delta.len() {
        let cmd_off = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or_else(|| "delta truncated in copy offset".to_string())?;
                    pos += 1;
                    cp_off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or_else(|| "delta truncated in copy size".to_string())?;
                    pos += 1;
                    cp_size |= (b as u64) << (8 * i);
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or_else(|| "copy range overflow".to_string())?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy out of base bounds: off {} len {} base {}",
                    cp_off,
                    cp_size,
                    base.len()
                ));
            }
            let out_off = out.len() as u64;
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            instrs.push(Instr {
                delta_off: cmd_off as u64,
                op: "copy".into(),
                src_off: Some(cp_off),
                len: cp_size,
                out_off,
            });
        } else if cmd != 0 {
            let len = cmd as usize;
            if pos + len > delta.len() {
                return Err("delta truncated in insert".into());
            }
            let out_off = out.len() as u64;
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            instrs.push(Instr {
                delta_off: cmd_off as u64,
                op: "insert".into(),
                src_off: None,
                len: len as u64,
                out_off,
            });
        } else {
            return Err("reserved delta opcode 0".into());
        }
    }
    if out.len() as u64 != declared_result_size {
        return Err(format!(
            "delta result size mismatch: declared {}, produced {}",
            declared_result_size,
            out.len()
        ));
    }
    Ok(DeltaOutcome { out, instrs, declared_base_size, declared_result_size })
}
