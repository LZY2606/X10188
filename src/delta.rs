//! Git delta 指令解析与应用 (copy/insert), 记录每条指令在 delta 流中的范围与输出范围。

#[derive(Clone, Debug)]
pub struct DeltaInstr {
    pub op: String,
    pub instr_off: usize,
    pub instr_len: usize,
    pub src_off: usize,
    pub out_off: usize,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct DeltaOutcome {
    pub out: Vec<u8>,
    pub instrs: Vec<DeltaInstr>,
    pub src_size: u64,
    pub tgt_size: u64,
}

pub fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos).ok_or("delta varint EOF")?;
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        if shift > 63 {
            return Err("delta varint overflow".to_string());
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let src_size = read_varint(delta, &mut pos)?;
    let tgt_size = read_varint(delta, &mut pos)?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "base size mismatch: delta expects {src_size}, base is {}",
            base.len()
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(tgt_size.min(1 << 26) as usize);
    let mut instrs = Vec::new();

    while pos < delta.len() {
        let instr_off = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut copy_off: u64 = 0;
            let mut copy_size: u64 = 0;
            for i in 0..4u32 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy instruction offset EOF")?;
                    pos += 1;
                    copy_off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3u32 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy instruction size EOF")?;
                    pos += 1;
                    copy_size |= (b as u64) << (8 * i);
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let off = copy_off as usize;
            let len = copy_size as usize;
            match off.checked_add(len) {
                Some(end) if end <= base.len() => {}
                _ => {
                    return Err(format!(
                        "copy out of range: base[{}..{}] but base len is {}",
                        off,
                        off + len,
                        base.len()
                    ))
                }
            }
            let out_off = out.len();
            out.extend_from_slice(&base[off..off + len]);
            instrs.push(DeltaInstr {
                op: "copy".to_string(),
                instr_off,
                instr_len: pos - instr_off,
                src_off: off,
                out_off,
                size: len,
            });
        } else if cmd != 0 {
            let take = cmd as usize;
            if pos + take > delta.len() {
                return Err("insert instruction overruns delta stream".to_string());
            }
            let out_off = out.len();
            out.extend_from_slice(&delta[pos..pos + take]);
            instrs.push(DeltaInstr {
                op: "insert".to_string(),
                instr_off,
                instr_len: 1 + take,
                src_off: pos,
                out_off,
                size: take,
            });
            pos += take;
        } else {
            return Err("delta opcode 0 is reserved".to_string());
        }
    }

    if out.len() as u64 != tgt_size {
        return Err(format!(
            "target size mismatch: header says {tgt_size}, produced {}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        out,
        instrs,
        src_size,
        tgt_size,
    })
}
