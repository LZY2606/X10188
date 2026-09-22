//! Git delta 指令应用与取证记录。

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    /// 指令在 delta 缓冲区中的字节范围 [start, end)
    pub range: (usize, usize),
    pub kind: InstrKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstrKind {
    Copy { offset: u64, size: u64 },
    Insert { len: u8 },
}

#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    pub result: Vec<u8>,
    pub src_size: u64,
    pub dst_size: u64,
    /// 指令区在 delta 缓冲区中的范围
    pub instr_range: (usize, usize),
    pub instructions: Vec<DeltaInstruction>,
    pub verified: bool,
    pub notes: Vec<String>,
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or("delta varint 越界")?;
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        if shift > 63 {
            return Err("delta varint 过长".into());
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let src_size = read_varint(delta, &mut pos)?;
    let dst_size = read_varint(delta, &mut pos)?;
    let mut notes = Vec::new();
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小不符：声明 {src_size}，base 实际 {}",
            base.len()
        ));
    }
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(dst_size as usize);
    let mut instructions = Vec::new();

    while pos < delta.len() {
        let start = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 offset 越界")?;
                    pos += 1;
                    offset |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 size 越界")?;
                    pos += 1;
                    size |= (b as u64) << (8 * i);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or("copy 指令范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 指令越界：[{offset}, {end}) 超出 base 长度 {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end as usize]);
            instructions.push(DeltaInstruction {
                range: (start, pos),
                kind: InstrKind::Copy { offset, size },
            });
        } else if cmd != 0 {
            let len = cmd;
            if pos + len as usize > delta.len() {
                return Err("insert 指令数据越界".into());
            }
            out.extend_from_slice(&delta[pos..pos + len as usize]);
            pos += len as usize;
            instructions.push(DeltaInstruction {
                range: (start, pos),
                kind: InstrKind::Insert { len },
            });
        } else {
            return Err("delta 出现保留指令 0x00".into());
        }
        if out.len() as u64 > dst_size {
            return Err(format!(
                "大小欺骗：delta 输出已超过声明目标大小 {dst_size}"
            ));
        }
    }

    let verified = out.len() as u64 == dst_size;
    if !verified {
        notes.push(format!(
            "输出大小不符：声明 {dst_size}，实际 {}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        result: out,
        src_size,
        dst_size,
        instr_range: (instr_start, delta.len()),
        instructions,
        verified,
        notes,
    })
}
