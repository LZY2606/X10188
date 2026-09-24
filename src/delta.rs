/// Git delta 指令应用。记录指令范围与输入输出长度, 供取证展示。
#[derive(Clone, Debug, serde::Serialize)]
pub struct DeltaOutcome {
    pub out: Vec<u8>,
    pub instr_start: usize,
    pub instr_end: usize,
    pub instr_count: usize,
    pub src_size: u64,
    pub tgt_size: u64,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos).ok_or("delta varint 截断")?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        if shift > 63 {
            return Err("delta varint 过长".into());
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let src_size = read_varint(delta, &mut pos)?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小不匹配: 声明 {src_size}, base 实际 {}",
            base.len()
        ));
    }
    let tgt_size = read_varint(delta, &mut pos)?;
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(tgt_size.min(1 << 24) as usize);
    let mut instr_count = 0usize;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        instr_count += 1;
        if cmd & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令截断")?;
                    pos += 1;
                    off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令截断")?;
                    pos += 1;
                    len |= (b as u64) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if off.checked_add(len).map_or(true, |end| end > base.len() as u64) {
                return Err(format!(
                    "copy 指令越界: offset={off} len={len}, base 仅 {} 字节",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..(off + len) as usize]);
        } else if cmd != 0 {
            let end = pos + cmd as usize;
            if end > delta.len() {
                return Err("insert 指令截断".into());
            }
            out.extend_from_slice(&delta[pos..end]);
            pos = end;
        } else {
            return Err("非法的 0 值指令".into());
        }
        if out.len() as u64 > tgt_size {
            return Err(format!(
                "delta 输出超过声明目标大小 {tgt_size}(已产出 {})",
                out.len()
            ));
        }
    }
    if out.len() as u64 != tgt_size {
        return Err(format!(
            "delta 目标大小不匹配: 声明 {tgt_size}, 实际产出 {}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        out,
        instr_start,
        instr_end: delta.len(),
        instr_count,
        src_size,
        tgt_size,
    })
}
