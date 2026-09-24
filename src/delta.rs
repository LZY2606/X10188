use crate::model::InstrSummary;

pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub instructions: Vec<InstrSummary>,
    pub declared_src: u64,
    pub declared_dst: u64,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("delta 头部 varint 截断".to_string());
        }
        let b = data[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta varint 溢出".to_string());
        }
    }
    Ok(v)
}

/// 应用 Git delta，记录每条指令的字节范围与输入输出长度。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let declared_src = read_varint(delta, &mut pos)?;
    let declared_dst = read_varint(delta, &mut pos)?;
    if declared_src != base.len() as u64 {
        return Err(format!(
            "base 大小不符: delta 声明 {}，实际 {}",
            declared_src,
            base.len()
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity((declared_dst as usize).min(1 << 26));
    let mut instructions = Vec::new();
    while pos < delta.len() {
        let start = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令截断".to_string());
                    }
                    off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令截断".to_string());
                    }
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off.checked_add(size).ok_or("copy 范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 越界: [{}..{}) 超出 base 长度 {}",
                    off,
                    end,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..end as usize]);
            instructions.push(InstrSummary {
                range: (start, pos),
                kind: "copy".to_string(),
                src_off: Some(off),
                len: size,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令截断".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            instructions.push(InstrSummary {
                range: (start, pos),
                kind: "insert".to_string(),
                src_off: None,
                len: n as u64,
            });
        } else {
            return Err("delta 含保留操作码 0".to_string());
        }
    }
    if out.len() as u64 != declared_dst {
        return Err(format!(
            "大小欺骗: delta 声明输出 {} 字节，实际还原 {} 字节",
            declared_dst,
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        output: out,
        instructions,
        declared_src,
        declared_dst,
    })
}
