//! Git delta 指令解析与应用,记录每条指令的范围供取证展示。

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Instr {
    pub kind: String,      // "copy" | "insert"
    pub delta_off: usize,  // 指令在 delta 中的起始偏移
    pub delta_len: usize,  // 指令占用字节数
    pub src_off: usize,    // copy: base 中的偏移; insert: delta 内数据偏移
    pub out_len: usize,    // 输出字节数
}

#[derive(Clone, Debug)]
pub struct DeltaOutcome {
    pub result: Vec<u8>,
    pub instrs: Vec<Instr>,
    pub base_size: u64,
    pub result_size: u64,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut val: u64 = 0;
    loop {
        if *pos >= data.len() {
            return Err("delta header varint 截断".into());
        }
        let b = data[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta varint 过长".into());
        }
    }
    Ok(val)
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let base_size = read_varint(delta, &mut pos)?;
    let result_size = read_varint(delta, &mut pos)?;
    if base_size != base.len() as u64 {
        return Err(format!(
            "delta 声明 base 大小 {} 与实际 {} 不符",
            base_size,
            base.len()
        ));
    }
    let mut result: Vec<u8> = Vec::with_capacity(result_size.min(1 << 24) as usize);
    let mut instrs = Vec::new();
    while pos < delta.len() {
        let instr_off = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 offset 截断".into());
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 size 截断".into());
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
                .ok_or("copy 范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 越界: base[{}..{}] 超出 {}",
                    cp_off,
                    end,
                    base.len()
                ));
            }
            result.extend_from_slice(&base[cp_off as usize..end as usize]);
            instrs.push(Instr {
                kind: "copy".into(),
                delta_off: instr_off,
                delta_len: pos - instr_off,
                src_off: cp_off as usize,
                out_len: cp_size as usize,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令数据截断".into());
            }
            result.extend_from_slice(&delta[pos..pos + n]);
            instrs.push(Instr {
                kind: "insert".into(),
                delta_off: instr_off,
                delta_len: 1 + n,
                src_off: pos,
                out_len: n,
            });
            pos += n;
        } else {
            return Err(format!("delta 指令 0x00 非法(偏移 {})", instr_off));
        }
        if result.len() as u64 > result_size {
            return Err(format!(
                "delta 输出超过声明大小 {}(大小欺骗?)",
                result_size
            ));
        }
    }
    if result.len() as u64 != result_size {
        return Err(format!(
            "delta 结果大小 {} 与声明 {} 不符",
            result.len(),
            result_size
        ));
    }
    Ok(DeltaOutcome {
        result,
        instrs,
        base_size,
        result_size,
    })
}
