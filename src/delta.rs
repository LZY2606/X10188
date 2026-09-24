//! Git delta 应用：解析指令流，记录指令范围与输入输出长度。

use crate::gitutil::parse_delta_varint;

#[derive(Debug, Clone)]
pub struct DeltaStep {
    pub base_desc: String,
    pub instr_offset: u64, // 指令流在 delta 数据中的起始偏移
    pub instr_len: u64,    // 指令流长度
    pub in_len: u64,       // base 输入长度
    pub out_len: u64,      // 输出长度
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug)]
pub struct DeltaInfo {
    pub base_size: u64,
    pub target_size: u64,
    pub instr_offset: usize,
}

pub fn parse_delta_header(data: &[u8]) -> Result<DeltaInfo, String> {
    let (base_size, u1) = parse_delta_varint(data, 0).ok_or("delta 头 base size 截断")?;
    let (target_size, u2) = parse_delta_varint(data, u1).ok_or("delta 头 target size 截断")?;
    Ok(DeltaInfo {
        base_size,
        target_size,
        instr_offset: u1 + u2,
    })
}

/// 应用 delta，返回输出与步骤记录。输出长度必须与 delta 头声明的 target size 一致。
pub fn apply_delta(base: &[u8], delta: &[u8], base_desc: &str) -> Result<(Vec<u8>, DeltaStep), String> {
    let info = parse_delta_header(delta)?;
    if info.base_size != base.len() as u64 {
        return Err(format!(
            "delta 声明 base 大小 {}，实际 {}",
            info.base_size,
            base.len()
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(info.target_size as usize);
    let mut pos = info.instr_offset;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 offset 截断")?;
                    pos += 1;
                    cp_off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 size 截断")?;
                    pos += 1;
                    cp_size |= (b as u64) << (8 * i);
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or("copy 指令范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 指令越界: base[{}..{}] 超出 {}",
                    cp_off,
                    end,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
        } else if cmd != 0 {
            // insert literal
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令数据截断".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("保留指令 0x00".to_string());
        }
        if out.len() as u64 > info.target_size {
            return Err(format!(
                "delta 输出超过声明目标大小 {}",
                info.target_size
            ));
        }
    }
    let ok = out.len() as u64 == info.target_size;
    if !ok {
        return Err(format!(
            "delta 输出 {} 字节，与声明目标 {} 不符",
            out.len(),
            info.target_size
        ));
    }
    Ok((
        out,
        DeltaStep {
            base_desc: base_desc.to_string(),
            instr_offset: info.instr_offset as u64,
            instr_len: (delta.len() - info.instr_offset) as u64,
            in_len: base.len() as u64,
            out_len: out.len() as u64,
            ok: true,
            detail: format!(
                "target={} instrs={}B",
                info.target_size,
                delta.len() - info.instr_offset
            ),
        },
    ))
}
