//! Git delta 指令解析与应用。

use crate::gitobj::parse_size_varint;

#[derive(Debug)]
pub struct DeltaInfo {
    pub base_size: u64,
    pub target_size: u64,
    /// 指令流在 delta 数据中的起始偏移
    pub instr_offset: usize,
    /// 指令流长度（字节）
    pub instr_len: usize,
}

#[derive(Debug)]
pub enum DeltaError {
    BadHeader(String),
    BadInstruction(String),
    SizeMismatch { declared: u64, actual: u64 },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::BadHeader(m) => write!(f, "delta 头错误: {m}"),
            DeltaError::BadInstruction(m) => write!(f, "delta 指令错误: {m}"),
            DeltaError::SizeMismatch { declared, actual } => {
                write!(f, "delta 目标大小欺骗: 声明 {declared} 实际 {actual}")
            }
        }
    }
}

pub fn parse_delta_header(delta: &[u8]) -> Result<DeltaInfo, DeltaError> {
    let mut pos = 0usize;
    let base_size = parse_size_varint(delta, &mut pos)
        .ok_or_else(|| DeltaError::BadHeader("base size varint 损坏".into()))?;
    let target_size = parse_size_varint(delta, &mut pos)
        .ok_or_else(|| DeltaError::BadHeader("target size varint 损坏".into()))?;
    Ok(DeltaInfo {
        base_size,
        target_size,
        instr_offset: pos,
        instr_len: delta.len() - pos,
    })
}

/// 应用 delta。返回 (输出, 指令流信息)。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInfo), DeltaError> {
    let info = parse_delta_header(delta)?;
    if info.base_size != base.len() as u64 {
        return Err(DeltaError::BadHeader(format!(
            "base 大小不匹配: delta 声明 {} 实际 {}",
            info.base_size,
            base.len()
        )));
    }
    let mut out = Vec::with_capacity(info.target_size as usize);
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
                    if pos >= delta.len() {
                        return Err(DeltaError::BadInstruction("copy offset 截断".into()));
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::BadInstruction("copy size 截断".into()));
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
                .ok_or_else(|| DeltaError::BadInstruction("copy 范围溢出".into()))?;
            if end > base.len() as u64 {
                return Err(DeltaError::BadInstruction(format!(
                    "copy 越界: [{cp_off}, {end}) 超出 base 长度 {}",
                    base.len()
                )));
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
        } else if cmd != 0 {
            // insert literal
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err(DeltaError::BadInstruction("insert 数据截断".into()));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err(DeltaError::BadInstruction("保留指令 0x00".into()));
        }
    }
    if out.len() as u64 != info.target_size {
        return Err(DeltaError::SizeMismatch {
            declared: info.target_size,
            actual: out.len() as u64,
        });
    }
    Ok((out, info))
}
