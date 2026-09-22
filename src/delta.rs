//! Git delta 指令解析与应用。记录每条指令在 delta 流中的字节范围，
//! 校验源/目标大小，支持输出上限（预算），失败时不产生任何部分结果。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstrKind {
    Copy { offset: u64, len: u64 },
    Insert { len: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instr {
    /// 指令在 delta 数据流中的字节范围 [start, end)
    pub start: usize,
    pub end: usize,
    pub kind: InstrKind,
}

#[derive(Debug)]
pub enum DeltaError {
    Truncated,
    SrcSizeMismatch { declared: u64, actual: u64 },
    /// 指令产生的输出超过头部声明的目标大小 —— 大小欺骗
    OutputOverflow { declared: u64 },
    /// 指令流耗尽后输出仍不足声明的目标大小 —— 大小欺骗
    SizeMismatch { declared: u64, actual: u64 },
    BadOpcode,
    CopyOutOfRange { offset: u64, len: u64, base: u64 },
    /// 输出超出预算剩余额度
    BudgetExceeded,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated => write!(f, "delta 指令流被截断"),
            DeltaError::SrcSizeMismatch { declared, actual } => {
                write!(f, "delta 源大小声明 {declared} 与 base 实际 {actual} 不符")
            }
            DeltaError::OutputOverflow { declared } => {
                write!(f, "大小欺骗: delta 输出超过声明的目标大小 {declared}")
            }
            DeltaError::SizeMismatch { declared, actual } => {
                write!(f, "大小欺骗: delta 声明目标 {declared} 实际产出 {actual}")
            }
            DeltaError::BadOpcode => write!(f, "非法 delta 操作码 0x00"),
            DeltaError::CopyOutOfRange { offset, len, base } => {
                write!(f, "copy 越界: offset={offset} len={len} base_len={base}")
            }
            DeltaError::BudgetExceeded => write!(f, "输出超出预算额度"),
        }
    }
}

pub struct DeltaResult {
    pub out: Vec<u8>,
    pub instrs: Vec<Instr>,
    pub src_size: u64,
    pub tgt_size: u64,
}

fn read_varint(data: &[u8], p: &mut usize) -> Result<u64, DeltaError> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*p).ok_or(DeltaError::Truncated)?;
        *p += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(DeltaError::Truncated);
        }
    }
    Ok(v)
}

pub fn apply_delta(base: &[u8], delta: &[u8], max_out: u64) -> Result<DeltaResult, DeltaError> {
    let mut p = 0usize;
    let src_size = read_varint(delta, &mut p)?;
    if src_size != base.len() as u64 {
        return Err(DeltaError::SrcSizeMismatch { declared: src_size, actual: base.len() as u64 });
    }
    let tgt_size = read_varint(delta, &mut p)?;
    let mut out: Vec<u8> = Vec::new();
    let mut instrs = Vec::new();
    while p < delta.len() {
        let start = p;
        let cmd = delta[p];
        p += 1;
        if cmd & 0x80 != 0 {
            let mut off = 0u64;
            let mut len = 0u64;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(p).ok_or(DeltaError::Truncated)?;
                    p += 1;
                    off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(p).ok_or(DeltaError::Truncated)?;
                    p += 1;
                    len |= (b as u64) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if off.checked_add(len).map_or(true, |end| end > base.len() as u64) {
                return Err(DeltaError::CopyOutOfRange { offset: off, len, base: base.len() as u64 });
            }
            let new_len = out.len() as u64 + len;
            if new_len > tgt_size {
                return Err(DeltaError::OutputOverflow { declared: tgt_size });
            }
            if new_len > max_out {
                return Err(DeltaError::BudgetExceeded);
            }
            out.extend_from_slice(&base[off as usize..(off + len) as usize]);
            instrs.push(Instr { start, end: p, kind: InstrKind::Copy { offset: off, len } });
        } else if cmd != 0 {
            let len = cmd as usize;
            let bytes = delta.get(p..p + len).ok_or(DeltaError::Truncated)?;
            let new_len = out.len() as u64 + len as u64;
            if new_len > tgt_size {
                return Err(DeltaError::OutputOverflow { declared: tgt_size });
            }
            if new_len > max_out {
                return Err(DeltaError::BudgetExceeded);
            }
            out.extend_from_slice(bytes);
            p += len;
            instrs.push(Instr { start, end: p, kind: InstrKind::Insert { len: len as u64 } });
        } else {
            return Err(DeltaError::BadOpcode);
        }
    }
    if out.len() as u64 != tgt_size {
        return Err(DeltaError::SizeMismatch { declared: tgt_size, actual: out.len() as u64 });
    }
    Ok(DeltaResult { out, instrs, src_size, tgt_size })
}
