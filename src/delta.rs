//! Git delta 指令解析与应用。
//!
//! 格式：base_size(varint7) + result_size(varint7) + 指令序列：
//! - 最高位 1：copy 指令，低 7 位标记 offset(4 字节) 与 size(3 字节) 是否存在；
//! - 非零且最高位 0：插入其后 N 个字节；
//! - 0：保留指令，出现即非法。

use crate::gitobj::read_varint7;

#[derive(Debug, Clone)]
pub struct DeltaStats {
    pub base_size: u64,
    pub result_size: u64,
    /// 指令区在 delta 程序中的字节范围。
    pub instr_start: usize,
    pub instr_end: usize,
    pub instr_count: usize,
    pub copy_bytes: u64,
    pub insert_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BaseSizeMismatch { declared: u64, actual: usize },
    ResultSizeMismatch { declared: u64, actual: usize },
    CopyOutOfBounds { offset: u64, size: u64, base_len: usize },
    InsertOutOfBounds { need: usize, remain: usize },
    ReservedOp,
}

impl DeltaError {
    pub fn message(&self) -> String {
        match self {
            DeltaError::Truncated => "delta 程序被截断".to_string(),
            DeltaError::BaseSizeMismatch { declared, actual } => format!(
                "delta base 大小欺骗：头部声明 {} 字节，实际 base {} 字节",
                declared, actual
            ),
            DeltaError::ResultSizeMismatch { declared, actual } => format!(
                "delta 输出大小欺骗：头部声明 {} 字节，实际拼出 {} 字节",
                declared, actual
            ),
            DeltaError::CopyOutOfBounds {
                offset,
                size,
                base_len,
            } => format!(
                "copy 越界：base offset={} size={}，base 仅 {} 字节",
                offset, size, base_len
            ),
            DeltaError::InsertOutOfBounds { need, remain } => format!(
                "insert 越界：需要 {} 字节，程序仅余 {} 字节",
                need, remain
            ),
            DeltaError::ReservedOp => "出现保留指令 0x00，delta 非法".to_string(),
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaStats), DeltaError> {
    let (base_size, n1) = read_varint7(delta, 0).ok_or(DeltaError::Truncated)?;
    let (result_size, n2) =
        read_varint7(delta, n1).ok_or(DeltaError::Truncated)?;
    let instr_start = n1 + n2;

    if base_size != base.len() as u64 {
        return Err(DeltaError::BaseSizeMismatch {
            declared: base_size,
            actual: base.len(),
        });
    }

    let mut out = Vec::with_capacity(result_size.min(64 * 1024 * 1024) as usize);
    let mut pos = instr_start;
    let mut stats = DeltaStats {
        base_size,
        result_size,
        instr_start,
        instr_end: 0,
        instr_count: 0,
        copy_bytes: 0,
        insert_bytes: 0,
    };

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        stats.instr_count += 1;
        if cmd & 0x80 != 0 {
            let mut offset = 0u64;
            let mut size = 0u64;
            if cmd & 0x01 != 0 {
                offset |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?);
                pos += 1;
            }
            if cmd & 0x02 != 0 {
                offset |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?) << 8;
                pos += 1;
            }
            if cmd & 0x04 != 0 {
                offset |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?) << 16;
                pos += 1;
            }
            if cmd & 0x08 != 0 {
                offset |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?) << 24;
                pos += 1;
            }
            if cmd & 0x10 != 0 {
                size |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?);
                pos += 1;
            }
            if cmd & 0x20 != 0 {
                size |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?) << 8;
                pos += 1;
            }
            if cmd & 0x40 != 0 {
                size |= u64::from(delta.get(pos).ok_or(DeltaError::Truncated)?) << 16;
                pos += 1;
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or(DeltaError::CopyOutOfBounds {
                offset,
                size,
                base_len: base.len(),
            })?;
            if end > base.len() as u64 {
                return Err(DeltaError::CopyOutOfBounds {
                    offset,
                    size,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[offset as usize..end as usize]);
            stats.copy_bytes += size;
        } else if cmd != 0 {
            let need = cmd as usize;
            if pos + need > delta.len() {
                return Err(DeltaError::InsertOutOfBounds {
                    need,
                    remain: delta.len().saturating_sub(pos),
                });
            }
            out.extend_from_slice(&delta[pos..pos + need]);
            pos += need;
            stats.insert_bytes += need as u64;
        } else {
            return Err(DeltaError::ReservedOp);
        }
    }

    stats.instr_end = pos;
    if out.len() as u64 != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_size,
            actual: out.len(),
        });
    }
    Ok((out, stats))
}
