//! Git delta 指令应用。
//! delta 头：<src-size LE-varint><dst-size LE-varint>
//! 指令：
//!   高位为 0 且非零：insert，低 7 位为长度，随后拷贝字面量
//!   高位为 1：copy，随后最多 4 字节偏移(LE)+最多 3 字节长度(LE)
//!   0x00：保留（非法）

use super::read_le_varint;

#[derive(Debug, Clone)]
pub struct DeltaStep {
    /// 指令在 delta 数据中的起止字节范围 [start, end)
    pub instr_start: usize,
    pub instr_end: usize,
    pub kind: &'static str,
    pub copy_offset: Option<u64>,
    pub length: u64,
    /// 应用前输出长度
    pub out_before: usize,
    /// 应用后输出长度
    pub out_after: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    BadHeader(String),
    SrcSizeMismatch { declared: u64, actual: usize },
    DstSizeMismatch { declared: u64, actual: usize },
    InvalidZeroOpcode,
    BadCopyParams,
    CopyOutOfRange { offset: u64, length: u64, base_len: usize },
    InsertOutOfRange { start: usize, length: u64, delta_len: usize },
    TrailingData(usize),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::BadHeader(s) => write!(f, "delta 头损坏: {s}"),
            DeltaError::SrcSizeMismatch { declared, actual } => write!(
                f,
                "delta 源大小不匹配：声明 {declared}，base 实际 {actual}"
            ),
            DeltaError::DstSizeMismatch { declared, actual } => write!(
                f,
                "delta 目标大小不匹配：声明 {declared}，重建结果 {actual}"
            ),
            DeltaError::InvalidZeroOpcode => write!(f, "非法指令 0x00"),
            DeltaError::BadCopyParams => write!(f, "copy 指令参数损坏"),
            DeltaError::CopyOutOfRange {
                offset,
                length,
                base_len,
            } => write!(
                f,
                "copy 越界：offset={offset} length={length}，base 长度 {base_len}"
            ),
            DeltaError::InsertOutOfRange {
                start,
                length,
                delta_len,
            } => write!(
                f,
                "insert 字面量越界：@{start} length={length}，delta 长度 {delta_len}"
            ),
            DeltaError::TrailingData(n) => write!(f, "delta 末尾有 {n} 字节多余数据"),
        }
    }
}

pub struct DeltaResult {
    pub data: Vec<u8>,
    pub steps: Vec<DeltaStep>,
    pub declared_src: u64,
    pub declared_dst: u64,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaResult, DeltaError> {
    let (declared_src, p1) = read_le_varint(delta, 0)
        .ok_or_else(|| DeltaError::BadHeader("源长度".into()))?;
    let (declared_dst, mut p) = read_le_varint(delta, p1)
        .ok_or_else(|| DeltaError::BadHeader("目标长度".into()))?;

    if declared_src != base.len() as u64 {
        return Err(DeltaError::SrcSizeMismatch {
            declared: declared_src,
            actual: base.len(),
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(declared_dst as usize);
    let mut steps: Vec<DeltaStep> = Vec::new();

    while p < delta.len() {
        let opcode = delta[p];
        let instr_start = p;
        p += 1;
        let out_before = out.len();

        if opcode & 0x80 != 0 {
            // copy
            let mut offset: u32 = 0;
            let mut length: u32 = 0;
            for i in 0..4u8 {
                if opcode & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::BadCopyParams);
                    }
                    offset |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3u8 {
                if opcode & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::BadCopyParams);
                    }
                    length |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            let off = offset as usize;
            let len = length as usize;
            if off.checked_add(len).map_or(true, |e| e > base.len()) {
                return Err(DeltaError::CopyOutOfRange {
                    offset: offset as u64,
                    length: length as u64,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[off..off + len]);
            steps.push(DeltaStep {
                instr_start,
                instr_end: p,
                kind: "copy",
                copy_offset: Some(offset as u64),
                length: length as u64,
                out_before,
                out_after: out.len(),
            });
        } else if opcode != 0 {
            // insert
            let len = opcode as usize;
            if p.checked_add(len).map_or(true, |e| e > delta.len()) {
                return Err(DeltaError::InsertOutOfRange {
                    start: p,
                    length: len as u64,
                    delta_len: delta.len(),
                });
            }
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
            steps.push(DeltaStep {
                instr_start,
                instr_end: p,
                kind: "insert",
                copy_offset: None,
                length: len as u64,
                out_before,
                out_after: out.len(),
            });
        } else {
            return Err(DeltaError::InvalidZeroOpcode);
        }
    }

    if out.len() as u64 != declared_dst {
        return Err(DeltaError::DstSizeMismatch {
            declared: declared_dst,
            actual: out.len(),
        });
    }

    Ok(DeltaResult {
        data: out,
        steps,
        declared_src,
        declared_dst,
    })
}
