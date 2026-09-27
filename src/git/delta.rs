//! Git delta 指令解析与应用（纯实现，不调用系统 git）。
//!
//! 指令格式：
//! - copy: 最高位为 1，紧随最多 4 字节偏移、最多 3 字节长度（长度为 0 时取 65536）；
//! - insert: 高位置 0，低 7 位即字面长度（1..=127）；
//! - 0 为保留非法操作码。
//! 前两个变长整数为 base_size / result_size，且都带 MSB 续位校验。

use serde::{Deserialize, Serialize};

use crate::budget::{BudError, Budget, BudgetUse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    Copy,
    Insert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyInstr {
    pub index: usize,
    pub kind: OpKind,
    /// 指令在 delta 负载中的字节范围（相对 delta 起点）。
    pub op_offset: usize,
    pub op_len: usize,
    /// copy 的源偏移 / insert 的字面起点。
    pub src_offset: usize,
    /// 拷贝或字面长度。
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaRecord {
    /// delta 指令数据长度。
    pub delta_len: usize,
    /// 头部声明的 base / result 大小。
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    /// 实际校验的 base 大小（必须等于声明值，否则为大小欺骗）。
    pub actual_base_size: u64,
    pub instructions: Vec<CopyInstr>,
    /// 记录的指令条数（instructions 可能被截断展示，但逻辑上全部执行）。
    pub instruction_count: usize,
    /// 输入（base）长度 / 输出长度。
    pub input_len: usize,
    pub output_len: usize,
    /// 最终校验：输出长度是否等于声明 result_size。
    pub size_ok: bool,
}

/// delta 执行结果。
pub struct Applied {
    pub output: Vec<u8>,
    pub record: DeltaRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated { at: usize, what: &'static str },
    BadSizeVarint { at: usize },
    BaseSizeMismatch { declared: u64, actual: u64 },
    ReservedZero { at: usize },
    CopyOutOfRange { at: usize, src: usize, len: usize, base_len: usize },
    InsertOutOfRange { at: usize, need: usize, remain: usize },
    SizeMismatch { declared: u64, actual: usize },
    Budget(BudError),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for DeltaError {}

/// 展示时最多保留多少条指令明细（全部指令仍会被执行）。
const RECORD_INSTR_CAP: usize = 200;

fn read_varint(d: &[u8], mut p: usize) -> Result<(u64, usize), DeltaError> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        if p >= d.len() {
            return Err(DeltaError::Truncated { at: p, what: "delta-size" });
        }
        let b = d[p];
        p += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DeltaError::BadSizeVarint { at: p });
        }
    }
    Ok((v, p))
}

/// 应用 delta。`depth` 为该对象所在链深度；`input_weight` 为链输入重量（比例预算用）。
#[allow(clippy::too_many_arguments)]
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    budget: &Budget,
    used: &mut BudgetUse,
    depth: u32,
    input_weight: u64,
) -> Result<Applied, DeltaError> {
    let (base_size, mut p) = read_varint(delta, 0)?;
    let (result_size, p2) = read_varint(delta, p)?;
    p = p2;
    if base_size as usize != base.len() {
        return Err(DeltaError::BaseSizeMismatch {
            declared: base_size,
            actual: base.len() as u64,
        });
    }

    // 预检查：声明的 result_size 是否会触发任何预算（可暂停、可重试）。
    used.check(budget, depth, input_weight, result_size)
        .map_err(DeltaError::Budget)?;

    // 分配以声明大小为上限，但仍逐条核对越界，最终再次比对实际长度。
    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(1 << 28) as usize);
    let mut instrs: Vec<CopyInstr> = Vec::new();
    let mut count = 0usize;

    while p < delta.len() {
        let op_offset = p;
        let op = delta[p];
        p += 1;
        if op & 0x80 != 0 {
            // copy
            let mut cp_off: u32 = 0;
            let mut cp_len: u32 = 0;
            for i in 0..4u8 {
                if op & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated { at: p, what: "copy-offset" });
                    }
                    cp_off |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3u8 {
                if op & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated { at: p, what: "copy-len" });
                    }
                    cp_len |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            if cp_len == 0 {
                cp_len = 0x10000;
            }
            let src = cp_off as usize;
            let len = cp_len as usize;
            if src.checked_add(len).map_or(true, |e)| e > base.len()) {
                return Err(DeltaError::CopyOutOfRange {
                    at: op_offset,
                    src,
                    len,
                    base_len: base.len(),
                });
            }
            if count < RECORD_INSTR_CAP {
                instrs.push(CopyInstr {
                    index: count,
                    kind: OpKind::Copy,
                    op_offset,
                    op_len: p - op_offset,
                    src_offset: src,
                    length: len,
                });
            }
            count += 1;
            out.extend_from_slice(&base[src..src + len]);
        } else if op != 0 {
            // insert literal
            let len = op as usize;
            if p + len > delta.len() {
                return Err(DeltaError::InsertOutOfRange {
                    at: op_offset,
                    need: len,
                    remain: delta.len() - p,
                });
            }
            if count < RECORD_INSTR_CAP {
                instrs.push(CopyInstr {
                    index: count,
                    kind: OpKind::Insert,
                    op_offset,
                    op_len: 1 + len,
                    src_offset: p,
                    length: len,
                });
            }
            count += 1;
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
        } else {
            return Err(DeltaError::ReservedZero { at: op_offset });
        }
        // 运行期保护：即使指令声明合法，输出也不得超过声称的 result_size 太多
        // （result_size 已通过预算与绝对上限检查）。
        if out.len() as u64 > result_size.saturating_add(1024).max(result_size) {
            return Err(DeltaError::SizeMismatch { declared: result_size, actual: out.len() });
        }
    }

    let size_ok = out.len() as u64 == result_size;
    if !size_ok {
        return Err(DeltaError::SizeMismatch { declared: result_size, actual: out.len() });
    }
    used.add(result_size);

    Ok(Applied {
        record: DeltaRecord {
            delta_len: delta.len(),
            declared_base_size: base_size,
            declared_result_size: result_size,
            actual_base_size: base.len() as u64,
            instructions: instrs,
            instruction_count: count,
            input_len: base.len(),
            output_len: out.len(),
            size_ok,
        },
        output: out,
    })
}
