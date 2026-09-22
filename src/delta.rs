//! Git delta 指令的解析与应用（copy/insert 两种 opcode）。
//!
//! 每个 delta 步骤都会记录：
//!   * base 的标识（由调用方填充）
//!   * 指令在 delta 字节流中的原始范围 [op_start, op_end)
//!   * 指令类型、参数
//!   * 应用前/后的输出长度
//!   * 校验结果（边界是否合法）
//!
//! 应用过程中通过 `BudgetGuard` 检查展开预算；超预算返回
//! `DeltaError::BudgetExceeded`（可重试，调用方不得把半成品当完整对象）。

use serde::Serialize;

use crate::types::Evidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Copy,
    Insert,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaStep {
    pub seq: i64,
    pub kind: StepKind,
    /// opcode 在 delta 字节流中的起点（相对 delta 起点）。
    pub op_start: u64,
    /// 该指令整体（opcode + 参数 + insert 数据）占用的字节数。
    pub op_len: u64,
    /// copy：base 内偏移；insert：0。
    pub src_offset: u64,
    /// copy/insert 的数据长度。
    pub length: u64,
    /// 应用前输出长度。
    pub out_before: u64,
    /// 应用后输出长度。
    pub out_after: u64,
    pub ok: bool,
    pub note: Option<String>,
}

/// 先于指令的两个 varint：source/target size。
#[derive(Debug, Clone, Serialize)]
pub struct DeltaHeader {
    pub source_size: u64,
    pub target_size: u64,
    pub header_len: usize,
}

#[derive(Debug)]
pub enum DeltaError {
    /// delta 头部声明的 source size 与实际 base 长度不符（大小欺骗的一种）。
    SourceSizeMismatch { declared: u64, actual: usize },
    /// delta 头部声明的 target size 与实际产出不符。
    TargetSizeMismatch { declared: u64, actual: usize },
    BadInstruction(String, usize),
    /// copy 越过 base 边界（环/坏 delta 常见）。
    CopyOutOfRange { offset: u64, length: u64, base_len: usize, op_start: usize },
    /// 预算不足，返回时调用方应保留中间状态以便补预算后重试。
    BudgetExceeded { at_op: usize, produced: usize, reason: String },
}

impl DeltaError {
    pub fn code(&self) -> &'static str {
        match self {
            DeltaError::SourceSizeMismatch { .. } => "delta_source_size_mismatch",
            DeltaError::TargetSizeMismatch { .. } => "delta_target_size_mismatch",
            DeltaError::BadInstruction(_, _) => "bad_delta_instruction",
            DeltaError::CopyOutOfRange { .. } => "delta_copy_out_of_range",
            DeltaError::BudgetExceeded { .. } => "budget_exceeded",
        }
    }
    pub fn message(&self) -> String {
        match self {
            DeltaError::SourceSizeMismatch { declared, actual } => {
                format!("delta 头声明 source size {declared}，实际 base 长度 {actual}")
            }
            DeltaError::TargetSizeMismatch { declared, actual } => {
                format!("delta 头声明 target size {declared}，实际产出 {actual}")
            }
            DeltaError::BadInstruction(m, p) => format!("delta 指令非法（偏移 {p}）：{m}"),
            DeltaError::CopyOutOfRange { offset, length, base_len, .. } => format!(
                "copy 指令越界：base_offset={offset} length={length} 但 base 长度 {base_len}"
            ),
            DeltaError::BudgetExceeded { reason, .. } => format!("展开预算超限：{reason}"),
        }
    }
    pub fn evidence(&self) -> Evidence {
        let (off, len) = match self {
            DeltaError::BadInstruction(_, p) => (Some(*p as u64), None),
            DeltaError::CopyOutOfRange { op_start, .. } => (Some(*op_start as u64), None),
            DeltaError::BudgetExceeded { at_op, .. } => (Some(*at_op as u64), None),
            _ => (None, None),
        };
        Evidence::new(self.code(), self.message(), off, len)
    }
}

/// 读取 little-endian-base-7 varint（delta 头的 source/target size）。
pub fn read_varint(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut val = 0u64;
    let mut shift = 0u32;
    let start = pos;
    loop {
        if pos >= buf.len() {
            return Err("varint 被截断".into());
        }
        let b = buf[pos];
        pos += 1;
        if shift < 64 {
            val |= ((b & 0x7f) as u64) << shift;
        }
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok((val, pos - start))
}

pub fn read_delta_header(buf: &[u8]) -> Result<DeltaHeader, DeltaError> {
    let (source_size, n1) = read_varint(buf, 0).map_err(|e| DeltaError::BadInstruction(e, 0))?;
    let (target_size, n2) = read_varint(buf, n1).map_err(|e| DeltaError::BadInstruction(e, n1))?;
    Ok(DeltaHeader { source_size, target_size, header_len: n1 + n2 })
}

/// 预算守卫：在真正产出字节前检查。
/// `note` 给出触发的具体维度（深度/总量/单对象比例）。
pub trait BudgetGuard {
    /// 当前对象目标输出声明大小；要求在应用前做预检查。
    fn check_target(&self, target_size: u64, depth: u32) -> Result<(), String>;
    /// 已经产出 produced，准备再追加 add 时调用。
    fn charge(&mut self, add: u64, produced: usize, depth: u32, at_op: usize) -> Result<(), DeltaError>;
}

pub struct NoBudget;
impl BudgetGuard for NoBudget {
    fn check_target(&self, _t: u64, _d: u32) -> Result<(), String> {
        Ok(())
    }
    fn charge(&mut self, _a: u64, _p: usize, _d: u32, _o: usize) -> Result<(), DeltaError> {
        Ok(())
    }
}

pub struct ApplyResult {
    pub output: Vec<u8>,
    pub header: DeltaHeader,
    pub steps: Vec<DeltaStep>,
}

/// 解析+应用整条 delta。即使最终失败，也会返回已经记录的步骤（部分输出不对外）。
pub fn apply_delta<G: BudgetGuard>(
    base: &[u8],
    delta: &[u8],
    depth: u32,
    guard: &mut G,
) -> Result<ApplyResult, (DeltaError, Vec<DeltaStep>, DeltaHeader)> {
    let header = match read_delta_header(delta) {
        Ok(h) => h,
        Err(e) => return Err((e, Vec::new(), DeltaHeader { source_size: 0, target_size: 0, header_len: 0 })),
    };
    if header.source_size as usize != base.len() {
        return Err((
            DeltaError::SourceSizeMismatch { declared: header.source_size, actual: base.len() },
            Vec::new(),
            header,
        ));
    }
    if let Err(reason) = guard.check_target(header.target_size, depth) {
        return Err((
            DeltaError::BudgetExceeded { at_op: header.header_len, produced: 0, reason },
            Vec::new(),
            header,
        ));
    }

    let mut steps = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(header.target_size.min(64 * 1024 * 1024) as usize);
    let mut pos = header.header_len;
    let mut seq = 0i64;

    while pos < delta.len() {
        let op_start = pos;
        let op = delta[pos];
        pos += 1;
        let before = out.len();

        if op & 0x80 != 0 {
            // copy from base
            let mut offset = 0u64;
            let mut length = 0u64;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err((DeltaError::BadInstruction("copy offset 参数被截断".into(), op_start), steps, header));
                    }
                    offset |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err((DeltaError::BadInstruction("copy size 参数被截断".into(), op_start), steps, header));
                    }
                    length |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            let op_len = (pos - op_start) as u64;

            if offset.checked_add(length).map(|end| end as usize > base.len()).unwrap_or(true) {
                let step = DeltaStep {
                    seq,
                    kind: StepKind::Copy,
                    op_start: op_start as u64,
                    op_len,
                    src_offset: offset,
                    length,
                    out_before: before as u64,
                    out_after: before as u64,
                    ok: false,
                    note: Some("copy 越过 base 边界".into()),
                };
                steps.push(step);
                return Err((
                    DeltaError::CopyOutOfRange { offset, length, base_len: base.len(), op_start },
                    steps,
                    header,
                ));
            }
            if let Err(e) = guard.charge(length, before, depth, op_start) {
                steps.push(DeltaStep {
                    seq,
                    kind: StepKind::Copy,
                    op_start: op_start as u64,
                    op_len,
                    src_offset: offset,
                    length,
                    out_before: before as u64,
                    out_after: before as u64,
                    ok: false,
                    note: Some("预算超限".into()),
                });
                return Err((e, steps, header));
            }
            let s = offset as usize;
            let l = length as usize;
            out.extend_from_slice(&base[s..s + l]);
            steps.push(DeltaStep {
                seq,
                kind: StepKind::Copy,
                op_start: op_start as u64,
                op_len,
                src_offset: offset,
                length,
                out_before: before as u64,
                out_after: out.len() as u64,
                ok: true,
                note: None,
            });
        } else if op != 0 {
            // insert literal
            let length = op as u64;
            if pos + length as usize > delta.len() {
                steps.push(DeltaStep {
                    seq,
                    kind: StepKind::Insert,
                    op_start: op_start as u64,
                    op_len: 1 + length,
                    src_offset: 0,
                    length,
                    out_before: before as u64,
                    out_after: before as u64,
                    ok: false,
                    note: Some("insert 数据超出 delta 长度".into()),
                });
                return Err((
                    DeltaError::BadInstruction("insert 数据超出 delta 长度".into(), op_start),
                    steps,
                    header,
                ));
            }
            if let Err(e) = guard.charge(length, before, depth, op_start) {
                steps.push(DeltaStep {
                    seq,
                    kind: StepKind::Insert,
                    op_start: op_start as u64,
                    op_len: 1 + length,
                    src_offset: 0,
                    length,
                    out_before: before as u64,
                    out_after: before as u64,
                    ok: false,
                    note: Some("预算超限".into()),
                });
                return Err((e, steps, header));
            }
            out.extend_from_slice(&delta[pos..pos + length as usize]);
            let op_len = (1 + length as usize) as u64;
            pos += length as usize;
            steps.push(DeltaStep {
                seq,
                kind: StepKind::Insert,
                op_start: op_start as u64,
                op_len,
                src_offset: 0,
                length,
                out_before: before as u64,
                out_after: out.len() as u64,
                ok: true,
                note: None,
            });
        } else {
            return Err((
                DeltaError::BadInstruction("opcode 0x00 是保留值".into(), op_start),
                steps,
                header,
            ));
        }
        seq += 1;
    }

    if out.len() as u64 != header.target_size {
        return Err((
            DeltaError::TargetSizeMismatch { declared: header.target_size, actual: out.len() },
            steps,
            header,
        ));
    }

    Ok(ApplyResult { output: out, header, steps })
}
