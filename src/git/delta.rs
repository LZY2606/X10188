use super::types::DeltaError;

/// Git delta 使用的小端变长整数。
pub fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() || shift >= 64 {
            return None;
        }
        let b = data[pos];
        pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((value, pos))
}

#[derive(Debug, Clone)]
pub struct DeltaStep {
    /// 指令在 delta 数据中的字节范围 [start,end)。
    pub start: usize,
    pub end: usize,
    pub op: String,
    /// copy 指令：基对象偏移；insert 指令：None。
    pub base_offset: Option<u64>,
    pub length: u64,
    /// 应用该指令前的输出长度。
    pub out_before: u64,
    /// 应用该指令后的输出长度。
    pub out_after: u64,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub result: Vec<u8>,
    pub steps: Vec<DeltaStep>,
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    /// delta 头部之后、第一条指令的字节偏移。
    pub instructions_start: usize,
}

/// 把一条 delta 应用到 base 上，同时记录每条指令的原始字节范围、
/// 基偏移、长度与逐步输出长度。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, DeltaError> {
    let (base_size, mut p) = read_varint(delta, 0).ok_or(DeltaError::Truncated)?;
    let (result_size, p2) = read_varint(delta, p).ok_or(DeltaError::Truncated)?;
    p = p2;
    let instructions_start = p;

    if base_size as usize != base.len() {
        return Err(DeltaError::BaseSizeMismatch { declared: base_size, actual: base.len() });
    }

    let mut result: Vec<u8> = Vec::with_capacity(result_size.min(256 * 1024 * 1024) as usize);
    let mut steps: Vec<DeltaStep> = Vec::new();

    while p < delta.len() {
        let op_start = p;
        let opcode = delta[p];
        p += 1;
        if opcode & 0x80 != 0 {
            // copy from base
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for i in 0..4u32 {
                if opcode & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    offset |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3u32 {
                if opcode & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    size |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let start = offset as u64;
            let len = size as u64;
            if start.checked_add(len).map(|e| e as usize > base.len()).unwrap_or(true) {
                return Err(DeltaError::CopyOutOfRange {
                    offset: start,
                    size: len,
                    base_len: base.len(),
                });
            }
            let out_before = result.len() as u64;
            result.extend_from_slice(&base[start as usize..start as usize + len as usize]);
            steps.push(DeltaStep {
                start: op_start,
                end: p,
                op: "copy".into(),
                base_offset: Some(start),
                length: len,
                out_before,
                out_after: result.len() as u64,
            });
        } else if opcode > 0 {
            // insert literal
            let len = opcode as usize;
            if p + len > delta.len() {
                return Err(DeltaError::InsertTooLong {
                    at: op_start,
                    declared: len as u64,
                });
            }
            let out_before = result.len() as u64;
            result.extend_from_slice(&delta[p..p + len]);
            p += len;
            steps.push(DeltaStep {
                start: op_start,
                end: p,
                op: "insert".into(),
                base_offset: None,
                length: len as u64,
                out_before,
                out_after: result.len() as u64,
            });
        } else {
            return Err(DeltaError::BadOpcode(0));
        }
    }

    if result.len() as u64 != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_size,
            actual: result.len(),
        });
    }

    Ok(AppliedDelta {
        result,
        steps,
        declared_base_size: base_size,
        declared_result_size: result_size,
        instructions_start,
    })
}
