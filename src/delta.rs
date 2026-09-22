use crate::error::PError;
use crate::types::{DeltaStepRec, OpRange};

/// 解码 delta 变长整数（little-endian base-128），返回 (值, 占用字节)。
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, PError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(PError::Delta("变长整数读取越界".to_string()));
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or_else(|| PError::Delta("变长整数溢出".to_string()))?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(PError::Delta("变长整数过长".to_string()));
        }
    }
    Ok(result)
}

/// 一次 delta 应用的结果。
pub struct Applied {
    pub out: Vec<u8>,
    pub declared_base_len: u64,
    pub declared_result_len: u64,
    pub ops: Vec<OpRange>,
    pub op_count: usize,
}

/// 将 delta 指令应用到 base，产出目标对象，并记录每条指令在 delta 数据中的区间。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Applied, PError> {
    let mut pos = 0usize;
    let declared_base_len = read_varint(delta, &mut pos)?;
    let declared_result_len = read_varint(delta, &mut pos)?;

    if declared_base_len != base.len() as u64 {
        return Err(PError::Delta(format!(
            "delta 声明 base 长度 {}，实际 base 长度 {}",
            declared_base_len,
            base.len()
        )));
    }

    let mut out: Vec<u8> = Vec::with_capacity(declared_result_len as usize);
    let mut ops: Vec<OpRange> = Vec::new();

    while pos < delta.len() {
        let op_start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            // copy from base
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for i in 0..4u8 {
                if opcode & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(PError::Delta("copy 偏移读取越界".to_string()));
                    }
                    offset |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3u8 {
                if opcode & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err(PError::Delta("copy 长度读取越界".to_string()));
                    }
                    size |= (delta[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let start = offset as usize;
            let end = start
                .checked_add(size as usize)
                .ok_or_else(|| PError::Delta("copy 区间整数溢出".to_string()))?;
            if end > base.len() {
                return Err(PError::Delta(format!(
                    "copy 越界：base[{}..{}]，base 长度 {}",
                    start,
                    end,
                    base.len()
                )));
            }
            out.extend_from_slice(&base[start..end]);
            ops.push(OpRange {
                start: op_start,
                end: pos,
                op: "copy".to_string(),
            });
        } else if opcode > 0 {
            // insert literal
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(PError::Delta(format!(
                    "insert 越界：需要 {} 字节，剩余 {}",
                    len,
                    delta.len() - pos
                )));
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            ops.push(OpRange {
                start: op_start,
                end: pos,
                op: "insert".to_string(),
            });
        } else {
            // opcode == 0 保留
            return Err(PError::Delta("遇到保留 opcode 0".to_string()));
        }
    }

    if out.len() as u64 != declared_result_len {
        return Err(PError::Delta(format!(
            "输出长度 {} 与声明目标长度 {} 不符",
            out.len(),
            declared_result_len
        )));
    }

    let op_count = ops.len();
    Ok(Applied {
        out,
        declared_base_len,
        declared_result_len,
        ops,
        op_count,
    })
}

/// 组装一步 delta 的取证记录。
pub fn build_step(
    base_cand: i64,
    base_oid: Option<crate::oid::Oid>,
    base: &[u8],
    applied: &Applied,
) -> DeltaStepRec {
    let copies = applied.ops.iter().filter(|o| o.op == "copy").count();
    let inserts = applied.ops.len() - copies;
    DeltaStepRec {
        base_cand,
        base_oid,
        declared_base_len: applied.declared_base_len,
        declared_result_len: applied.declared_result_len,
        input_len: base.len() as u64,
        output_len: applied.out.len() as u64,
        op_count: applied.op_count,
        ops: applied.ops.clone(),
        summary: format!("{} copy + {} insert", copies, inserts),
        input_matches_declared: applied.declared_base_len == base.len() as u64,
        output_matches_declared: applied.declared_result_len == applied.out.len() as u64,
    }
}
