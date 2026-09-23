use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum DeltaError {
    Truncated,
    Invalid(&'static str),
    BaseSizeMismatch { declared: u64, actual: u64 },
    ResultSizeMismatch { declared: u64, actual: u64 },
    CopyOutOfRange { offset: u64, len: u64, base_len: u64 },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated => write!(f, "delta 指令被截断"),
            DeltaError::Invalid(m) => write!(f, "delta 指令无效: {m}"),
            DeltaError::BaseSizeMismatch { declared, actual } => {
                write!(f, "base 大小欺骗: delta 声明 {declared}, 实际 base {actual}")
            }
            DeltaError::ResultSizeMismatch { declared, actual } => {
                write!(f, "结果大小欺骗: delta 声明 {declared}, 实际输出 {actual}")
            }
            DeltaError::CopyOutOfRange { offset, len, base_len } => write!(
                f,
                "copy 越界: offset={offset} len={len} base_len={base_len}"
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum DeltaOp {
    Copy { offset: u64, len: u64 },
    Insert { data: Vec<u8> },
}

impl DeltaOp {
    pub fn output_len(&self) -> u64 {
        match self {
            DeltaOp::Copy { len, .. } => *len,
            DeltaOp::Insert { data } => data.len() as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DeltaProgram {
    pub base_size: u64,
    pub result_size: u64,
    pub ops: Vec<DeltaOp>,
    /// 每条指令在 delta 数据中的字节范围 [start, end)
    pub op_spans: Vec<(usize, usize)>,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut v: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated);
        }
        let b = data[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(DeltaError::Invalid("varint 过长"));
        }
    }
    Ok(v)
}

/// 解析 git delta 指令序列（ofs-delta / ref-delta 同构）
pub fn parse_delta(data: &[u8]) -> Result<DeltaProgram, DeltaError> {
    let mut pos = 0;
    let base_size = read_varint(data, &mut pos)?;
    let result_size = read_varint(data, &mut pos)?;
    let mut ops = Vec::new();
    let mut op_spans = Vec::new();

    while pos < data.len() {
        let start = pos;
        let opcode = data[pos];
        pos += 1;
        if opcode == 0 {
            return Err(DeltaError::Invalid("保留指令 0"));
        }
        if opcode & 0x80 != 0 {
            // copy from base
            let mut offset: u64 = 0;
            let mut len: u64 = 0;
            for (i, slot) in [
                (&mut offset, 0u32),
                (&mut offset, 8),
                (&mut offset, 16),
                (&mut offset, 24),
                (&mut len, 0),
                (&mut len, 8),
                (&mut len, 16),
            ]
            .iter_mut()
            .enumerate()
            {
                if opcode & (1 << i) != 0 {
                    if pos >= data.len() {
                        return Err(DeltaError::Truncated);
                    }
                    *slot.0 |= (data[pos] as u64) << slot.1;
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            ops.push(DeltaOp::Copy { offset, len });
        } else {
            // insert literal bytes
            let n = opcode as usize;
            if pos + n > data.len() {
                return Err(DeltaError::Truncated);
            }
            ops.push(DeltaOp::Insert {
                data: data[pos..pos + n].to_vec(),
            });
            pos += n;
        }
        op_spans.push((start, pos));
    }

    Ok(DeltaProgram {
        base_size,
        result_size,
        ops,
        op_spans,
    })
}

/// 应用 delta，严格校验所有边界与声明大小
pub fn apply_delta(base: &[u8], prog: &DeltaProgram) -> Result<Vec<u8>, DeltaError> {
    if base.len() as u64 != prog.base_size {
        return Err(DeltaError::BaseSizeMismatch {
            declared: prog.base_size,
            actual: base.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(prog.result_size.min(1 << 24) as usize);
    for op in &prog.ops {
        match op {
            DeltaOp::Copy { offset, len } => {
                let end = offset.checked_add(*len).ok_or(DeltaError::Invalid("copy 长度溢出"))?;
                if end > base.len() as u64 {
                    return Err(DeltaError::CopyOutOfRange {
                        offset: *offset,
                        len: *len,
                        base_len: base.len() as u64,
                    });
                }
                out.extend_from_slice(&base[*offset as usize..end as usize]);
            }
            DeltaOp::Insert { data } => out.extend_from_slice(data),
        }
    }
    if out.len() as u64 != prog.result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: prog.result_size,
            actual: out.len() as u64,
        });
    }
    Ok(out)
}

/// 生成 git delta 指令（仅测试辅助用，核心解析不依赖它）
pub fn build_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    // 简单策略：尝试找最长公共前缀作为 copy，其余按 insert 处理
    let mut out = Vec::new();
    write_varint(base.len() as u64, &mut out);
    write_varint(result.len() as u64, &mut out);
    let common = base.iter().zip(result.iter()).take_while(|(a, b)| a == b).count();
    if common > 0 {
        write_copy(&mut out, 0, common as u64);
    }
    let rest = &result[common..];
    let mut i = 0;
    while i < rest.len() {
        let n = (rest.len() - i).min(127);
        let chunk = &rest[i..i + n];
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        i += n;
    }
    out
}

fn write_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn write_copy(out: &mut Vec<u8>, offset: u64, len: u64) {
    let mut opcode = 0x80u8;
    let mut bytes = Vec::new();
    for (i, val) in [offset & 0xff, (offset >> 8) & 0xff, (offset >> 16) & 0xff, (offset >> 24) & 0xff]
        .iter()
        .enumerate()
    {
        if *val != 0 {
            opcode |= 1 << i;
            bytes.push(*val as u8);
        }
    }
    for (i, val) in [len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff].iter().enumerate() {
        if *val != 0 {
            opcode |= 1 << (4 + i);
            bytes.push(*val as u8);
        }
    }
    out.push(opcode);
    out.extend(bytes);
}
