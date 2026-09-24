//! Git delta 指令解析与应用，逐条记录指令范围、输入/输出长度与校验结果。

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Copy { src_off: u64, len: u64 },
    Insert { len: u64 },
}

#[derive(Debug, Clone)]
pub struct DeltaOp {
    /// 指令在 delta 数据内的字节范围
    pub instr_off: usize,
    pub instr_len: usize,
    pub op: Op,
}

#[derive(Debug, Clone)]
pub struct Delta {
    pub src_size: u64,
    pub tgt_size: u64,
    /// 头部（两个 varint）之后的指令区起点
    pub ops_start: usize,
    pub ops: Vec<DeltaOp>,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub instr_off: usize,
    pub instr_len: usize,
    pub op: String,
    pub in_len: u64,
    pub out_len: u64,
    pub ok: bool,
    pub detail: String,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            bail!("delta varint 截断");
        }
        let b = data[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            bail!("delta varint 过长");
        }
    }
}

pub fn parse_delta(data: &[u8]) -> Result<Delta> {
    let mut pos = 0usize;
    let src_size = read_varint(data, &mut pos)?;
    let tgt_size = read_varint(data, &mut pos)?;
    let ops_start = pos;
    let mut ops = Vec::new();
    while pos < data.len() {
        let instr_off = pos;
        let cmd = data[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut src_off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= data.len() {
                        bail!("copy 指令截断");
                    }
                    src_off |= (data[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= data.len() {
                        bail!("copy 指令截断");
                    }
                    len |= (data[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            ops.push(DeltaOp {
                instr_off,
                instr_len: pos - instr_off,
                op: Op::Copy { src_off, len },
            });
        } else if cmd != 0 {
            let len = cmd as usize;
            if pos + len > data.len() {
                bail!("insert 指令截断");
            }
            ops.push(DeltaOp {
                instr_off,
                instr_len: 1 + len,
                op: Op::Insert { len: len as u64 },
            });
            pos += len;
        } else {
            bail!("非法的 0 指令");
        }
    }
    Ok(Delta { src_size, tgt_size, ops_start, ops })
}

/// 应用 delta，返回 (输出, 每步记录)。任何一步失败都会带 ok=false 的记录并返回 Err。
pub fn apply_delta(base: &[u8], delta_data: &[u8]) -> Result<(Vec<u8>, Vec<Step>)> {
    let delta = parse_delta(delta_data)?;
    let mut steps = Vec::new();
    if base.len() as u64 != delta.src_size {
        bail!(
            "base 大小不匹配: delta 期望 {} 实际 {}",
            delta.src_size,
            base.len()
        );
    }
    let mut out = Vec::with_capacity(delta.tgt_size as usize);
    for op in &delta.ops {
        match op.op {
            Op::Copy { src_off, len } => {
                let ok = src_off + len <= base.len() as u64;
                let step = Step {
                    instr_off: op.instr_off,
                    instr_len: op.instr_len,
                    op: format!("copy base[{src_off}..{}]", src_off + len),
                    in_len: base.len() as u64,
                    out_len: len,
                    ok,
                    detail: if ok { String::new() } else { "copy 越界".into() },
                };
                if !ok {
                    steps.push(step);
                    bail_with_steps(steps, "copy 指令越界");
                }
                steps.push(step);
                out.extend_from_slice(&base[src_off as usize..(src_off + len) as usize]);
            }
            Op::Insert { len } => {
                let data_off = op.instr_off + op.instr_len - len as usize;
                steps.push(Step {
                    instr_off: op.instr_off,
                    instr_len: op.instr_len,
                    op: format!("insert {len} 字节"),
                    in_len: (delta_data.len() - data_off) as u64,
                    out_len: len,
                    ok: true,
                    detail: String::new(),
                });
                out.extend_from_slice(&delta_data[data_off..data_off + len as usize]);
            }
        }
        if out.len() as u64 > delta.tgt_size {
            bail_with_steps(steps, "输出超过声明的目标大小（大小欺骗）");
        }
    }
    if out.len() as u64 != delta.tgt_size {
        bail_with_steps(
            steps,
            &format!("输出大小 {} 与声明 {} 不符", out.len(), delta.tgt_size),
        );
    }
    Ok((out, steps))
}

fn bail_with_steps<T>(steps: Vec<Step>, msg: &str) -> Result<T> {
    // 把已记录的步骤编码进错误，调用方需要步骤时用 apply_delta_capturing
    Err(DeltaError { msg: msg.to_string(), steps }.into())
}

#[derive(Debug)]
pub struct DeltaError {
    pub msg: String,
    pub steps: Vec<Step>,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl std::error::Error for DeltaError {}

/// 应用 delta 并始终返回步骤记录（成功或失败）。
pub fn apply_delta_capturing(
    base: &[u8],
    delta_data: &[u8],
) -> (Result<Vec<u8>>, Vec<Step>) {
    match apply_delta(base, delta_data) {
        Ok((out, steps)) => (Ok(out), steps),
        Err(e) => {
            if let Some(de) = e.downcast_ref::<DeltaError>() {
                (Err(anyhow::anyhow!(de.msg.clone())), de.steps.clone())
            } else {
                (Err(e), Vec::new())
            }
        }
    }
}
