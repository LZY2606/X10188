//! Git delta 指令解析与应用。支持预算检查点：每条指令执行前询问
//! `allow`，若被拒绝则在指令边界返回可重试的中间状态。

use sha1::Digest;

#[derive(Debug, Clone)]
pub struct Step {
    pub instr_off: u64,
    pub instr_len: u64,
    pub in_len: u64,
    pub out_len: u64,
    pub sha1: String,
}

#[derive(Debug)]
pub enum DeltaOutcome {
    Done { out: Vec<u8>, steps: Vec<Step> },
    Paused { next_off: usize, out: Vec<u8>, steps: Vec<Step> },
}

/// 读取 delta 头部的小端 7 位 varint，返回 (值, 消费后偏移)。
fn read_varint(buf: &[u8], mut off: usize) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if off >= buf.len() {
            return Err("delta 头部 varint 截断".into());
        }
        let b = buf[off];
        off += 1;
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta 头部 varint 过长".into());
        }
    }
    Ok((value, off))
}

/// 解析 delta 头部：源大小、目标大小、头部总长度。
pub fn delta_header(delta: &[u8]) -> Result<(u64, u64, usize), String> {
    let (src, p1) = read_varint(delta, 0)?;
    let (tgt, p2) = read_varint(delta, p1)?;
    Ok((src, tgt, p2))
}

fn sha1_hex(data: &[u8]) -> String {
    let mut h = sha1::Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 从 `start` 偏移处继续应用 delta 指令，`out` 为已有输出。
/// `allow(n)` 在每条指令执行前调用，返回 false 则在该指令边界暂停。
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    start: usize,
    mut out: Vec<u8>,
    mut allow: impl FnMut(u64) -> bool,
) -> Result<DeltaOutcome, String> {
    let mut steps = Vec::new();
    let mut i = start;
    while i < delta.len() {
        let instr_off = i;
        let cmd = delta[i];
        i += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    if i >= delta.len() {
                        return Err("copy 指令 offset 截断".into());
                    }
                    cp_off |= (delta[i] as u64) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    if i >= delta.len() {
                        return Err("copy 指令 size 截断".into());
                    }
                    cp_size |= (delta[i] as u64) << (8 * bit);
                    i += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or_else(|| "copy 指令地址溢出".to_string())?;
            if end as usize > base.len() {
                return Err(format!(
                    "copy 指令越界: base 长 {}，请求 [{}..{}]",
                    base.len(),
                    cp_off,
                    end
                ));
            }
            if !allow(cp_size) {
                return Ok(DeltaOutcome::Paused { next_off: instr_off, out, steps });
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            steps.push(Step {
                instr_off: instr_off as u64,
                instr_len: (i - instr_off) as u64,
                in_len: cp_size,
                out_len: cp_size,
                sha1: sha1_hex(&out),
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if i + n > delta.len() {
                return Err("insert 指令数据截断".into());
            }
            if !allow(n as u64) {
                return Ok(DeltaOutcome::Paused { next_off: instr_off, out, steps });
            }
            out.extend_from_slice(&delta[i..i + n]);
            i += n;
            steps.push(Step {
                instr_off: instr_off as u64,
                instr_len: (1 + n) as u64,
                in_len: 0,
                out_len: n as u64,
                sha1: sha1_hex(&out),
            });
        } else {
            return Err(format!("保留指令 0 @{}", instr_off));
        }
    }
    Ok(DeltaOutcome::Done { out, steps })
}
