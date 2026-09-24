//! Git delta 指令解析与应用，记录每条指令的范围。
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instr {
    pub op: String,      // "copy" | "insert"
    pub cmd_off: usize,  // 指令在 delta 数据中的偏移
    pub src_off: u64,    // copy: base 内偏移；insert: delta 数据内偏移
    pub len: u64,
    pub out_off: u64,    // 输出中的偏移
}

fn read_varint(d: &[u8], p: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *p >= d.len() {
            return Err("delta 头部截断".into());
        }
        let b = d[*p];
        *p += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta varint 溢出".into());
        }
    }
    Ok(v)
}

/// 应用 delta，返回 (输出, 指令记录)。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<Instr>), String> {
    let mut p = 0usize;
    let src_size = read_varint(delta, &mut p)?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小不符: 声明 {src_size}，base 实际 {}",
            base.len()
        ));
    }
    let dst_size = read_varint(delta, &mut p)?;
    if dst_size > crate::zlib::HARD_CAP {
        return Err(format!("delta 声明输出过大: {dst_size}"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(dst_size as usize);
    let mut instrs = Vec::new();
    while p < delta.len() {
        let cmd_off = p;
        let cmd = delta[p];
        p += 1;
        if cmd & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err("copy 指令截断".into());
                    }
                    off |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if p >= delta.len() {
                        return Err("copy 指令截断".into());
                    }
                    len |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if off.saturating_add(len) > base.len() as u64 {
                return Err(format!(
                    "copy 越界: off {off} len {len}，base 长度 {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..(off + len) as usize]);
            instrs.push(Instr {
                op: "copy".into(),
                cmd_off,
                src_off: off,
                len,
                out_off: out.len() as u64 - len,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if p + n > delta.len() {
                return Err("insert 指令截断".into());
            }
            out.extend_from_slice(&delta[p..p + n]);
            instrs.push(Instr {
                op: "insert".into(),
                cmd_off,
                src_off: p as u64,
                len: n as u64,
                out_off: out.len() as u64 - n as u64,
            });
            p += n;
        } else {
            return Err("非法 delta 指令 0x00".into());
        }
        if out.len() as u64 > dst_size {
            return Err(format!(
                "delta 输出超过声明大小 {dst_size}（大小欺骗嫌疑）"
            ));
        }
    }
    if out.len() as u64 != dst_size {
        return Err(format!(
            "delta 输出大小不符: 声明 {dst_size}，实际 {}",
            out.len()
        ));
    }
    Ok((out, instrs))
}
