//! Git ofs/ref delta 指令流应用，逐指令记录范围、累计输入输出长度与校验。

use super::{read_size_encoding, Error, Result};

#[derive(Clone, Debug)]
pub struct DeltaCmd {
    pub index: usize,
    pub kind: &'static str,
    /// copy 时为基对象中的字节范围；insert 时为 delta 数据中的字节范围。
    pub src_start: u64,
    pub src_end: u64,
    pub length: u64,
    /// 该指令应用前/后目标（输出）长度。
    pub out_before: u64,
    pub out_after: u64,
    /// 该指令对应字节在 delta 指令流中的范围。
    pub instr_start: usize,
    pub instr_end: usize,
}

pub struct DeltaApply {
    pub out: Vec<u8>,
    pub source_size: u64,
    pub target_size: u64,
    pub cmds: Vec<DeltaCmd>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaApply> {
    let mut p = 0usize;
    let source_size = read_size_encoding(delta, &mut p)?;
    let target_size = read_size_encoding(delta, &mut p)?;
    if source_size as usize != base.len() {
        return Err(Error::Delta(format!(
            "delta 源大小 {} 与基对象长度 {} 不一致",
            source_size,
            base.len()
        )));
    }
    if target_size as usize > 1024 * 1024 * 1024 {
        return Err(Error::Delta(format!("目标大小 {} 过大", target_size)));
    }

    let mut out: Vec<u8> = Vec::with_capacity(target_size as usize);
    let mut cmds: Vec<DeltaCmd> = Vec::new();
    let mut idx = 0usize;

    while p < delta.len() {
        let op = delta[p];
        let instr_start = p;
        p += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut offset = 0u64;
            let mut size = 0u64;
            for bit in 0..4u32 {
                if op & (1 << bit) != 0 {
                    let b = *delta.get(p).ok_or_else(|| Error::Delta("copy 指令截断".into()))?;
                    p += 1;
                    offset |= (b as u64) << (8 * bit);
                }
            }
            for bit in 0..3u32 {
                if op & (1 << (4 + bit)) != 0 {
                    let b = *delta.get(p).ok_or_else(|| Error::Delta("copy 指令截断".into()))?;
                    p += 1;
                    size |= (b as u64) << (8 * bit);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            if offset.checked_add(size).map_or(true, |e| e as usize > base.len()) {
                return Err(Error::Delta(format!(
                    "copy 指令越界: offset={} size={} base_len={}",
                    offset, size, base.len()
                )));
            }
            if out.len() as u64 + size > target_size {
                return Err(Error::Delta("copy 指令使输出超过声明目标大小（输出大小欺骗）".into()));
            }
            let before = out.len() as u64;
            out.extend_from_slice(&base[offset as usize..(offset + size) as usize]);
            cmds.push(DeltaCmd {
                index: idx,
                kind: "copy",
                src_start: offset,
                src_end: offset + size,
                length: size,
                out_before: before,
                out_after: out.len() as u64,
                instr_start,
                instr_end: p,
            });
        } else if op != 0 {
            // insert literal
            let size = op as u64;
            if p + size as usize > delta.len() {
                return Err(Error::Delta("insert 指令字面数据截断".into()));
            }
            if out.len() as u64 + size > target_size {
                return Err(Error::Delta("insert 指令使输出超过声明目标大小（输出大小欺骗）".into()));
            }
            let before = out.len() as u64;
            let src_start = p as u64;
            out.extend_from_slice(&delta[p..p + size as usize]);
            p += size as usize;
            cmds.push(DeltaCmd {
                index: idx,
                kind: "insert",
                src_start,
                src_end: src_start + size,
                length: size,
                out_before: before,
                out_after: out.len() as u64,
                instr_end: p,
                instr_start,
            });
        } else {
            return Err(Error::Delta("delta 指令操作码 0 保留且非法".into()));
        }
        idx += 1;
    }

    if out.len() as u64 != target_size {
        return Err(Error::Delta(format!(
            "指令执行完毕输出 {} 字节，与声明目标 {} 不一致",
            out.len(),
            target_size
        )));
    }

    Ok(DeltaApply {
        out,
        source_size,
        target_size,
        cmds,
    })
}

/// 构造 delta 指令流（测试用）：按 (offset,size) copy 与字面 insert 拼接。
pub fn build_delta(source_size: usize, target: &[u8], ops: &[DeltaBuildOp]) -> Vec<u8> {
    let mut d = Vec::new();
    write_size(&mut d, source_size as u64);
    write_size(&mut d, target.len() as u64);
    for op in ops {
        match op {
            DeltaBuildOp::Copy(mut off, mut sz) => {
                if *sz == 0 {
                    continue;
                }
                let mut byte = 0x80u8;
                let mut off_bytes = [0u8; 4];
                for i in 0..4 {
                    off_bytes[i] = (off & 0xff) as u8;
                    if off_bytes[i] != 0 {
                        byte |= 1 << i;
                    }
                    off >>= 8;
                }
                let mut sz_bytes = [0u8; 3];
                let enc_size = if *sz == 0x10000 { 0 } else { *sz };
                for i in 0..3 {
                    sz_bytes[i] = (enc_size & 0xff) as u8;
                    if sz_bytes[i] != 0 {
                        byte |= 1 << (4 + i);
                    }
                    sz >>= 8;
                }
                d.push(byte);
                for i in 0..4 {
                    if byte & (1 << i) != 0 {
                        d.push(off_bytes[i]);
                    }
                }
                for i in 0..3 {
                    if byte & (1 << (4 + i)) != 0 {
                        d.push(sz_bytes[i]);
                    }
                }
            }
            DeltaBuildOp::Insert(data) => {
                let mut i = 0;
                while i < data.len() {
                    let n = std::cmp::min(127, data.len() - i);
                    d.push(n as u8);
                    d.extend_from_slice(&data[i..i + n]);
                    i += n;
                }
            }
        }
    }
    debug_assert_eq!(d.len().min(d.len()), d.len());
    let _ = target;
    d
}

fn write_size(d: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        d.push(b);
        if v == 0 {
            break;
        }
    }
}

#[derive(Clone, Debug)]
pub enum DeltaBuildOp {
    Copy(u64, u64),
    Insert(Vec<u8>),
}
