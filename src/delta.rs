use crate::git::read_size_varint;

#[derive(Clone, Debug)]
pub struct DeltaMeta {
    pub src_size: u64,
    pub tgt_size: u64,
    /// 指令区在 delta 数据中的起止（两个 size varint 之后）。
    pub instr_start: usize,
    pub instr_end: usize,
    pub ops: usize,
}

pub fn read_header(delta: &[u8]) -> Result<DeltaMeta, String> {
    let mut pos = 0usize;
    let src_size = read_size_varint(delta, &mut pos)?;
    let tgt_size = read_size_varint(delta, &mut pos)?;
    Ok(DeltaMeta {
        src_size,
        tgt_size,
        instr_start: pos,
        instr_end: delta.len(),
        ops: 0,
    })
}

/// 按 git delta 编码应用指令，每一步都做边界校验，输出超过目标声明大小立即中止。
pub fn apply(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaMeta), String> {
    let mut meta = read_header(delta)?;
    if meta.src_size as usize != base.len() {
        return Err(format!(
            "delta 源大小 {} 与 base 长度 {} 不一致",
            meta.src_size,
            base.len()
        ));
    }
    let mut out = Vec::with_capacity(meta.tgt_size.min(1 << 20) as usize);
    let mut i = meta.instr_start;
    let mut ops = 0usize;
    while i < delta.len() {
        let cmd = delta[i];
        i += 1;
        ops += 1;
        if cmd & 0x80 != 0 {
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for b in 0..4u8 {
                if cmd & (1 << b) != 0 {
                    let v = *delta.get(i).ok_or("copy 指令偏移字节不足")?;
                    i += 1;
                    offset |= (v as u32) << (8 * b);
                }
            }
            for b in 0..3u8 {
                if cmd & (0x10 << b) != 0 {
                    let v = *delta.get(i).ok_or("copy 指令长度字节不足")?;
                    i += 1;
                    size |= (v as u32) << (8 * b);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or("copy 范围整数溢出")? as usize;
            if end > base.len() {
                return Err(format!(
                    "copy 指令越界: offset={offset} size={size} base_len={}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if i + n > delta.len() {
                return Err("insert 指令数据越界".into());
            }
            out.extend_from_slice(&delta[i..i + n]);
            i += n;
        } else {
            return Err("非法 delta 指令 0x00".into());
        }
        if out.len() as u64 > meta.tgt_size {
            return Err(format!(
                "delta 输出 {} 超过声明目标大小 {}",
                out.len(),
                meta.tgt_size
            ));
        }
    }
    if out.len() as u64 != meta.tgt_size {
        return Err(format!(
            "delta 最终长度 {} 与声明目标大小 {} 不符",
            out.len(),
            meta.tgt_size
        ));
    }
    meta.ops = ops;
    Ok((out, meta))
}

fn put_size_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

fn emit_copy(out: &mut Vec<u8>, offset: usize, size: usize) {
    let mut cmd = 0x80u8;
    let mut off_flags = 0u8;
    for b in 0..4u8 {
        if (offset >> (8 * b)) & 0xff != 0 {
            off_flags |= 1 << b;
        }
    }
    let mut size_flags = 0u8;
    let eff_size = if size == 0x10000 { 0 } else { size };
    for b in 0..3u8 {
        if (eff_size >> (8 * b)) & 0xff != 0 {
            size_flags |= 0x10 << b;
        }
    }
    cmd |= off_flags | size_flags;
    out.push(cmd);
    for b in 0..4u8 {
        if off_flags & (1 << b) != 0 {
            out.push(((offset >> (8 * b)) & 0xff) as u8);
        }
    }
    for b in 0..3u8 {
        if size_flags & (0x10 << b) != 0 {
            out.push(((eff_size >> (8 * b)) & 0xff) as u8);
        }
    }
}

/// 测试辅助：生成合法 delta（公共前缀走 copy，其余走 insert），核心解析不依赖系统 git。
pub fn encode(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_size_varint(&mut out, base.len() as u64);
    put_size_varint(&mut out, target.len() as u64);
    let prefix = base
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut copied = 0usize;
    while copied < prefix {
        let n = (prefix - copied).min(0x10000);
        emit_copy(&mut out, copied, n);
        copied += n;
    }
    let mut pos = prefix;
    while pos < target.len() {
        let n = (target.len() - pos).min(127);
        out.push(n as u8);
        out.extend_from_slice(&target[pos..pos + n]);
        pos += n;
    }
    out
}
