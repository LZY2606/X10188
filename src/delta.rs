//! Git delta instruction parser/applier with strict size verification.

#[derive(Debug)]
pub struct DeltaInfo {
    pub src_size: u64,
    pub tgt_size: u64,
    /// Offset inside the inflated delta where instructions begin.
    pub instr_start: usize,
    pub output: Vec<u8>,
}

fn read_varint(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() || shift > 63 {
            return Err("delta 头部 varint 损坏".into());
        }
        let b = buf[pos];
        pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((v, pos));
        }
    }
}

/// Apply `delta` to `base`, verifying the declared source size and never
/// allowing output to exceed the declared target size (size-spoof guard).
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaInfo, String> {
    let (src_size, p1) = read_varint(delta, 0)?;
    let (tgt_size, p2) = read_varint(delta, p1)?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小不符: 声明 {src_size}, base 实际 {}",
            base.len()
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(tgt_size.min(1 << 24) as usize);
    let mut pos = p2;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令截断".into());
                    }
                    off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令截断".into());
                    }
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off
                .checked_add(size)
                .ok_or("copy 指令偏移溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 指令越界: [{off}, {end}) 超出 base 长度 {}",
                    base.len()
                ));
            }
            if out.len() as u64 + size > tgt_size {
                return Err("大小欺骗: copy 使输出超过声明目标大小".into());
            }
            out.extend_from_slice(&base[off as usize..end as usize]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令截断".into());
            }
            if out.len() + n > tgt_size as usize {
                return Err("大小欺骗: insert 使输出超过声明目标大小".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("非法 delta 指令 0x00".into());
        }
    }
    if out.len() as u64 != tgt_size {
        return Err(format!(
            "大小欺骗: 声明目标 {tgt_size} 字节, 指令实际产出 {}",
            out.len()
        ));
    }
    Ok(DeltaInfo {
        src_size,
        tgt_size,
        instr_start: p2,
        output: out,
    })
}
