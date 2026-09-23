//! Git delta 指令流解析与应用，记录指令范围供取证展示。
#[derive(Debug)]
pub struct DeltaOutcome {
    pub out: Vec<u8>,
    pub base_size: u64,
    pub target_size: u64,
    /// 指令区在 delta 数据中的字节范围 [instr_start, instr_end)
    pub instr_start: usize,
    pub instr_end: usize,
    pub instr_count: usize,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("delta header varint truncated".into());
        }
        let b = data[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err("delta varint overflow".into());
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let base_size = read_varint(delta, &mut pos)?;
    let target_size = read_varint(delta, &mut pos)?;
    if base.len() as u64 != base_size {
        return Err(format!(
            "base size mismatch: delta expects {base_size}, got {}",
            base.len()
        ));
    }
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(target_size as usize);
    let mut count = 0usize;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        count += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut off: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy offset truncated".into());
                    }
                    off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy size truncated".into());
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
                .ok_or_else(|| "copy range overflow".to_string())? as usize;
            if end > base.len() {
                return Err(format!(
                    "copy out of range: {off}..{end} exceeds base {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..end]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert literal overruns delta".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("reserved delta opcode 0".into());
        }
        if out.len() as u64 > target_size {
            return Err(format!(
                "delta output exceeded target size {target_size}"
            ));
        }
    }
    if out.len() as u64 != target_size {
        return Err(format!(
            "delta produced {} bytes, target size {target_size}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        out,
        base_size,
        target_size,
        instr_start,
        instr_end: delta.len(),
        instr_count: count,
    })
}
