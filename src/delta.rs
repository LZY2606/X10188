use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeltaOp {
    /// byte range of this instruction inside the delta payload [start, end)
    pub range: (usize, usize),
    pub kind: String, // "copy" | "insert"
    /// for copy: offset in base; for insert: offset in delta payload
    pub src_off: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaInfo {
    pub src_size: u64,
    pub dst_size: u64,
    pub ops: Vec<DeltaOp>,
    /// bytes consumed by the two size varints
    pub header_len: usize,
}

fn read_varint(delta: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let c = *delta
            .get(*pos)
            .ok_or("delta 变长整数越界".to_string())?;
        *pos += 1;
        v |= u64::from(c & 0x7f) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err("delta 变长整数过长".to_string());
        }
    }
}

/// Apply a git delta to `base`, returning the reconstructed bytes and a
/// detailed instruction trace (ranges, offsets, lengths).
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInfo), String> {
    let mut pos = 0usize;
    let src_size = read_varint(delta, &mut pos)?;
    let dst_size = read_varint(delta, &mut pos)?;
    let header_len = pos;

    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小校验失败: 声明 {src_size}，实际 base {}",
            base.len()
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(dst_size.min(1 << 26) as usize);
    let mut ops = Vec::new();

    while pos < delta.len() {
        let op_start = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 offset 字节越界")?;
                    pos += 1;
                    cp_off |= u64::from(b) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *delta.get(pos).ok_or("copy 指令 size 字节越界")?;
                    pos += 1;
                    cp_size |= u64::from(b) << (8 * i);
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or("copy 指令范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 指令越界: base 长 {}，请求 [{cp_off}, {end})",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            ops.push(DeltaOp {
                range: (op_start, pos),
                kind: "copy".to_string(),
                src_off: cp_off,
                len: cp_size,
            });
        } else if cmd != 0 {
            // insert literal bytes
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err(format!(
                    "insert 指令越界: 需要 {n} 字节，delta 剩余 {}",
                    delta.len() - pos
                ));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            ops.push(DeltaOp {
                range: (op_start, pos + n),
                kind: "insert".to_string(),
                src_off: pos as u64,
                len: n as u64,
            });
            pos += n;
        } else {
            return Err("delta 指令 0 为保留值".to_string());
        }
        if out.len() as u64 > dst_size {
            return Err(format!(
                "delta 输出超过声明目标大小 {dst_size}（大小欺骗嫌疑）"
            ));
        }
    }

    if out.len() as u64 != dst_size {
        return Err(format!(
            "delta 输出 {} 与声明目标大小 {dst_size} 不一致（大小欺骗）",
            out.len()
        ));
    }

    Ok((
        out,
        DeltaInfo {
            src_size,
            dst_size,
            ops,
            header_len,
        },
    ))
}

/// Encode a delta that transforms `base` into `target` (simple greedy encoder
/// used by tests and fixtures; not part of the forensic read path).
pub fn encode_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    fn varint(mut v: u64, out: &mut Vec<u8>) {
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
    let mut out = Vec::new();
    varint(base.len() as u64, &mut out);
    varint(target.len() as u64, &mut out);

    // longest common prefix as a single copy op
    let mut prefix = 0usize;
    while prefix < base.len() && prefix < target.len() && base[prefix] == target[prefix] {
        prefix += 1;
    }
    if prefix > 0 {
        let mut cmd = 0x80u8;
        // offset = 0 -> no offset bytes
        let mut size = prefix;
        let mut size_bytes = [0u8; 3];
        let mut n = 0;
        for i in 0..3 {
            size_bytes[i] = (size & 0xff) as u8;
            if size_bytes[i] != 0 {
                cmd |= 0x10 << i;
                n = i + 1;
            }
            size >>= 8;
        }
        out.push(cmd);
        for b in size_bytes.iter().take(n) {
            out.push(*b);
        }
    }
    // insert the remainder in <=127 byte chunks
    let mut rest = &target[prefix..];
    while !rest.is_empty() {
        let n = rest.len().min(127);
        out.push(n as u8);
        out.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
    }
    out
}
