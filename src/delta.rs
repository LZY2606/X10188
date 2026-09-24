//! Git pack 变长编码与 delta 指令应用。
//!
//! 全部纯 Rust 实现，不调用系统 git。delta 应用过程中记录
//! 每条指令在 delta 数据中的原始范围，供取证页面展示。

/// pack 对象头部解码结果。
pub struct PackHeader {
    pub type_code: u8,
    pub size: u64,
    pub header_len: usize,
}

/// 解析对象条目头部（3 位类型 + 变长 size）。
pub fn decode_pack_object_header(data: &[u8], start: usize) -> Result<PackHeader, String> {
    let mut pos = start;
    if pos >= data.len() {
        return Err("pack 对象头起始偏移越界".to_string());
    }
    let c = data[pos];
    pos += 1;
    let type_code = (c >> 1) & 0x07;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cur = c;
    while cur & 0x80 != 0 {
        if pos >= data.len() {
            return Err("pack 对象头变长 size 越界（流被截断）".to_string());
        }
        cur = data[pos];
        pos += 1;
        size = size
            .checked_add(((cur & 0x7f) as u64) << shift)
            .ok_or_else(|| "pack 对象 size 溢出 u64".to_string())?;
        shift += 7;
        if shift > 64 {
            return Err("pack 对象 size 变长编码过长".to_string());
        }
    }
    Ok(PackHeader {
        type_code,
        size,
        header_len: pos - start,
    })
}

/// 解析 delta 数据头部的纯 7 位组变长整数（source/target size）。
pub fn decode_delta_varint(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut pos = start;
    if pos >= data.len() {
        return Err("delta 变长整数起始越界".to_string());
    }
    let mut size = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return Err("delta 变长整数被截断".to_string());
        }
        let c = data[pos];
        pos += 1;
        size = size
            .checked_add(((c & 0x7f) as u64) << shift)
            .ok_or_else(|| "delta size 溢出 u64".to_string())?;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 64 {
            return Err("delta 变长编码过长".to_string());
        }
    }
    Ok((size, pos - start))
}

/// ofs-delta “负偏移距离”编码（与 git 线格式一致）。
pub fn encode_ofs_distance(distance: u64) -> Vec<u8> {
    assert!(distance > 0, "ofs-delta 距离必须为正");
    let mut bytes = vec![(distance & 0x7f) as u8];
    let mut v = distance >> 7;
    while v > 0 {
        v -= 1;
        bytes.push((v & 0x7f) as u8);
        v >>= 7;
    }
    bytes.reverse();
    let n = bytes.len();
    for b in bytes[..n.saturating_sub(1)].iter_mut() {
        *b |= 0x80;
    }
    bytes
}

/// 解码 ofs-delta 负偏移距离。返回（距离, 占用字节数）。
pub fn decode_ofs_distance(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut pos = start;
    if pos >= data.len() {
        return Err("ofs-delta 头起始越界".to_string());
    }
    let mut c = data[pos];
    pos += 1;
    let mut ofs = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if pos >= data.len() {
            return Err("ofs-delta 变长偏移被截断".to_string());
        }
        // ofs+1 必须仍能放进 7 的倍数位宽，否则为越界编码。
        let plus = ofs.checked_add(1).ok_or_else(|| "ofs-delta 偏移溢出".to_string())?;
        if plus >> 57 != 0 {
            return Err("ofs-delta 偏移编码过大（越界）".to_string());
        }
        c = data[pos];
        pos += 1;
        ofs = (plus << 7) | ((c & 0x7f) as u64);
    }
    if ofs == 0 {
        return Err("ofs-delta 距离为 0（非法）".to_string());
    }
    Ok((ofs, pos - start))
}

/// 编码对象条目头（type_code 为 pack 线格式类型号）。
pub fn encode_pack_object_header(type_code: u8, size: u64) -> Vec<u8> {
    let mut v = vec![(type_code << 4) | (size & 0x0f) as u8];
    let mut s = size >> 4;
    while s > 0 {
        v.push((s & 0x7f) as u8);
        s >>= 7;
    }
    let n = v.len();
    for b in v[..n.saturating_sub(1)].iter_mut() {
        *b |= 0x80;
    }
    v
}

/// delta 头部纯变长整数编码。
pub fn encode_delta_varint(size: u64) -> Vec<u8> {
    let mut v = vec![(size & 0x7f) as u8];
    let mut s = size >> 7;
    while s > 0 {
        v.push((s & 0x7f) as u8);
        s >>= 7;
    }
    let n = v.len();
    for b in v[..n.saturating_sub(1)].iter_mut() {
        *b |= 0x80;
    }
    v
}

/// 一条 delta 指令的取证记录。
#[derive(Clone, Debug)]
pub struct DeltaInstr {
    /// 指令操作码在 delta 数据中的字节范围 [start, end)。
    pub op_range: (usize, usize),
    /// 操作数据（insert 负载 / copy 引用）在 delta 中的范围。
    pub data_range: (usize, usize),
    pub kind: &'static str,
    pub detail: String,
}

/// delta 应用结果。
pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub instructions: Vec<DeltaInstr>,
    pub header_len: usize,
}

/// 应用 delta：校验头部声明的 source/target size，逐条执行指令。
///
/// 任何越界、保留操作码、输出长度不符都返回错误（绝不返回部分结果）。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, String> {
    let (src_size, n1) = decode_delta_varint(delta, 0)?;
    let (tgt_size, n2) = decode_delta_varint(delta, n1)?;
    if src_size as usize != base.len() {
        return Err(format!(
            "delta source size 欺骗：头部声明 {src_size}，base 实际 {} 字节",
            base.len()
        ));
    }
    // 先检查声明的目标大小不会造成离谱分配，调用方还会做预算校验。
    let mut out: Vec<u8> = Vec::new();
    let mut instrs: Vec<DeltaInstr> = Vec::new();
    let mut pos = n1 + n2;
    while pos < delta.len() {
        let op_pos = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY：从 base 复制。
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            let mut data_start = pos;
            if op & 0x01 != 0 {
                cp_off |= read_byte(delta, &mut pos)? as u32;
            }
            if op & 0x02 != 0 {
                cp_off |= (read_byte(delta, &mut pos)? as u32) << 8;
            }
            if op & 0x04 != 0 {
                cp_off |= (read_byte(delta, &mut pos)? as u32) << 16;
            }
            if op & 0x08 != 0 {
                cp_off |= (read_byte(delta, &mut pos)? as u32) << 24;
            }
            if op & 0x10 != 0 {
                cp_size |= read_byte(delta, &mut pos)? as u32;
            }
            if op & 0x20 != 0 {
                cp_size |= (read_byte(delta, &mut pos)? as u32) << 8;
            }
            if op & 0x40 != 0 {
                cp_size |= (read_byte(delta, &mut pos)? as u32) << 16;
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off as u64 + cp_size as u64;
            if end > base.len() as u64 {
                return Err(format!(
                    "COPY 指令越界：offset={cp_off} size={cp_size}，base 长度 {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[cp_off as usize..(cp_off + cp_size) as usize]);
            instrs.push(DeltaInstr {
                op_range: (op_pos, data_start),
                data_range: (data_start, pos),
                kind: "copy",
                detail: format!("offset={cp_off} size={cp_size}"),
            });
        } else if op != 0 {
            // INSERT：直接附加 delta 中的 op 字节。
            let take = op as usize;
            if pos + take > delta.len() {
                return Err("INSERT 指令负载越界（delta 被截断）".to_string());
            }
            let data_end = pos + take;
            out.extend_from_slice(&delta[pos..data_end]);
            instrs.push(DeltaInstr {
                op_range: (op_pos, pos),
                data_range: (pos, data_end),
                kind: "insert",
                detail: format!("size={take}"),
            });
            pos = data_end;
        } else {
            return Err(format!("delta 保留操作码 0x00 出现在偏移 {op_pos}（非法）"));
        }
        // 提前对照声明目标长度，防止中途失控增长。
        if out.len() as u64 > tgt_size {
            return Err(format!(
                "delta 输出已超过声明 target size {tgt_size}（大小欺骗）"
            ));
        }
    }
    if out.len() as u64 != tgt_size {
        return Err(format!(
            "delta target size 欺骗：头部声明 {tgt_size}，实际还原 {} 字节",
            out.len()
        ));
    }
    Ok(AppliedDelta {
        output: out,
        instructions: instrs,
        header_len: n1 + n2,
    })
}

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8, String> {
    if *pos >= data.len() {
        return Err("COPY 指令参数越界（delta 被截断）".to_string());
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}
