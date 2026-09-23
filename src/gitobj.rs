//! 纯 Git 对象原语：oid 计算、变长整数、zlib 边界、delta 应用。
//! 不调用系统 git。

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs_delta",
        OBJ_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

/// 计算 Git object id：sha1("<type> <len>\0" + content)
pub fn object_id(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// 解压 zlib 流并返回 (解压结果, 消耗的输入字节数)。
/// 消耗的字节数即 zlib 边界，用于定位 pack 中下一个对象。
pub fn zlib_decompress_bounded(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(input, &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {}", e))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if d.total_in() == before_in && d.total_out() == before_out {
                    return Err(format!(
                        "zlib 流被截断：已消费 {} 字节仍未到达流尾",
                        d.total_in()
                    ));
                }
            }
        }
    }
}

/// Git 风格的 size 变长整数（delta 头部用，7 位小端组）。
pub fn read_size_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut val: u64 = 0;
    loop {
        if *pos >= data.len() {
            return Err("变长整数越界（数据截断）".into());
        }
        let c = data[*pos];
        *pos += 1;
        val |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            return Ok(val);
        }
        if shift > 63 {
            return Err("变长整数过长".into());
        }
    }
}

/// pack 对象头的 type+size 编码。
pub fn read_type_size(data: &[u8], pos: &mut usize) -> Result<(u8, u64), String> {
    if *pos >= data.len() {
        return Err("对象头越界".into());
    }
    let mut c = data[*pos];
    *pos += 1;
    let otype = (c >> 4) & 0x7;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("对象头越界".into());
        }
        c = data[*pos];
        *pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象头 size 过长".into());
        }
    }
    Ok((otype, size))
}

/// ofs-delta 的偏移编码（特殊变长）。
pub fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= data.len() {
        return Err("ofs-delta 偏移越界".into());
    }
    let mut c = data[*pos];
    *pos += 1;
    let mut offset = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("ofs-delta 偏移越界".into());
        }
        c = data[*pos];
        *pos += 1;
        offset = ((offset + 1) << 7) | (c & 0x7f) as u64;
    }
    Ok(offset)
}

pub struct DeltaOutcome {
    pub out: Vec<u8>,
    /// 指令区在 delta 数据中的范围 [instr_start, instr_end)
    pub instr_start: usize,
    pub instr_end: usize,
}

/// 应用 Git delta：源大小校验（大小欺骗检测）、目标大小校验、指令边界校验。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let src_size = read_size_varint(delta, &mut pos)?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小欺骗：头部声明 {} 字节，实际 base {} 字节",
            src_size,
            base.len()
        ));
    }
    let tgt_size = read_size_varint(delta, &mut pos)? as usize;
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(tgt_size.min(1 << 26));
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
                .ok_or_else(|| "copy 指令偏移溢出".to_string())?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 指令越界：base 长 {}，请求 [{}..{})",
                    base.len(),
                    off,
                    end
                ));
            }
            out.extend_from_slice(&base[off as usize..end as usize]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令截断".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("delta 指令 0 为保留值".into());
        }
        if out.len() > tgt_size {
            return Err(format!(
                "delta 输出超过声明目标大小 {}（大小欺骗）",
                tgt_size
            ));
        }
    }
    if out.len() != tgt_size {
        return Err(format!(
            "delta 目标大小不符：声明 {}，实际 {}",
            tgt_size,
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        out,
        instr_start,
        instr_end: pos,
    })
}
