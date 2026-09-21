use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
    Unknown(u8),
}

impl ObjType {
    pub fn from_code(code: u8) -> ObjType {
        match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            other => ObjType::Unknown(other),
        }
    }

    pub fn from_name(name: &str) -> ObjType {
        match name {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            "ofs_delta" => ObjType::OfsDelta,
            "ref_delta" => ObjType::RefDelta,
            _ => ObjType::Unknown(0),
        }
    }

    pub fn name(&self) -> String {
        match self {
            ObjType::Commit => "commit".to_string(),
            ObjType::Tree => "tree".to_string(),
            ObjType::Blob => "blob".to_string(),
            ObjType::Tag => "tag".to_string(),
            ObjType::OfsDelta => "ofs_delta".to_string(),
            ObjType::RefDelta => "ref_delta".to_string(),
            ObjType::Unknown(c) => format!("unknown_{c}"),
        }
    }

    /// git object id 使用的类型名（delta 类型没有自己的 oid 类型名）
    pub fn oid_type_name(&self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// 计算 git object id: sha1("<type> <len>\0" + content)
pub fn object_id(type_name: &str, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{} {}\0", type_name, content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// 解压 zlib 流，返回 (解压结果, 消耗的输入字节数)。
/// 消耗的输入字节数即 zlib 流边界，调用方据此定位下一个 pack 对象。
pub fn zlib_inflate(data: &[u8], cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut decompressor = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let in_pos = decompressor.total_in() as usize;
        if in_pos >= data.len() {
            return Err("zlib 流被截断（输入耗尽但流未结束）".to_string());
        }
        let out_before = decompressor.total_out() as usize;
        let status = decompressor
            .decompress(&data[in_pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = decompressor.total_out() as usize - out_before;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > cap {
            return Err(format!(
                "解压大小超过上限 {cap} 字节（疑似大小欺骗或 zip bomb）"
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok((out, decompressor.total_in() as usize));
            }
            Status::Ok => {}
            Status::BufError => {
                if produced == 0 && decompressor.total_in() as usize == in_pos {
                    return Err("zlib 流无法继续（BufError，疑似截断或损坏）".to_string());
                }
            }
        }
    }
}

/// delta 头部/指令中的 7 位小端 varint
pub fn delta_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("delta varint 越界（数据截断）".to_string());
        }
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        if shift > 63 {
            return Err("delta varint 过长".to_string());
        }
    }
}

pub struct DeltaOutcome {
    pub out: Vec<u8>,
    /// 指令区在 delta 数据中的起止偏移（不含源/目标大小头）
    pub instr_start: usize,
    pub instr_end: usize,
    pub src_size: u64,
    pub dst_size: u64,
}

/// 应用 git delta 指令。校验源大小与目标大小。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let src_size = delta_varint(delta, &mut pos)?;
    let dst_size = delta_varint(delta, &mut pos)?;
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(dst_size.min(1 << 26) as usize);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 offset 字段截断".to_string());
                    }
                    offset |= (delta[pos] as u64) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 size 字段截断".to_string());
                    }
                    size |= (delta[pos] as u64) << (8 * bit);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| "copy 指令偏移溢出".to_string())?;
            if end as usize > base.len() {
                return Err(format!(
                    "copy 指令越界: offset={offset} size={size} 超出 base 长度 {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end as usize]);
        } else if cmd != 0 {
            // insert literal
            let len = cmd as usize;
            if pos + len > delta.len() {
                return Err("insert 指令越界（字面量截断）".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        } else {
            return Err("delta 指令 0 是保留指令".to_string());
        }
    }
    Ok(DeltaOutcome {
        out,
        instr_start,
        instr_end: pos,
        src_size,
        dst_size,
    })
}
