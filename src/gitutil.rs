//! Git object id 计算与底层编码工具。核心解析不调用系统 git。

use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn pack_code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }

    pub fn from_str(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            "ofs_delta" => Some(ObjType::OfsDelta),
            "ref_delta" => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// 计算 Git object id: sha1("<type> <len>\0" + content)
pub fn object_id(otype: ObjType, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", otype.as_str(), content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 解析 pack 对象头: (type, size, 消耗字节数)
pub fn parse_entry_header(data: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    let mut i = pos;
    let mut c = *data.get(i)?;
    i += 1;
    let otype = (c >> 4) & 0x7;
    let mut size: u64 = (c & 0x0f) as u64;
    let mut shift = 4;
    while c & 0x80 != 0 {
        c = *data.get(i)?;
        i += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((otype, size, i - pos))
}

/// 编码 pack 对象头（测试构造用）
pub fn encode_entry_header(otype: u8, mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = ((otype & 0x7) << 4) | (size as u8 & 0x0f);
    size >>= 4;
    while size > 0 {
        first |= 0x80;
        out.push(first);
        first = (size as u8) & 0x7f;
        size >>= 7;
    }
    out.push(first);
    out
}

/// 解析 ofs-delta 的负偏移编码
pub fn parse_ofs_distance(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut i = pos;
    let mut c = *data.get(i)?;
    i += 1;
    let mut off: u64 = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *data.get(i)?;
        i += 1;
        off = ((off + 1) << 7) | (c & 0x7f) as u64;
    }
    Some((off, i - pos))
}

/// 编码 ofs-delta 距离（测试构造用）
pub fn encode_ofs_distance(off: u64) -> Vec<u8> {
    let mut bytes = vec![(off & 0x7f) as u8];
    let mut rest = off >> 7;
    while rest > 0 {
        rest -= 1;
        bytes.push(((rest & 0x7f) as u8) | 0x80);
        rest >>= 7;
    }
    bytes.reverse();
    bytes
}

/// 解析 git delta 头部的 varint (little-endian 7bit)
pub fn parse_delta_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut i = pos;
    let mut shift = 0u32;
    let mut val: u64 = 0;
    loop {
        let c = *data.get(i)?;
        i += 1;
        val |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return None;
        }
    }
    Some((val, i - pos))
}

pub fn encode_delta_varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

/// 截断预览：可打印 UTF-8 视为文本，否则 hexdump
pub fn preview(content: &[u8], max: usize) -> (bool, String) {
    let slice = &content[..content.len().min(max)];
    if let Ok(s) = std::str::from_utf8(slice) {
        if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') {
            return (true, s.to_string());
        }
    }
    let mut out = String::new();
    for (i, chunk) in slice.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }
        out.push('\n');
    }
    (false, out)
}
