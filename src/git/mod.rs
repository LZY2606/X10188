//! 从零实现的 Git 对象/pack/index/loose 解析，不依赖系统 git。

pub mod delta;
pub mod idx;
pub mod loose;
pub mod oid;
pub mod pack;
pub mod zlib;

/// pack 内对象类型。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(c: u8) -> Option<ObjType> {
        match c {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn code(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn from_loose_name(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("pack 格式错误: {0}")]
    Pack(String),
    #[error("zlib 错误: {0}")]
    Zlib(String),
    #[error("delta 错误: {0}")]
    Delta(String),
    #[error("index 格式错误: {0}")]
    Idx(String),
    #[error("loose object 错误: {0}")]
    Loose(String),
    #[error("大小欺骗: {0}")]
    SizeLie(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn take<'a>(buf: &'a [u8], pos: &mut usize) -> Result<u8> {
    if *pos >= buf.len() {
        return Err(Error::Pack("数据截断".into()));
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

/// pack 对象头 / delta 头使用的 7 位变长整数。
pub fn read_size_encoding(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let c = take(data, pos)?;
        result |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::Pack("size encoding 过长".into()));
        }
    }
    Ok(result)
}

/// 读取 pack entry 头，返回 (类型, 声明的解压后大小)。
pub fn read_pack_entry_header(buf: &[u8], pos: &mut usize) -> Result<(ObjType, u64)> {
    let c = take(buf, pos)?;
    let type_code = (c >> 4) & 0x7;
    let ty = ObjType::from_pack_code(type_code)
        .ok_or_else(|| Error::Pack(format!("未知 pack 对象类型 {}", type_code)))?;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cur = c;
    while cur & 0x80 != 0 {
        cur = take(buf, pos)?;
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((ty, size))
}

/// ofs-delta 的负偏移编码，返回相对当前对象头的距离。
pub fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut c = take(data, pos)?;
    let mut dist = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = take(data, pos)?;
        dist = dist
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| Error::Pack("ofs 距离溢出".into()))?;
        dist |= (c & 0x7f) as u64;
    }
    Ok(dist)
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for b in oid {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn parse_oid(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi << 4 | lo) as u8;
    }
    Some(out)
}
