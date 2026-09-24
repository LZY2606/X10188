//! loose object 解析：zlib("<type> <size>\0" + content)

use crate::gitutil::ObjType;
use crate::pack::inflate_bounded;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub otype: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub size_spoofed: bool,
    pub compressed_len: u64,
}

pub fn parse_loose(data: &[u8]) -> Result<ParsedLoose, String> {
    let (raw, consumed) = inflate_bounded(data, 256 * 1024 * 1024)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose object 缺少头部 NUL".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "loose object 头部非 UTF-8".to_string())?;
    let mut parts = header.splitn(2, ' ');
    let tname = parts.next().ok_or("loose object 头部缺少类型")?;
    let otype = ObjType::from_str(tname).ok_or_else(|| format!("未知 loose 类型 {tname}"))?;
    if otype.is_delta() {
        return Err("loose object 不应是 delta 类型".to_string());
    }
    let declared_size: u64 = parts
        .next()
        .ok_or("loose object 头部缺少大小")?
        .parse()
        .map_err(|_| "loose object 大小非法")?;
    let content = raw[nul + 1..].to_vec();
    let size_spoofed = content.len() as u64 != declared_size;
    Ok(ParsedLoose {
        otype,
        declared_size,
        content,
        size_spoofed,
        compressed_len: consumed,
    })
}
