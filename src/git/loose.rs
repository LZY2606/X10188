//! loose object 解析：`<type> <size>\0` 头 + zlib 压缩体。

use super::zlib::inflate_zlib;
use super::{Error, ObjType, Result};

#[derive(Clone, Debug)]
pub struct LooseInfo {
    pub ty: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    /// zlib 流相对文件起点的字节范围。
    pub z_start: u64,
    pub z_end: u64,
    pub header_len: usize,
}

const INFLATE_HARD_LIMIT: usize = 512 * 1024 * 1024;

pub fn parse_loose(data: &[u8]) -> Result<LooseInfo> {
    let nul = data
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::Loose("loose 对象缺少 NUL 头分隔".into()))?;
    let header = std::str::from_utf8(&data[..nul])
        .map_err(|_| Error::Loose("loose 对象头不是合法 UTF-8".into()))?;
    let mut parts = header.split(' ');
    let ty_name = parts.next().ok_or_else(|| Error::Loose("对象头缺类型".into()))?;
    let size_str = parts.next().ok_or_else(|| Error::Loose("对象头缺大小".into()))?;
    let ty = ObjType::from_loose_name(ty_name)
        .ok_or_else(|| Error::Loose(format!("未知 loose 类型 {}", ty_name)))?;
    let declared: u64 = size_str
        .parse()
        .map_err(|_| Error::Loose(format!("对象大小不是数字: {}", size_str)))?;

    let z_start = nul + 1;
    let infl = inflate_zlib(&data[z_start..], INFLATE_HARD_LIMIT, Some(declared))?;
    Ok(LooseInfo {
        ty,
        declared_size: declared,
        content: infl.data,
        z_start: z_start as u64,
        z_end: (z_start + infl.consumed) as u64,
        header_len: z_start,
    })
}
