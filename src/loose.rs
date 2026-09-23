//! Loose object parser: zlib("<type> <size>\\0" + content).

use crate::pack::zlib_inflate_bounded;
use crate::pack::INFLATE_HARD_CAP;

#[derive(Debug)]
pub struct LooseParse {
    pub type_name: String,
    pub content: Vec<u8>,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseParse, String> {
    let (raw, _consumed) = zlib_inflate_bounded(data, INFLATE_HARD_CAP)
        .map_err(|e| format!("loose object 解压失败: {e}"))?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object 缺少 \\0 分隔符")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let (type_name, size_s) = header
        .split_once(' ')
        .ok_or("loose 头部缺少空格分隔")?;
    let declared: u64 = size_s.parse().map_err(|_| "loose 大小字段非法")?;
    let content = raw[nul + 1..].to_vec();
    if declared != content.len() as u64 {
        return Err(format!(
            "大小欺骗: loose 声明 {declared} 字节, 实际 {}",
            content.len()
        ));
    }
    if !["commit", "tree", "blob", "tag"].contains(&type_name) {
        return Err(format!("未知 loose 类型 {type_name}"));
    }
    Ok(LooseParse {
        type_name: type_name.to_string(),
        content,
    })
}
