//! Loose object 解析：zlib("<type> <size>\0" + content)。
use crate::zlib;

pub struct ParsedLoose {
    pub type_name: String,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub consumed: usize,
}

pub fn parse_loose(bytes: &[u8]) -> Result<ParsedLoose, String> {
    // loose 对象一般很小；声明大小未知，先用硬上限解压头部
    let inf = zlib::inflate_limited(bytes, zlib::HARD_CAP - 1)?;
    let nul = inf
        .data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象头缺少 NUL 分隔".to_string())?;
    let header = std::str::from_utf8(&inf.data[..nul])
        .map_err(|_| "loose 对象头非 UTF-8".to_string())?;
    let mut it = header.splitn(2, ' ');
    let type_name = it.next().unwrap_or("").to_string();
    let size_str = it.next().ok_or_else(|| "loose 对象头缺少大小".to_string())?;
    let declared_size: u64 = size_str
        .trim()
        .parse()
        .map_err(|_| format!("loose 对象头大小非法: {size_str}"))?;
    match type_name.as_str() {
        "commit" | "tree" | "blob" | "tag" => {}
        t => return Err(format!("loose 对象类型未知: {t}")),
    }
    let content = inf.data[nul + 1..].to_vec();
    Ok(ParsedLoose {
        type_name,
        declared_size,
        content,
        consumed: inf.consumed,
    })
}
