use crate::pack::zlib_decompress;

/// 解析 loose object: zlib("<type> <len>\0" + content)
pub fn parse_loose(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let (raw, _consumed) = zlib_decompress(data, 512 * 1024 * 1024)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object 缺少头部 NUL 分隔")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().ok_or("loose 头部缺少类型")?;
    let size: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("loose 头部缺少合法大小")?;
    match type_name {
        "commit" | "tree" | "blob" | "tag" => {}
        other => return Err(format!("未知 loose 类型 {other}")),
    }
    let content = &raw[nul + 1..];
    if content.len() as u64 != size {
        return Err(format!(
            "loose 大小欺骗: 头部声明 {size} 字节, 实际 {} 字节",
            content.len()
        ));
    }
    Ok((type_name.to_string(), content.to_vec()))
}
