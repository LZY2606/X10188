use crate::inflate::inflate_prefix;

pub struct LooseInfo {
    pub type_name: String,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub compressed_len: usize,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseInfo, String> {
    let (raw, clen) = inflate_prefix(data, None)?;
    let nul = raw.iter().position(|&b| b == 0).ok_or("loose 头缺少 NUL")?;
    let header = String::from_utf8_lossy(&raw[..nul]).to_string();
    let mut it = header.splitn(2, ' ');
    let type_name = it.next().unwrap_or("").to_string();
    if crate::gitobj::type_name(match type_name.as_str() {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => 0,
    })
    .is_none()
    {
        return Err(format!("未知 loose 类型 {type_name}"));
    }
    let declared_size: u64 = it
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or("loose 头大小缺失")?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(format!(
            "大小欺骗: loose 声明 {} 实际 {}",
            declared_size,
            content.len()
        ));
    }
    Ok(LooseInfo { type_name, declared_size, content, compressed_len: clen })
}
