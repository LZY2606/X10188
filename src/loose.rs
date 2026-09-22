//! Loose object 解析（zlib 压缩的 "type size\0content"）。

use crate::pack::{git_oid, inflate_all, ObjType};

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: String,
    /// zlib 流消耗的字节数（边界）
    pub consumed: usize,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseObject, String> {
    let (raw, consumed) = inflate_all(data)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object 缺少 \\0 分隔符")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let (tname, size_s) = header
        .split_once(' ')
        .ok_or_else(|| format!("loose 头部格式错误: {header}"))?;
    let obj_type = match tname {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(format!("未知 loose 类型 {other}")),
    };
    let declared_size: u64 = size_s
        .parse()
        .map_err(|_| format!("loose 声明大小非法: {size_s}"))?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(format!(
            "大小欺骗：loose 声明 {declared_size} 字节，实际 {} 字节",
            content.len()
        ));
    }
    let oid = git_oid(tname, &content);
    Ok(LooseObject { obj_type, declared_size, content, oid, consumed })
}
