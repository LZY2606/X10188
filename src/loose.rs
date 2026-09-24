//! Loose object parsing: zlib stream of "{type} {len}\\0{content}".

use crate::gitobj::{object_id, ObjType};
use crate::inflate::inflate_bounded;

#[derive(Debug)]
pub struct LooseParse {
    pub oid: String,
    pub typ: ObjType,
    pub content: Vec<u8>,
    pub declared_size: u64,
}

pub fn parse_loose(data: &[u8], inflate_limit: u64) -> Result<LooseParse, String> {
    let inflated = inflate_bounded(data, inflate_limit).map_err(|e| format!("zlib 解压失败: {e}"))?;
    let raw = inflated.data;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象头缺少 NUL 分隔符".to_string())?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 对象头不是 UTF-8".to_string())?;
    let (typ_name, size_str) = header
        .split_once(' ')
        .ok_or_else(|| format!("loose 对象头格式错误: {header:?}"))?;
    let typ = match typ_name {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(format!("未知 loose 对象类型 {other:?}")),
    };
    let declared_size: u64 = size_str
        .parse()
        .map_err(|_| format!("loose 对象头大小字段非法: {size_str:?}"))?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(format!(
            "loose 对象大小欺骗: 头声明 {declared_size}，实际 {}",
            content.len()
        ));
    }
    let oid = object_id(typ, &content);
    Ok(LooseParse {
        oid,
        typ,
        content,
        declared_size,
    })
}
