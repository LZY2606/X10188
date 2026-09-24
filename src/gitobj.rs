//! Git 对象封装：`"<type> <size>\0<content>"` 与 object id (SHA-1) 计算。

use sha1::{Digest, Sha1};

use crate::oid::ObjType;

/// 计算 loose / canonical git 对象的 SHA-1 object id。
pub fn hash_object(obj_type: ObjType, content: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", obj_type.name(), content.len());
    let mut h = Sha1::new();
    Digest::update(&mut h, header.as_bytes());
    Digest::update(&mut h, content);
    h.finalize().into()
}

/// 将 canonical 对象封装成 loose 存储格式（可选择 zlib 压缩）。
pub fn wrap_object(obj_type: ObjType, content: &[u8]) -> Vec<u8> {
    let header = format!("{} {}\0", obj_type.name(), content.len());
    let mut out = Vec::with_capacity(header.len() + content.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(content);
    out
}

/// 解开 loose 对象：校验头部大小并返回类型与内容。
pub fn unwrap_object(raw: &[u8]) -> Result<(ObjType, Vec<u8>), String> {
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象缺少 NUL 头部分隔符".to_string())?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|e| format!("头部非 UTF-8: {e}"))?;
    let (t, size) = header
        .split_once(' ')
        .ok_or_else(|| "loose 头部格式应为 '<type> <size>'".to_string())?;
    let ty = match t {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(format!("未知 loose 对象类型 {other}")),
    };
    let declared: usize = size
        .parse()
        .map_err(|_| format!("loose 头部大小不是数字: {size}"))?;
    let body = raw[nul + 1..].to_vec();
    if body.len() != declared {
        return Err(format!(
            "loose 大小欺骗：头部声明 {declared} 字节，实际 {} 字节",
            body.len()
        ));
    }
    Ok((ty, body))
}
