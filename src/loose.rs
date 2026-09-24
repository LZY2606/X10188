use crate::model::ObjType;
use crate::zlib;

pub struct LooseObject {
    pub obj_type: ObjType,
    pub data: Vec<u8>,
    pub declared_size: u64,
    pub compressed_len: u64,
    pub evidence: Vec<String>,
}

/// 解析 loose object：zlib("<type> <size>\0" + content)
pub fn parse_loose(bytes: &[u8]) -> Result<LooseObject, String> {
    let (raw, consumed) = zlib::decompress_bound(bytes)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose 对象头缺少 NUL 分隔")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 对象头非 UTF-8")?;
    let (t, sz) = header.split_once(' ').ok_or("loose 对象头格式错误")?;
    let obj_type = ObjType::from_git_name(t).ok_or_else(|| format!("未知对象类型 {t}"))?;
    let declared_size: u64 = sz.parse().map_err(|_| "loose 对象头大小解析失败")?;
    let data = raw[nul + 1..].to_vec();
    let mut evidence = Vec::new();
    if data.len() as u64 != declared_size {
        evidence.push(format!(
            "大小欺骗: 头部声明 {} 字节，实际内容 {} 字节",
            declared_size,
            data.len()
        ));
    }
    if consumed != bytes.len() {
        evidence.push(format!(
            "loose 对象尾部存在 {} 字节多余数据",
            bytes.len() - consumed
        ));
    }
    Ok(LooseObject {
        obj_type,
        data,
        declared_size,
        compressed_len: consumed as u64,
        evidence,
    })
}
