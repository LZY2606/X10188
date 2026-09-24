//! Git loose object 解析：zlib("<type> <size>\\0" + content)。

use anyhow::{bail, Result};
use crate::pack::{inflate_bound, EntryKind};

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: EntryKind,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: String,
}

pub fn looks_like_loose(data: &[u8]) -> bool {
    // zlib 头：0x78 0x01/0x9c/0xda 最常见；宽松判断 CMF/FLG 校验
    data.len() >= 2 && data[0] & 0x0f == 8 && ((data[0] as u16) << 8 | data[1] as u16) % 31 == 0
}

pub fn parse_loose(data: &[u8]) -> Result<LooseObject> {
    let (inflated, _) = inflate_bound(data)?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("loose 对象头缺少 NUL 分隔"))?;
    let header = std::str::from_utf8(&inflated[..nul])
        .map_err(|_| anyhow::anyhow!("loose 对象头不是 UTF-8"))?;
    let (kind_s, size_s) = header
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("loose 对象头格式错误"))?;
    let kind = EntryKind::from_name(kind_s)
        .filter(|k| !k.is_delta())
        .ok_or_else(|| anyhow::anyhow!("未知 loose 对象类型 {kind_s}"))?;
    let declared_size: u64 = size_s.parse().map_err(|_| anyhow::anyhow!("大小字段非法"))?;
    let content = inflated[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        bail!("大小欺骗: 声明 {declared_size} 实际 {}", content.len());
    }
    let oid = crate::gitutil::git_oid(kind.name(), &content);
    Ok(LooseObject { kind, declared_size, content, oid })
}
