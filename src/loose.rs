use crate::error::PError;
use crate::oid::Oid;
use crate::types::ObjKind;
use crate::zlib::inflate_unbounded;

/// 单个对象解压硬上限。
pub const LOOSE_HARD_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub kind: ObjKind,
    /// 头里声明的大小。
    pub declared_size: u64,
    pub content: Vec<u8>,
    /// zlib 流占用的压缩字节数。
    pub zlib_consumed: usize,
    /// 重新计算出的 git object id。
    pub computed_oid: Oid,
}

/// 解析 loose object：zlib 流 -> "<type> <size>\0<content>"。
pub fn parse_loose(buf: &[u8]) -> Result<ParsedLoose, PError> {
    let inf = inflate_unbounded(buf, LOOSE_HARD_LIMIT)?;
    let raw = &inf.data;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| PError::LooseHeader("缺少 NUL 分隔符".to_string()))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| PError::LooseHeader("头部不是合法 UTF-8".to_string()))?;
    let mut parts = header.splitn(2, ' ');
    let kind_word = parts
        .next()
        .ok_or_else(|| PError::LooseHeader("缺少类型".to_string()))?;
    let size_str = parts
        .next()
        .ok_or_else(|| PError::LooseHeader("缺少大小".to_string()))?;
    let kind = ObjKind::from_word(kind_word.as_bytes())
        .ok_or_else(|| PError::LooseHeader(format!("未知类型 {}", kind_word)))?;
    let declared_size: u64 = size_str
        .parse()
        .map_err(|_| PError::LooseHeader(format!("大小不是数字: {}", size_str)))?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(PError::SizeSpoof {
            declared: declared_size,
            actual: content.len() as u64,
        });
    }
    let computed_oid = crate::git::git_object_id(kind, &content);
    Ok(ParsedLoose {
        kind,
        declared_size,
        content,
        zlib_consumed: inf.consumed,
        computed_oid,
    })
}
