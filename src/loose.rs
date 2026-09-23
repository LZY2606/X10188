use crate::pack::inflate_bounded;
use crate::util;

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub type_name: String,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: String,
    pub size_ok: bool,
}

/// Parse a zlib-compressed loose object: "<type> <size>\0<content>".
pub fn parse_loose(data: &[u8]) -> Result<LooseObject, String> {
    let (inflated, _consumed) = inflate_bounded(data)?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose object missing header NUL".to_string())?;
    let header = std::str::from_utf8(&inflated[..nul])
        .map_err(|_| "loose header not utf8".to_string())?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().unwrap_or("").to_string();
    let declared_size: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "loose header missing size".to_string())?;
    if !matches!(type_name.as_str(), "commit" | "tree" | "blob" | "tag") {
        return Err(format!("unknown loose object type '{}'", type_name));
    }
    let content = inflated[nul + 1..].to_vec();
    let size_ok = content.len() as u64 == declared_size;
    let oid = util::git_oid(&type_name, &content);
    Ok(LooseObject { type_name, declared_size, content, oid, size_ok })
}
