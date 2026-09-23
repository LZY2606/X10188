//! Loose object file parsing.
use crate::gitobj::inflate_all;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LooseObject {
    pub kind: String,
    pub content: Vec<u8>,
    pub oid: String,
}

pub fn parse_loose(buf: &[u8]) -> Result<LooseObject, String> {
    let raw = inflate_all(buf, 512 * 1024 * 1024)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "bad loose header")?;
    let mut parts = header.splitn(2, ' ');
    let kind = parts.next().ok_or("loose header missing type")?;
    if !matches!(kind, "commit" | "tree" | "blob" | "tag") {
        return Err(format!("unknown loose object type '{}'", kind));
    }
    let size: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("loose header missing size")?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "size deception: loose header says {} bytes, content has {}",
            size,
            content.len()
        ));
    }
    let oid = crate::gitobj::object_id(kind, &content);
    Ok(LooseObject {
        kind: kind.to_string(),
        content,
        oid,
    })
}
