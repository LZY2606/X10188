//! Loose object (`zlib("<type> <len>\\0<body>")`) reader.

use super::{inflate_limited, GitType};

/// A successfully decoded loose object.
#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: GitType,
    pub content: Vec<u8>,
}

/// Decode a loose object file, verifying its declared header.
pub fn parse_loose(data: &[u8], cap: u64) -> Result<LooseObject, String> {
    let raw = inflate_limited(data, cap)?;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL header terminator".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|e| format!("loose object header not utf-8: {e}"))?;
    let (name, len_str) = header
        .split_once(' ')
        .ok_or_else(|| "loose object header missing space".to_string())?;
    let kind = match name {
        "commit" => GitType::Commit,
        "tree" => GitType::Tree,
        "blob" => GitType::Blob,
        "tag" => GitType::Tag,
        other => return Err(format!("loose object has invalid type '{other}'")),
    };
    let declared: u64 = len_str
        .parse()
        .map_err(|e| format!("loose object length '{len_str}' invalid: {e}"))?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared {
        return Err(format!(
            "loose object size spoof: header says {declared}, body is {} bytes",
            content.len()
        ));
    }
    Ok(LooseObject { kind, content })
}
