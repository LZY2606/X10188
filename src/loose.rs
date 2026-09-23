//! Loose object 解析：zlib("<type> <size>\\0" + content)。
use crate::gitutil;

#[derive(Debug)]
pub struct LooseParse {
    pub kind: String,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: String,
    pub error: Option<String>,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseParse, String> {
    let inf = gitutil::inflate(data, Some(gitutil::MAX_INFLATE as usize))
        .map_err(|e| format!("not a loose object: {e}"))?;
    let nul = inf
        .data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose header missing NUL".to_string())?;
    let header = std::str::from_utf8(&inf.data[..nul])
        .map_err(|_| "loose header not utf8".to_string())?;
    let (kind, size_s) = header
        .split_once(' ')
        .ok_or_else(|| "bad loose header".to_string())?;
    if !matches!(kind, "blob" | "commit" | "tree" | "tag") {
        return Err(format!("unknown loose type {kind}"));
    }
    let declared: u64 = size_s.parse().map_err(|_| "bad loose size".to_string())?;
    let content = inf.data[nul + 1..].to_vec();
    let error = if content.len() as u64 != declared {
        Some(format!(
            "size_mismatch: declared {declared}, actual {}",
            content.len()
        ))
    } else {
        None
    };
    let oid = gitutil::object_id(kind, &content);
    Ok(LooseParse {
        kind: kind.to_string(),
        declared_size: declared,
        content,
        oid,
        error,
    })
}
