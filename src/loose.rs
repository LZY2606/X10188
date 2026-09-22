//! Parsers for loose objects: zlib-compressed `<type> <size>\0<content>`.

use crate::gitio::{inflate_at, ObjType};

#[derive(Debug, Clone)]
pub struct LooseInfo {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub size_ok: bool,
    pub zlib_ok: bool,
    pub inflate_error: Option<String>,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseInfo, String> {
    let inf = inflate_at(data, 0);
    let raw = inf.data;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL header terminator".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "loose object header is not valid UTF-8".to_string())?;
    let (name, num) = header
        .split_once(' ')
        .ok_or_else(|| format!("loose object header malformed: {header:?}"))?;
    let obj_type = match name {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        _ => return Err(format!("loose object has unsupported type {name:?}")),
    };
    let declared_size: u64 = num
        .parse()
        .map_err(|_| format!("loose object size not numeric: {num:?}"))?;
    let content = raw[nul + 1..].to_vec();
    Ok(LooseInfo {
        obj_type,
        declared_size,
        size_ok: declared_size as usize == content.len(),
        zlib_ok: inf.stream_end && inf.error.is_none(),
        inflate_error: inf.error,
        content,
    })
}
