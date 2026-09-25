//! Loose object file parsing ("<type> <size>\0<content>", zlib compressed).

use crate::gitobj::{zlib_decompress_all, ObjType};

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseObject, String> {
    let raw = zlib_decompress_all(data)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose header not utf8")?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().ok_or("loose header missing type")?;
    let size_str = parts.next().ok_or("loose header missing size")?;
    let obj_type = ObjType::from_name(type_name)
        .filter(|t| !t.is_delta())
        .ok_or_else(|| format!("bad loose object type '{type_name}'"))?;
    let declared_size: u64 = size_str
        .parse()
        .map_err(|_| format!("bad loose object size '{size_str}'"))?;
    let content = raw[nul + 1..].to_vec();
    Ok(LooseObject {
        obj_type,
        declared_size,
        content,
    })
}
