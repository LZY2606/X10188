use crate::gitobj::ObjType;
use crate::zlib;

pub const LOOSE_SLACK: usize = 32;

pub struct LooseObject {
    pub kind: ObjType,
    pub body: Vec<u8>,
}

/// Parse a loose object: zlib("<type> <size>\0<body>").
pub fn parse_loose(data: &[u8], max_size: usize) -> Result<LooseObject, String> {
    let inflated = zlib::inflate_exact(data, max_size, LOOSE_SLACK).map_err(|e| e.to_string())?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose object missing NUL after header".to_string())?;
    let header = std::str::from_utf8(&inflated[..nul]).map_err(|e| e.to_string())?;
    let mut parts = header.splitn(2, ' ');
    let kind_s = parts.next().ok_or("loose header missing type")?;
    let size_s = parts.next().ok_or("loose header missing size")?;
    let kind = ObjType::from_name(kind_s).ok_or_else(|| format!("unknown type {}", kind_s))?;
    let declared: usize = size_s.parse().map_err(|_| "bad size in loose header".to_string())?;
    let body = inflated[nul + 1..].to_vec();
    if body.len() != declared {
        return Err(format!(
            "size spoof: loose header declares {} but body is {}",
            declared,
            body.len()
        ));
    }
    Ok(LooseObject { kind, body })
}
