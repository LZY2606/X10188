//! loose object：zlib 压缩的 `<type> <size>\0<content>`。

use super::ObjType;
use flate2::read::ZlibDecoder;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: ObjType,
    pub content: Vec<u8>,
    pub declared_size: u64,
    pub errors: Vec<String>,
}

pub fn parse(data: &[u8]) -> std::io::Result<LooseObject> {
    let mut dec = ZlibDecoder::new(data);
    let mut raw = Vec::new();
    if let Err(e) = dec.read_to_end(&mut raw) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("loose zlib error: {}", e),
        ));
    }
    let nul = raw.iter().position(|b| *b == 0).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "loose header missing NUL")
    })?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "loose header not utf8")
    })?;
    let (name, size_str) = header
        .split_once(' ')
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "loose header bad"))?;
    let kind = ObjType::from_name(name).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unknown loose type {}", name))
    })?;
    let declared_size: u64 = size_str.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "loose size not a number")
    })?;
    let content = raw[nul + 1..].to_vec();
    let mut errors = Vec::new();
    if declared_size != content.len() as u64 {
        errors.push(format!(
            "loose size spoof: header declared {}, actual {}",
            declared_size,
            content.len()
        ));
    }
    Ok(LooseObject {
        kind,
        content,
        declared_size,
        errors,
    })
}
