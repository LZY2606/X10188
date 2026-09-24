use crate::error::{Error, ErrorCode, R};
use crate::gitenc::read_var_size;
use crate::model::{LooseInfo, ObjKind};
use crate::zlibw::inflate_at;

pub fn parse_loose(buf: &[u8]) -> R<LooseInfo> {
    let (raw, _) = inflate_at(buf, crate::model::HARD_INFLATE_CAP)
        .map_err(|e| Error::new(ErrorCode::LooseZlibError, e.message))?;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::new(ErrorCode::LooseBadHeader, "no NUL terminator"))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| Error::new(ErrorCode::LooseBadHeader, "header not utf8"))?;
    let (name, size_str) = header
        .split_once(' ')
        .ok_or_else(|| Error::new(ErrorCode::LooseBadHeader, "header missing size"))?;
    let kind = match name {
        "commit" => ObjKind::Commit,
        "tree" => ObjKind::Tree,
        "blob" => ObjKind::Blob,
        "tag" => ObjKind::Tag,
        other => return Err(Error::new(ErrorCode::EntryTypeUnknown, format!("loose type {}", other))),
    };
    let declared: u64 = size_str
        .parse()
        .map_err(|_| Error::new(ErrorCode::LooseBadHeader, "bad size"))?;
    let content = raw[nul + 1..].to_vec();
    if declared as usize != content.len() {
        return Err(Error::new(
            ErrorCode::DeltaSizeMismatch,
            format!("loose header size {} but content {}", declared, content.len()),
        ));
    }
    Ok(LooseInfo { kind, content, inflated_size: declared })
}

pub fn encode_loose(kind: &str, content: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut header = Vec::new();
    header.extend_from_slice(kind.as_bytes());
    header.push(b' ');
    header.extend_from_slice(content.len().to_string().as_bytes());
    header.push(0);
    header.extend_from_slice(content);
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&header).unwrap();
    enc.finish().unwrap()
}
