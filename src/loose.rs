//! Loose Git object parser: zlib stream of "<type> <size>\0<content>".
use crate::pack::{inflate_unknown, HARD_CAP};

#[derive(Debug)]
pub struct LooseParse {
    pub otype: String,
    pub size: u64,
    pub content: Vec<u8>,
    pub oid: String,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseParse, String> {
    let (raw, _used) = inflate_unknown(data, HARD_CAP)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose header not utf8")?;
    let mut parts = header.splitn(2, ' ');
    let otype = parts.next().ok_or("loose header missing type")?.to_string();
    if !matches!(otype.as_str(), "commit" | "tree" | "blob" | "tag") {
        return Err(format!("unknown loose object type '{}'", otype));
    }
    let size: u64 = parts
        .next()
        .ok_or("loose header missing size")?
        .parse()
        .map_err(|_| "loose header size not a number")?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "size deception: header says {}, content is {}",
            size,
            content.len()
        ));
    }
    let oid = crate::gitobj::git_oid(&otype, &content);
    Ok(LooseParse { otype, size, content, oid })
}
