use crate::git::object_id::hex20;
use crate::git::zdec::inflate_unbounded;
use crate::git::{GitError, ObjType};

pub struct LooseObject {
    pub obj_type: ObjType,
    pub content: Vec<u8>,
    pub header_len: usize,
    pub zlib_start: usize,
    pub zlib_end: usize,
}

pub fn parse_loose(path_oid_hex: &str, data: &[u8], hard_cap: usize)
    -> Result<LooseObject, GitError>
{
    let expected = hex20(path_oid_hex).ok_or_else(|| {
        GitError::new("bad_loose_name", "loose object filename is not a 40-hex oid")
    })?;
    let (out, range) = inflate_unbounded(data, 0, hard_cap)
        .map_err(|e| GitError::new("loose_inflate_failed", e))?;
    let nul = out
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| GitError::new("loose_bad_header", "missing NUL in loose object"))?;
    let header = std::str::from_utf8(&out[..nul])
        .map_err(|_| GitError::new("loose_bad_header", "non-UTF8 loose header"))?;
    let (name, len_s) = header
        .split_once(' ')
        .ok_or_else(|| GitError::new("loose_bad_header", "malformed loose header"))?;
    let declared_len: usize = len_s
        .parse()
        .map_err(|_| GitError::new("loose_bad_header", "bad length in loose header"))?;
    let content = out[nul + 1..].to_vec();
    if content.len() != declared_len {
        return Err(GitError::new(
            "loose_size_spoof",
            format!("header length {declared_len} but content is {} bytes", content.len()),
        ));
    }
    let obj_type = match name {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => {
            return Err(GitError::new(
                "loose_bad_type",
                format!("unknown loose type {other}"),
            ))
        }
    };
    let computed = crate::git::object_id::hash_object(obj_type, &content);
    if computed != expected {
        return Err(GitError::new(
            "loose_oid_mismatch",
            format!(
                "loose content hashes to {} but path says {}",
                hex::encode(computed),
                path_oid_hex
            ),
        ));
    }
    Ok(LooseObject {
        obj_type,
        content,
        header_len: nul + 1,
        zlib_start: range.compressed_start,
        zlib_end: range.compressed_end,
    })
}
