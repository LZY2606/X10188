//! Loose object parser (`<type> <size>\0<zlib body>`).

use crate::git::{object_id, GitType};
use crate::zlib_util::{inflate_one, InflateError};

pub const LOOSE_MAX_INFLATE: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub declared_type: String,
    pub declared_size: u64,
    pub body: Vec<u8>,
    pub compressed_len: usize,
    pub adler_ok: bool,
    pub computed_oid: [u8; 20],
    pub header_ok: bool,
    pub issue: Option<String>,
    pub content_sha256: String,
}

pub fn parse_loose(raw: &[u8]) -> Result<ParsedLoose, String> {
    use sha2::Digest;
    let inf = match inflate_one(raw, LOOSE_MAX_INFLATE) {
        Ok(v) => v,
        Err(InflateError::Corrupt(m)) => return Err(format!("zlib stream corrupt: {m}")),
        Err(InflateError::ExceedsMaxOutput { produced }) => {
            return Err(format!("inflated size exceeded cap (produced {produced})"))
        }
    };
    let nul = inf
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or("missing NUL in loose object header")?;
    let header = std::str::from_utf8(&inf.data[..nul]).map_err(|_| "non-utf8 loose header")?;
    let (type_name, size_str) = header
        .split_once(' ')
        .ok_or("loose header missing '<type> <size>'")?;
    let ty = GitType::from_loose_name(type_name).ok_or(format!("unknown type {type_name}"))?;
    let declared_size: u64 = size_str.parse().map_err(|_| "bad size in loose header")?;
    let body = inf.data[nul + 1..].to_vec();

    let computed = object_id(ty, &body);
    let header_ok = body.len() as u64 == declared_size;
    let mut h = sha2::Sha256::new();
    h.update(&body);
    let content_sha256 = hex::encode(h.finalize());

    let mut issue = None;
    if !header_ok {
        issue = Some(format!(
            "loose header claims {declared_size} bytes but body is {} bytes",
            body.len()
        ));
    }

    Ok(ParsedLoose {
        declared_type: type_name.to_string(),
        declared_size,
        body,
        compressed_len: inf.compressed_len,
        adler_ok: inf.adler_ok,
        computed_oid: computed,
        header_ok,
        issue,
        content_sha256,
    })
}
