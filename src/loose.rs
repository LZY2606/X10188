use serde::Serialize;

use crate::encoding::{git_object_id, zlib_inflate_range};
use crate::types::GitType;

#[derive(Clone, Debug, Serialize)]
pub struct LooseInfo {
    /// Oid implied by the storage path (first dir + file name).
    pub claimed_oid_hex: String,
    pub kind_name: String,
    pub declared_size: u64,
    pub content_len: usize,
    pub zlib_start: u64,
    pub zlib_end: u64,
    pub computed_oid_hex: String,
    pub oid_ok: bool,
    #[serde(skip)]
    pub content: Vec<u8>,
    pub error: Option<String>,
}

/// Parse a loose object file. `claimed_hex` is the 40-hex oid from the path.
pub fn parse_loose(data: &[u8], claimed_hex: &str) -> LooseInfo {
    let inflate = match zlib_inflate_range(data) {
        Ok((out, used)) => (out, used),
        Err(e) => {
            return LooseInfo {
                claimed_oid_hex: claimed_hex.into(),
                kind_name: String::new(),
                declared_size: 0,
                content_len: 0,
                zlib_start: 0,
                zlib_end: 0,
                computed_oid_hex: String::new(),
                oid_ok: false,
                content: Vec::new(),
                error: Some(e),
            }
        }
    };
    let (raw, used) = inflate;
    let nul = match raw.iter().position(|&b| b == 0) {
        Some(n) => n,
        None => {
            return LooseInfo {
                claimed_oid_hex: claimed_hex.into(),
                kind_name: String::new(),
                declared_size: 0,
                content_len: 0,
                zlib_start: 0,
                zlib_end: used as u64,
                computed_oid_hex: String::new(),
                oid_ok: false,
                content: Vec::new(),
                error: Some("loose object missing NUL header terminator".into()),
            }
        }
    };
    let header = String::from_utf8_lossy(&raw[..nul]);
    let mut parts = header.splitn(2, ' ');
    let kind_name = parts.next().unwrap_or("").to_string();
    let declared: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
    let content = raw[nul + 1..].to_vec();

    let kind = match kind_name.as_str() {
        "commit" => GitType::Commit,
        "tree" => GitType::Tree,
        "blob" => GitType::Blob,
        "tag" => GitType::Tag,
        other => {
            return LooseInfo {
                claimed_oid_hex: claimed_hex.into(),
                kind_name: other.into(),
                declared_size: declared,
                content_len: content.len(),
                zlib_start: 0,
                zlib_end: used as u64,
                computed_oid_hex: String::new(),
                oid_ok: false,
                content,
                error: Some(format!("unknown loose object type '{other}'")),
            }
        }
    };

    let mut error = None;
    if declared as usize != content.len() {
        error = Some(format!(
            "size spoof: header declares {declared}, actual content is {}",
            content.len()
        ));
    }
    let computed = git_object_id(kind, &content);
    let computed_hex = hex::encode(computed);
    let oid_ok = computed_hex == claimed_hex.to_lowercase();
    if !oid_ok {
        error = Some(format!(
            "loose oid mismatch: path says {claimed_hex}, content hashes to {computed_hex}"
        ));
    }

    LooseInfo {
        claimed_oid_hex: claimed_hex.into(),
        kind_name: kind.name().into(),
        declared_size: declared,
        content_len: content.len(),
        zlib_start: 0,
        zlib_end: used as u64,
        computed_oid_hex: computed_hex,
        oid_ok,
        content,
        error,
    }
}
