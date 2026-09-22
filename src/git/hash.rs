//! Git object-id (SHA-1) helpers.

use sha1_smol::Sha1;

/// Compute the Git object id for raw content of `type_name`.
/// The hashed stream is `"<type> <len>\0<content>"`.
pub fn object_id(type_name: &str, content: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(type_name.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.digest().bytes());
    out
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.digest().bytes())
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.digest().bytes());
    out
}

pub fn to_hex(id: &[u8; 20]) -> String {
    hex::encode(id)
}

pub fn parse_hex(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(s.trim()).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}
