use sha1::{Digest, Sha1};

use crate::git::types::ObjectType;

/// Computes the git object id for inflated payload bytes:
/// `sha1("<type> <len>\0<payload>")`.
pub fn git_id(kind: ObjectType, payload: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", kind.as_str(), payload.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(payload);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn to_hex(id: &[u8; 20]) -> String {
    hex::encode(id)
}

pub fn from_hex(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}
