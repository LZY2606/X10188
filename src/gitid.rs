//! Git object-id computation and hex helpers.

use sha1::{Digest, Sha1};

use crate::types::GitType;

/// Compute the SHA-1 object id a base object would have loose.
pub fn git_object_id(kind: GitType, content: &[u8]) -> [u8; 20] {
    let name = kind
        .loose_name()
        .expect("git_object_id only applies to base object types");
    let mut h = Sha1::new();
    h.update(name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

pub fn to_hex(id: &[u8]) -> String {
    let mut s = String::with_capacity(id.len() * 2);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Short, human-friendly label for an unknown delta candidate.
pub fn short_hex(id: &[u8]) -> String {
    let h = to_hex(id);
    if h.len() <= 12 {
        h
    } else {
        h[..12].to_string()
    }
}
