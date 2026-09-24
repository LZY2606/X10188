pub mod delta;
pub mod pack;
pub mod resolve;
pub mod store;
pub mod web;

use sha1::{Digest, Sha1};

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

pub fn git_oid(type_name: &str, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(type_name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().into_bytes());
    h.update(b"\0");
    h.update(content);
    let r = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&r);
    oid
}

pub fn type_name(kind: u8) -> &'static str {
    match kind {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        6 => "ofs_delta",
        7 => "ref_delta",
        _ => "unknown",
    }
}

pub fn is_base_kind(kind: u8) -> bool {
    matches!(kind, 1 | 2 | 3 | 4)
}
