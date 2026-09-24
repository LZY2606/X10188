//! Git object framing, type ids and object-id (SHA-1) computation.

use sha1::{Digest, Sha1};

/// Pack object type codes exactly as they appear in the 3-bit type field.
pub mod ptype {
    pub const COMMIT: u8 = 1;
    pub const TREE: u8 = 2;
    pub const BLOB: u8 = 3;
    pub const TAG: u8 = 4;
    pub const OFS_DELTA: u8 = 6;
    pub const REF_DELTA: u8 = 7;
}

pub fn type_name(t: u8) -> &'static str {
    match t {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        6 => "ofs_delta",
        7 => "ref_delta",
        _ => "unknown",
    }
}

pub fn type_from_name(name: &str) -> Option<u8> {
    Some(match name {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => return None,
    })
}

/// Content as stored loose on disk: `<type> <len>\0<content>`.
pub fn framed(type_code: u8, content: &[u8]) -> Vec<u8> {
    let name = type_name(type_code);
    let mut v = format!("{} {}\0", name, content.len()).into_bytes();
    v.extend_from_slice(content);
    v
}

/// Git object id = SHA-1 over the framed object.
pub fn object_id(type_code: u8, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(&framed(type_code, content));
    let r = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&r);
    oid
}

pub fn hex(oid: &[u8]) -> String {
    let mut s = String::with_capacity(oid.len() * 2);
    for b in oid {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
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

/// Split a framed loose object into `(type, content)`.
pub fn split_frame(buf: &[u8]) -> Option<(u8, &[u8])> {
    let nul = buf.iter().position(|&b| b == 0)?;
    let head = std::str::from_utf8(&buf[..nul]).ok()?;
    let mut it = head.split(' ');
    let name = it.next()?;
    let len: usize = it.next()?.parse().ok()?;
    let body = &buf[nul + 1..];
    if body.len() != len {
        return None;
    }
    Some((type_from_name(name)?, body))
}
