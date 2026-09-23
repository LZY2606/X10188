use sha1::{Digest, Sha1};

use crate::git::ObjType;

/// Recompute a Git object id: sha1("<type> <len>\0<content>").
pub fn hash_object(ty: ObjType, content: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", ty.header_name().unwrap(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn hex20(s: &str) -> Option<[u8; 20]> {
    let b = s.as_bytes();
    if b.len() != 40 || !b.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn to_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn oid_matches(oid: &[u8; 20], prefix: &[u8]) -> bool {
    if prefix.len() != 20 {
        return false;
    }
    oid.as_slice() == prefix
}

pub fn crc32_zlib_bytes(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
