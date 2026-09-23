use sha1::{Digest, Sha1};

pub const TYPE_NAMES: [&str; 8] = [
    "none", "commit", "tree", "blob", "tag", "reserved", "ofs_delta", "ref_delta",
];

pub fn type_name(code: u8) -> &'static str {
    TYPE_NAMES
        .get(code as usize)
        .copied()
        .unwrap_or("unknown")
}

pub fn is_delta(code: u8) -> bool {
    code == 6 || code == 7
}

/// Compute the Git object id (SHA-1 of "<type> <len>\0" + content).
pub fn object_id(type_name: &str, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(format!("{} {}", type_name, content.len()).as_bytes());
    h.update([0u8]);
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn parse_oid_hex(s: &str) -> Option<[u8; 20]> {
    let b = hex::decode(s).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&b);
    Some(oid)
}
