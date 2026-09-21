use sha1::{Digest, Sha1};

/// Recompute the Git object id for a fully reconstructed object.
pub fn git_oid(otype: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}", otype, content.len()).as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Pack object type code -> canonical Git type name (delta types excluded).
pub fn type_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("commit"),
        2 => Some("tree"),
        3 => Some("blob"),
        4 => Some("tag"),
        _ => None,
    }
}

pub fn type_label(code: u8) -> &'static str {
    match code {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        6 => "ofs-delta",
        7 => "ref-delta",
        _ => "unknown",
    }
}
