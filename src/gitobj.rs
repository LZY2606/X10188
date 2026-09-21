use sha1::{Digest, Sha1};

/// Recompute the Git object id: sha1("<type> <len>\0" + content).
pub fn object_id(obj_type: &str, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(obj_type.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    hex::encode(hasher.finalize())
}

pub fn type_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("commit"),
        2 => Some("tree"),
        3 => Some("blob"),
        4 => Some("tag"),
        6 => Some("ofs-delta"),
        7 => Some("ref-delta"),
        _ => None,
    }
}

pub fn is_delta(type_name: &str) -> bool {
    type_name == "ofs-delta" || type_name == "ref-delta"
}
