pub mod delta;
pub mod engine;
pub mod loose;
pub mod pack;
pub mod store;
pub mod web;

/// Compute the Git object id (sha1 of "<type> <len>\\0" + content).
pub fn git_oid(obj_type: &str, content: &[u8]) -> String {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(format!("{} {}\0", obj_type, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}
