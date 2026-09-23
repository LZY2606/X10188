use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

pub fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Git object id: sha1 of "<type> <len>\0" + content
pub fn git_oid(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}", type_name, content.len()).as_bytes());
    h.update(&[0u8]);
    h.update(content);
    hex_encode(&h.finalize())
}

pub fn sha1_hex(b: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(b);
    hex_encode(&h.finalize())
}

pub fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex_encode(&h.finalize())
}

pub fn crc32_hex(b: &[u8]) -> u32 {
    crc32fast::hash(b)
}
