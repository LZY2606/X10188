use sha1::{Digest, Sha1};
use sha2::Sha256;

/// 计算 Git object id: sha1("<type> <len>\\0" + content)，返回 hex。
pub fn git_oid(kind_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(kind_name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub fn short(oid: &str, n: usize) -> String {
    oid.chars().take(n).collect()
}
