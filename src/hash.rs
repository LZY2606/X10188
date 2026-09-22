use sha1::{Digest, Sha1};
use sha2::Sha256;

pub fn sha1_hex(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn oid_from_hex(value: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}
