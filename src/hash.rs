use crate::oid::Oid;
use crate::types::GitType;
use sha1::{Digest, Sha1};

/// 计算 Git object id：sha1("<type> <len>\\0" + payload)
pub fn object_id(kind: GitType, payload: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.as_str().as_bytes());
    h.update(b" ");
    h.update(payload.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(payload);
    Oid(h.finalize().into())
}

pub fn sha1_hex(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}
