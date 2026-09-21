use sha1::{Digest, Sha1};

pub type Oid = [u8; 20];

/// 计算 Git object id: sha1("<type> <len>\0" + content)
pub fn object_id(obj_type: &str, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(obj_type.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn sha1_bytes(data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn to_hex(oid: &Oid) -> String {
    hex::encode(oid)
}

pub fn from_hex(s: &str) -> Option<Oid> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&b);
    Some(oid)
}

pub fn short(oid_hex: &str) -> String {
    oid_hex.chars().take(10).collect()
}
