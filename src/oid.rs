use sha1::{Digest, Sha1};

pub type Oid = [u8; 20];

pub fn to_hex(oid: &Oid) -> String {
    hex::encode(oid)
}

pub fn from_hex(s: &str) -> Option<Oid> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

/// Git object id = SHA1("{kind} {len}\\0{content}")
pub fn object_id(kind: &str, content: &[u8]) -> Oid {
    let mut hasher = Sha1::new();
    hasher.update(format!("{} {}\0", kind, content.len()).as_bytes());
    hasher.update(content);
    hasher.finalize().into()
}

pub fn sha1_raw(data: &[u8]) -> Oid {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}
