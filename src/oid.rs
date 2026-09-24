use sha1::{Digest, Sha1};

use crate::model::ObjType;

pub type Oid = [u8; 20];

pub fn to_hex(oid: &Oid) -> String {
    let mut s = String::with_capacity(40);
    for b in oid {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn from_hex(s: &str) -> Option<Oid> {
    let s = s.trim();
    if s.len() != 40 {
        return None;
    }
    let mut oid = [0u8; 20];
    for i in 0..20 {
        oid[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(oid)
}

/// Git object id: sha1("<type> <len>\0" + content)
pub fn hash_object(obj_type: ObjType, data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", obj_type.git_name(), data.len()).as_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn hash_bytes(data: &[u8]) -> Oid {
    Sha1::digest(data).into()
}
