use std::fmt;

use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn zero() -> Oid {
        Oid([0u8; 20])
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let raw = hex::decode(s).ok()?;
        if raw.len() != 20 {
            return None;
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&raw);
        Some(Oid(out))
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

pub fn sha1_of(data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    Oid(out)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn object_id(obj_type: &str, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(obj_type.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    Oid(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_known_blob_oid() {
        let oid = object_id("blob", b"hello world\n");
        assert_eq!(oid.to_hex(), "3b18e512dba79e4c8300dd08aeb37f8e728b8dad");
    }

    #[test]
    fn hex_roundtrip() {
        let oid = object_id("blob", b"x");
        assert_eq!(Oid::from_hex(&oid.to_hex()), Some(oid));
        assert_eq!(Oid::from_hex("zzzz"), None);
    }
}
