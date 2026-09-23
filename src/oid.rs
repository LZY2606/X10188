use sha1::{Digest, Sha1};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn zero() -> Oid {
        Oid([0u8; 20])
    }

    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(b);
        Some(Oid(a))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn parse_hex(s: &str) -> Option<Oid> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            let hi = hex_val(b[i * 2])?;
            let lo = hex_val(b[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Oid(out))
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn short(&self) -> String {
        self.hex().chars().take(8).collect()
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.hex())
    }
}

/// Compute the git object id for `content` of the given loose object type.
pub fn object_id(kind: &str, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    Oid(h.finalize().into())
}

/// Content fingerprint used to make import order / repeated imports stable.
pub fn content_fingerprint(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    Oid(h.finalize().into()).hex()
}
