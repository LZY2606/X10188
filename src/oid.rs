//! 20-byte Git object id (SHA-1) wrapper.

use std::fmt;

/// Git SHA-1 object id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub const ZERO: Oid = Oid([0u8; 20]);

    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(b);
        Some(Oid(out))
    }

    /// Parse a 40-char hex string.
    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Oid(out))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Short hex prefix used in previews.
    pub fn short(&self) -> String {
        self.hex().chars().take(10).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let s = "0123456789abcdef0123456789abcdef01234567";
        let o = Oid::from_hex(s).unwrap();
        assert_eq!(o.hex(), s);
        assert!(Oid::from_hex("abc").is_none());
        assert!(Oid::from_hex(&format!("{}z", s)).is_none());
        assert_eq!(Oid::from_bytes(&[1u8; 19]), None);
    }
}
