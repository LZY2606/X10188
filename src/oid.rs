//! 20-byte Git object identifier (SHA-1) helpers.

use std::fmt;

/// A git object id: exactly 20 raw bytes.
#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub const ZERO: Oid = Oid([0u8; 20]);

    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        let mut o = [0u8; 20];
        o.copy_from_slice(b);
        Some(Oid(o))
    }

    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            let hi = hex_val(s.as_bytes()[i * 2])?;
            let lo = hex_val(s.as_bytes()[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Oid(out))
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn short(&self) -> String {
        self.hex().chars().take(8).collect()
    }
}

const HEX: &[u8] = b"0123456789abcdef";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let h = "0123456789abcdef0123456789abcdef01234567";
        let o = Oid::from_hex(h).unwrap();
        assert_eq!(o.hex(), h);
    }

    #[test]
    fn bad_hex() {
        assert!(Oid::from_hex("zz").is_none());
        assert!(Oid::from_hex("0123").is_none());
    }
}
