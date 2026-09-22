//! 20-byte Git object identifier helpers (no external hex crate needed).

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub const ZERO: Oid = Oid([0u8; 20]);

    pub fn from_bytes(b: &[u8]) -> Result<Oid, String> {
        if b.len() != 20 {
            return Err(format!("oid must be 20 bytes, got {}", b.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(b);
        Ok(Oid(out))
    }

    pub fn from_hex(s: &str) -> Result<Oid, String> {
        let s = s.trim();
        if s.len() != 40 {
            return Err(format!("oid hex must be 40 chars, got {}: {s}", s.len()));
        }
        let mut out = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Oid(out))
    }

    pub fn hex(&self) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn short(&self) -> String {
        self.hex().chars().take(10).collect()
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", c as char)),
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl serde::Serialize for Oid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}
