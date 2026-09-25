use serde::{Deserialize, Serialize};
use std::fmt;

/// A 20-byte Git object id (SHA-1).
#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Oid(#[serde(with = "hex_serde")] pub [u8; 20]);

impl Oid {
    pub fn zero() -> Self {
        Oid([0u8; 20])
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Oid(out))
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 20 {
            return None;
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(b);
        Some(Oid(out))
    }
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn short(&self) -> String {
        self.hex().chars().take(8).collect()
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}
impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
        let st = String::deserialize(d)?;
        let o = super::Oid::from_hex(&st).ok_or_else(|| serde::de::Error::custom("bad oid"))?;
        Ok(o.0)
    }
}
