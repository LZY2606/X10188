use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// 20 字节 SHA-1 对象 id
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(b);
        Some(Oid(a))
    }

    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let raw = hex::decode(s).ok()?;
        Oid::from_bytes(&raw)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.to_hex()[..8].to_string()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.short())
    }
}

impl Serialize for Oid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Oid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Oid, D::Error> {
        let s = String::deserialize(d)?;
        Oid::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid oid hex"))
    }
}
