use std::cmp::Ordering;
use std::fmt;

/// 20 字节 Git 对象 ID（SHA-1）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub const fn zero() -> Self {
        Oid([0u8; 20])
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.len() != 40 {
            return Err(format!("oid 长度应为 40，实际 {}: {}", s.len(), s));
        }
        let mut out = [0u8; 20];
        hex::decode_to_slice(s, &mut out).map_err(|e| e.to_string())?;
        Ok(Oid(out))
    }

    pub fn from_slice(b: &[u8]) -> Result<Self, String> {
        if b.len() != 20 {
            return Err(format!("oid 原始长度应为 20，实际 {}", b.len()));
        }
        let mut o = [0u8; 20];
        o.copy_from_slice(b);
        Ok(Oid(o))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

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

impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Oid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl serde::Serialize for Oid {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.hex())
    }
}

impl<'de> serde::Deserialize<'de> for Oid {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Oid::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
