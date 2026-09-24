//! 20 字节 Git object id 的简单包装。

use std::fmt;

/// Git SHA-1 对象 ID（20 字节）。
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

    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).ok()?;
            let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).ok()?;
            out[i] = (hi << 4) | lo;
        }
        Some(Oid(out))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.hex()[..12].to_string()
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
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

/// Git 对象类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn base_type_name(t: ObjType) -> &'static str {
        t.name()
    }
}
