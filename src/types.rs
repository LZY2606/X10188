use serde::Serialize;

/// Git object type tag as it appears in pack headers / loose object headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_u8(v: u8) -> Option<ObjType> {
        Some(match v {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    /// Resolved (non-delta) object type.
    pub fn resolved(self) -> Option<ObjType> {
        match self {
            ObjType::OfsDelta | ObjType::RefDelta => None,
            t => Some(t),
        }
    }
}

pub type Oid = [u8; 20];

pub fn oid_hex(o: &Oid) -> String {
    hex::encode(o)
}

pub fn parse_oid(s: &str) -> Option<Oid> {
    let b = hex::decode(s).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    Some(o)
}
