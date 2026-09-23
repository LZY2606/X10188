use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
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
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }

    pub fn from_name(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// Git object id: sha1 of "<type> <len>\0" + content.
pub fn object_id(typ: ObjType, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", typ.name(), content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}
