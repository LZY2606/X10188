//! Git object id / git object body framing. No system git is used.

use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    pub fn parse_loose(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn is_content(self) -> bool {
        matches!(
            self,
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag
        )
    }
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Git object id = sha1(`<type> <len>\0<content>`).
pub fn git_object_id(kind: ObjType, payload: &[u8]) -> String {
    let header = format!("{} {}\0", kind.name(), payload.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(payload);
    hex::encode(h.finalize())
}

pub fn git_frame(kind: ObjType, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{} {}\0", kind.name(), payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}
