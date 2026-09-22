//! Low-level Git object format parsing (pack / idx / loose / delta).
//!
//! Nothing in this module invokes the system `git` binary.

pub mod delta;
pub mod hash;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod varint;
pub mod zlib;

/// Object types stored inside a pack (3-bit type field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
    Bad = 0,
}

impl ObjType {
    pub fn from_code(code: u8) -> ObjType {
        match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => ObjType::Bad,
        }
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
            ObjType::Bad => "bad",
        }
    }

    pub fn from_name(name: &str) -> Option<ObjType> {
        Some(match name {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }

    pub fn is_base(self) -> bool {
        matches!(self, ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag)
    }
}
