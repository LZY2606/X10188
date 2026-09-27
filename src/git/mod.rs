//! Git 对象与 pack 解析原语：不调用系统 git。

pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod reader;

use sha1::{Digest, Sha1};

/// Git 对象类型（编码顺序与 pack 头一致；OF/REF_DELTA 单独列出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
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

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
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

    pub fn from_name(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }
}

/// 计算 Git 对象 id：sha1("<type> <len>\0<content>")。
pub fn git_object_id(kind: ObjType, content: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    h.finalize().into()
}

pub fn hex20(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
