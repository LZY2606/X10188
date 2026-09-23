//! Git object 基础：类型、object id (SHA-1) 计算。不调用系统 git。
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl Kind {
    pub fn from_code(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Commit),
            2 => Some(Kind::Tree),
            3 => Some(Kind::Blob),
            4 => Some(Kind::Tag),
            6 => Some(Kind::OfsDelta),
            7 => Some(Kind::RefDelta),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Kind> {
        match name {
            "commit" => Some(Kind::Commit),
            "tree" => Some(Kind::Tree),
            "blob" => Some(Kind::Blob),
            "tag" => Some(Kind::Tag),
            "ofs_delta" => Some(Kind::OfsDelta),
            "ref_delta" => Some(Kind::RefDelta),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
            Kind::OfsDelta => "ofs_delta",
            Kind::RefDelta => "ref_delta",
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, Kind::OfsDelta | Kind::RefDelta)
    }
}

/// 计算 Git object id: sha1("<type> <len>\\0" + content)
pub fn git_oid(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}", type_name, content.len()).as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Sha256;
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
