use serde::{Deserialize, Serialize};

/// Git 对象类型（含 pack 中的 delta 伪类型）
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl GitType {
    pub fn from_pack_code(code: u8) -> Option<GitType> {
        match code {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            6 => Some(GitType::OfsDelta),
            7 => Some(GitType::RefDelta),
            _ => None,
        }
    }

    pub fn pack_code(self) -> u8 {
        match self {
            GitType::Commit => 1,
            GitType::Tree => 2,
            GitType::Blob => 3,
            GitType::Tag => 4,
            GitType::OfsDelta => 6,
            GitType::RefDelta => 7,
        }
    }

    /// Git object id 计算时使用的类型名（delta 类型无对应名）
    pub fn as_str(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::OfsDelta => "ofs_delta",
            GitType::RefDelta => "ref_delta",
        }
    }

    pub fn from_str(s: &str) -> Option<GitType> {
        match s {
            "commit" => Some(GitType::Commit),
            "tree" => Some(GitType::Tree),
            "blob" => Some(GitType::Blob),
            "tag" => Some(GitType::Tag),
            "ofs_delta" => Some(GitType::OfsDelta),
            "ref_delta" => Some(GitType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
    }
}
