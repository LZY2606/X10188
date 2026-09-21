//! Git 对象基础类型与 object id 计算。

use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; OID_LEN]);

impl Oid {
    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let raw = hex::decode(s).ok()?;
        let mut out = [0u8; OID_LEN];
        out.copy_from_slice(&raw);
        Some(Oid(out))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }

    pub fn from_str(s: &str) -> Option<GitType> {
        match s {
            "commit" => Some(GitType::Commit),
            "tree" => Some(GitType::Tree),
            "blob" => Some(GitType::Blob),
            "tag" => Some(GitType::Tag),
            _ => None,
        }
    }

    /// pack 对象头中的 3-bit 类型编码。
    pub fn pack_code(&self) -> u8 {
        match self {
            GitType::Commit => 1,
            GitType::Tree => 2,
            GitType::Blob => 3,
            GitType::Tag => 4,
        }
    }

    pub fn from_pack_code(code: u8) -> Option<GitType> {
        match code {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            _ => None,
        }
    }
}

/// 计算 Git object id: sha1("<type> <len>\0" + content)
pub fn git_oid(git_type: GitType, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(git_type.as_str().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; OID_LEN];
    oid.copy_from_slice(&out);
    Oid(oid)
}

/// 文件内容的摘要（sha256），用于候选排序与去重判定。
pub fn content_digest(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
