use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid([u8; 20]);

impl Oid {
    pub fn from_bytes(b: [u8; 20]) -> Self {
        Oid(b)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s).ok()?;
        if v.len() != 20 {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        Some(Oid(a))
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GitType {
    Commit,
    Tree,
    Tag,
    Blob,
}

impl GitType {
    pub fn name(&self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }
    pub fn from_name(s: &[u8]) -> Option<Self> {
        match s {
            b"commit" => Some(GitType::Commit),
            b"tree" => Some(GitType::Tree),
            b"blob" => Some(GitType::Blob),
            b"tag" => Some(GitType::Tag),
            _ => None,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            _ => None,
        }
    }
}

/// Compute the Git object id: SHA1("<type> <len>\0" || content).
pub fn hash_object(ty: GitType, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(ty.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    Oid::from_bytes(h.finalize().into())
}

pub fn sha1_raw(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let r = h.finalize();
    let mut a = [0u8; 20];
    a.copy_from_slice(&r);
    a
}
