use sha1::{Digest, Sha1};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let bytes = hex::decode(s).ok()?;
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Some(Oid(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.to_hex()[..8].to_string()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.short())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }

    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            _ => None,
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

pub fn compute_oid(t: ObjType, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", t.as_str(), content.len()).as_bytes());
    h.update(content);
    Oid(h.finalize().into())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_matches_git_well_known_value() {
        let oid = compute_oid(ObjType::Blob, b"");
        assert_eq!(oid.to_hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        let oid = compute_oid(ObjType::Blob, b"hello world\n");
        assert_eq!(oid.to_hex(), "3b18e512dba79e4c8300dd08aeb37f8e728b8dad");
    }
}
