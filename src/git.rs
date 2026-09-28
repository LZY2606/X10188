//! Git object types and object-id computation.

use crate::oid::Oid;
use sha1::{Digest, Sha1};

/// Canonical git object types (the seven pack types; offset/ref delta are
/// container types rather than stored object types).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GitType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    /// Delta with an absolute 20-byte base object id.
    RefDelta = 6,
    /// Delta with a negative offset to another entry in the same pack.
    OfsDelta = 7,
}

impl GitType {
    pub fn from_pack_code(code: u8) -> Option<GitType> {
        Some(match code {
            1 => GitType::Commit,
            2 => GitType::Tree,
            3 => GitType::Blob,
            4 => GitType::Tag,
            6 => GitType::RefDelta,
            7 => GitType::OfsDelta,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::RefDelta => "ref-delta",
            GitType::OfsDelta => "ofs-delta",
        }
    }

    /// True for the four canonical content types.
    pub fn is_leaf(self) -> bool {
        matches!(
            self,
            GitType::Commit | GitType::Tree | GitType::Blob | GitType::Tag
        )
    }
}

/// Result type stored in a git object header (commit/tree/blob/tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl LeafType {
    pub fn name(self) -> &'static str {
        match self {
            LeafType::Commit => "commit",
            LeafType::Tree => "tree",
            LeafType::Blob => "blob",
            LeafType::Tag => "tag",
        }
    }

    pub fn as_bytes(self) -> &'static [u8] {
        self.name().as_bytes()
    }
}

impl From<GitType> for LeafType {
    fn from(g: GitType) -> LeafType {
        match g {
            GitType::Commit => LeafType::Commit,
            GitType::Tree => LeafType::Tree,
            GitType::Blob => LeafType::Blob,
            GitType::Tag => LeafType::Tag,
            _ => LeafType::Blob,
        }
    }
}

/// Compute the git object id of `<type> <size>\0<content>`.
pub fn object_id(kind: LeafType, content: &[u8]) -> Oid {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    let out = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&out);
    Oid(o)
}

/// Parse a canonical loose-object header `type size\0`.
/// Returns (type, declared_size, header_len).
pub fn parse_object_header(buf: &[u8]) -> Option<(LeafType, u64, usize)> {
    let nul = buf.iter().position(|&b| b == 0)?;
    let head = std::str::from_utf8(&buf[..nul]).ok()?;
    let (t, s) = head.split_once(' ')?;
    let lt = match t {
        "commit" => LeafType::Commit,
        "tree" => LeafType::Tree,
        "blob" => LeafType::Blob,
        "tag" => LeafType::Tag,
        _ => return None,
    };
    let size: u64 = s.parse().ok()?;
    Some((lt, size, nul + 1))
}

#[cfg(test)]
pub(crate) mod known_ids {
    use super::*;
    #[test]
    fn empty_blob() {
        // well known: e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
        assert_eq!(
            object_id(LeafType::Blob, b"").hex(),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    #[test]
    fn hello_blob() {
        // printf 'hello\n' | git hash-object --stdin -> ce013625030ba8dba900ac5a2f57e2f0b3079f29
        assert_eq!(
            object_id(LeafType::Blob, b"hello\n").hex(),
            "ce013625030ba8dba900ac5a2f57e2f0b3079f29"
        );
    }
}
