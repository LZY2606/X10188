//! Git object type constants and content-addressed object ids (SHA-1).

use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
/// Reserved 5 = ofs_delta in pack headers (never a real object).
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        Some(match code {
            OBJ_COMMIT => ObjType::Commit,
            OBJ_TREE => ObjType::Tree,
            OBJ_BLOB => ObjType::Blob,
            OBJ_TAG => ObjType::Tag,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            ObjType::Commit => OBJ_COMMIT,
            ObjType::Tree => OBJ_TREE,
            ObjType::Blob => OBJ_BLOB,
            ObjType::Tag => OBJ_TAG,
        }
    }

    pub fn from_name(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }
}

/// Compute the Git object id: `sha1("<type> <len>\0<content>")`.
pub fn git_object_id(kind: ObjType, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let r = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_oid() {
        // The well-known empty blob id.
        let id = git_object_id(ObjType::Blob, b"");
        assert_eq!(
            hex::encode(id),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }
}
