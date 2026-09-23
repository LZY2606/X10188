//! Git object id / type helpers. No system git is used anywhere.

use sha1::{Digest, Sha1};

pub const TYPES: [&str; 8] = [
    "none", "commit", "tree", "blob", "tag", "unknown5", "ofs-delta", "ref-delta",
];

pub fn type_name(id: u8) -> &'static str {
    TYPES.get(id as usize).copied().unwrap_or("unknown")
}

pub fn is_delta(type_id: u8) -> bool {
    type_id == 6 || type_id == 7
}

/// Compute the Git object id: sha1("<type> <len>\\0" + content).
pub fn object_id(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(type_name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_blob_oid() {
        // Well-known: git hash-object of "hello" (no trailing newline).
        assert_eq!(
            object_id("blob", b"hello"),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
        // Empty blob.
        assert_eq!(
            object_id("blob", b""),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }
}
