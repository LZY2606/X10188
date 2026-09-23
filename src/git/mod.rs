pub mod delta;
pub mod idxfile;
pub mod loose;
pub mod pack;
pub mod varint;

use sha1::{Digest, Sha1};

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Recompute a Git object id: sha1("<type> <size>\0<body>").
pub fn git_object_id(type_name: &str, body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(type_name.as_bytes());
    hasher.update(b" ");
    hasher.update(body.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(body);
    let out = hasher.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn valid_type_name(name: &str) -> bool {
    matches!(name, "commit" | "tree" | "blob" | "tag")
}
