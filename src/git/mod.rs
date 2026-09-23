//! Pure-Rust Git object/pack primitives. No external git binary is used.

pub mod varint;
pub mod zlib;
pub mod object;
pub mod pack;
pub mod index;
pub mod loose;
pub mod delta;
pub mod builder;

pub use varint::{read_size_encoding, write_size_encoding};
pub use object::{git_object_id, ObjType, OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, OBJ_TAG, OBJ_OFS_DELTA, OBJ_REF_DELTA};

/// Parse a 40-char hex sha1.
pub fn parse_oid(s: &str) -> Option<[u8; 20]> {
    let s = s.trim();
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

pub fn oid_hex(o: &[u8; 20]) -> String {
    hex::encode(o)
}
