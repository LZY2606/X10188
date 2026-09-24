use sha1::{Digest, Sha1};

pub const T_COMMIT: u8 = 1;
pub const T_TREE: u8 = 2;
pub const T_BLOB: u8 = 3;
pub const T_TAG: u8 = 4;
pub const T_OFS_DELTA: u8 = 6;
pub const T_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        T_COMMIT => "commit",
        T_TREE => "tree",
        T_BLOB => "blob",
        T_TAG => "tag",
        T_OFS_DELTA => "ofs_delta",
        T_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

/// Git object id: sha1("<type> <len>\0" + content)
pub fn oid_for(typ: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(typ.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}
