use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(code: u8) -> Option<&'static str> {
    match code {
        OBJ_COMMIT => Some("commit"),
        OBJ_TREE => Some("tree"),
        OBJ_BLOB => Some("blob"),
        OBJ_TAG => Some("tag"),
        _ => None,
    }
}

pub fn type_label(code: u8) -> &'static str {
    match code {
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        c => type_name(c).unwrap_or("unknown"),
    }
}

/// 重新计算 Git object id: sha1("<type> <len>\0" + content)
pub fn oid_hex(type_name_str: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name_str, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}
