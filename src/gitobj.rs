//! Git 对象基础：类型、object id 计算（纯 Rust，不调用系统 git）。
use sha1::{Digest, Sha1};

pub const T_COMMIT: u8 = 1;
pub const T_TREE: u8 = 2;
pub const T_BLOB: u8 = 3;
pub const T_TAG: u8 = 4;
pub const T_OFS_DELTA: u8 = 6;
pub const T_REF_DELTA: u8 = 7;

pub fn type_name(code: u8) -> &'static str {
    match code {
        T_COMMIT => "commit",
        T_TREE => "tree",
        T_BLOB => "blob",
        T_TAG => "tag",
        T_OFS_DELTA => "ofs_delta",
        T_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

pub fn is_delta(code: u8) -> bool {
    code == T_OFS_DELTA || code == T_REF_DELTA
}

/// 计算 Git object id：sha1("<type> <len>\0" + content)
pub fn object_id(type_code: u8, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name(type_code), content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// 裸 sha1（用于 pack/idx 校验和）
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 文件内容摘要（导入时保留）
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Sha256;
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
