//! 基础类型与工具：对象类型、Git object id、hex、预算。

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn kind_name(code: u8) -> &'static str {
    match code {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn kind_code(name: &str) -> Option<u8> {
    match name {
        "commit" => Some(OBJ_COMMIT),
        "tree" => Some(OBJ_TREE),
        "blob" => Some(OBJ_BLOB),
        "tag" => Some(OBJ_TAG),
        _ => None,
    }
}

pub fn is_delta_kind(kind: &str) -> bool {
    kind == "ofs-delta" || kind == "ref-delta"
}

/// 计算 Git object id：sha1("<type> <len>\\0" + content)
pub fn git_oid(kind: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", kind, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// 文件内容摘要（用于来源登记与确定性排序）
pub fn content_digest(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 资源预算：delta 深度、总展开字节、单对象放大比例。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_object_ratio: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 64,
            max_total_bytes: 1 << 30,
            max_object_ratio: 1000,
        }
    }
}
