use sha1::{Digest, Sha1};

use crate::oid::Oid;
use crate::types::ObjKind;

/// 计算 git 对象 id：SHA1("<type> <len>\0" + content)。
pub fn git_object_id(kind: ObjKind, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.word().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let r = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&r);
    Oid(o)
}

/// 内容预览：保留前 N 字节，文本尽量按 UTF-8 展示。
pub fn preview(content: &[u8], max: usize) -> String {
    let n = content.len().min(max);
    let slice = &content[..n];
    match std::str::from_utf8(slice) {
        Ok(s) => s
            .chars()
            .map(|c| if c.is_control() && c != '\n' && c != '\t' { '·' } else { c })
            .collect(),
        Err(_) => format!("hex:{}", hex::encode(&slice[..n.min(48)])),
    }
}
