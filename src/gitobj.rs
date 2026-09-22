//! Git object id（sha1）计算与对象类型工具。不调用系统 git。

use sha1::{Digest, Sha1};

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Git 对象 id = sha1("<type> <len>\\0" + payload)
pub fn git_oid(type_name: &str, payload: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name, payload.len()).as_bytes());
    h.update(payload);
    hex(&h.finalize())
}

/// 导入文件的内容摘要（用于候选来源的确定性排序与去重）。
pub fn file_digest(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn type_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("commit"),
        2 => Some("tree"),
        3 => Some("blob"),
        4 => Some("tag"),
        6 => Some("ofs-delta"),
        7 => Some("ref-delta"),
        _ => None,
    }
}

pub fn code_for_name(name: &str) -> Option<u8> {
    match name {
        "commit" => Some(1),
        "tree" => Some(2),
        "blob" => Some(3),
        "tag" => Some(4),
        _ => None,
    }
}

pub fn is_delta(code: u8) -> bool {
    code == 6 || code == 7
}
