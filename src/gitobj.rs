//! Git 对象基础：类型名、对象 id、十六进制。

use sha1::{Digest, Sha1};

pub const TYPE_COMMIT: u8 = 1;
pub const TYPE_TREE: u8 = 2;
pub const TYPE_BLOB: u8 = 3;
pub const TYPE_TAG: u8 = 4;
pub const TYPE_OFS_DELTA: u8 = 6;
pub const TYPE_REF_DELTA: u8 = 7;

pub static TYPE_NAMES: [&str; 8] = [
    "none", "commit", "tree", "blob", "tag", "reserved", "ofs-delta", "ref-delta",
];

pub fn type_name(code: u8) -> String {
    TYPE_NAMES
        .get(code as usize)
        .copied()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("unknown({})", code))
}

pub fn base_type_code(name: &str) -> Option<u8> {
    TYPE_NAMES.iter().position(|n| *n == name).map(|i| i as u8)
}

/// 计算 Git object id：sha1("<type> <len>\0" + content)。
pub fn object_id(obj_type: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", obj_type, content.len()).into_bytes());
    h.update(content);
    hex_encode(&h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex_encode(&h.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 读取 7-bit 小端变长整数（pack/delta 通用）。返回 (值, 消耗字节数)。
pub fn read_varint7(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        if pos >= data.len() {
            return None;
        }
        let b = data[pos];
        pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((value, pos - start))
}
