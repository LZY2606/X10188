//! 纯 Rust 实现的 Git 对象/pack/index/delta 解析（不调用系统 git）。

pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod zlib;

use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn name(&self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }

    pub fn from_code(code: u8) -> Option<GitType> {
        match code {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            _ => None,
        }
    }

    pub fn from_name(name: &[u8]) -> Option<GitType> {
        match name {
            b"commit" => Some(GitType::Commit),
            b"tree" => Some(GitType::Tree),
            b"blob" => Some(GitType::Blob),
            b"tag" => Some(GitType::Tag),
            _ => None,
        }
    }
}

/// 计算 Git 对象 id：SHA1("<type> <size>\0" + content)
pub fn git_object_id(t: GitType, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(t.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

/// 计算一段字节的 SHA1（pack trailer / 校验用）。
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn hex20(s: &str) -> Option<[u8; 20]> {
    let b = hex::decode(s).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&b);
    Some(oid)
}

/// Git pack 的 little-endian 风格 7 位变长整数（delta header 的 src/dst 长度）。
pub fn read_le_varint(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() || shift > 63 {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((val, pos))
}
