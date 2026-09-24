//! 不依赖系统 git 的底层 Git 对象 / pack / delta 解析。

pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;

use sha1::{Digest, Sha1};
use std::fmt;

pub const OID_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; OID_LEN]);

impl Oid {
    pub fn from_hex(s: &str) -> Option<Oid> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            let h = hex_nibble(b[i * 2])?;
            let l = hex_nibble(b[i * 2 + 1])?;
            out[i] = (h << 4) | l;
        }
        Some(Oid(out))
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn short(&self) -> String {
        self.hex().chars().take(10).collect()
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.hex())
    }
}

/// pack 中可能出现的对象类型（6=ofs_delta, 7=ref_delta）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        Some(match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn base_kind_name(self) -> Option<&'static str> {
        Some(match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            _ => return None,
        })
    }
}

/// 读取 pack 头部的可变长度整数（小端，高位续位）。
pub fn read_size_encoding(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut result = 0u64;
    let mut pos = start;
    loop {
        let b = *data
            .get(pos)
            .ok_or_else(|| "size 编码提前结束".to_string())?;
        result |= ((b & 0x7f) as u64) << shift;
        pos += 1;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err("size 编码过长".to_string());
        }
    }
    Ok((result, pos))
}

/// 按 git 规则计算 loose / 还原后对象的 oid：sha1("<type> <len>\0<content>")。
pub fn git_object_id(kind: ObjType, content: &[u8]) -> Oid {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    Oid(h.finalize().into())
}

/// sha1 over bytes
pub fn sha1_bytes(data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(data);
    Oid(h.finalize().into())
}
