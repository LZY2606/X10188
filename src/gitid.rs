//! Git object id（SHA-1）与 Git 对象相关的底层编码约定。
//!
//! Git 中一个对象的 SHA-1 = sha1("<type> <len>\0" + payload)。
//! 本模块不依赖系统 git，全部从零实现。

use sha1::{Digest, Sha1};

pub type Oid = [u8; 20];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjType {
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
        }
    }

    pub fn from_name(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }

    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        // Git pack v2: 1=commit 2=tree 3=blob 4=tag 6=ofs-delta 7=ref-delta
        Some(match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            _ => return None,
        })
    }
}

/// 计算还原后对象的 Git object id。
pub fn git_object_id(ty: ObjType, payload: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(ty.name().as_bytes());
    h.update(b" ");
    h.update(payload.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(payload);
    h.finalize().into()
}

pub fn oid_hex(o: &Oid) -> String {
    let mut s = String::with_capacity(40);
    for b in o {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn oid_from_hex(s: &str) -> Option<Oid> {
    if s.len() != 40 {
        return None;
    }
    let mut out = Oid::default();
    for (i, byte) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(byte[0])?;
        let lo = hex_val(byte[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Git 使用的小端变长整数（每个字节高位表示“还有后续字节”）。
pub fn read_size_encoding(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut result: u64 = 0;
    loop {
        if *pos >= data.len() {
            return Err("变长整数读取越界（数据被截断）".to_string());
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("变长整数过长".to_string());
        }
    }
    Ok(result)
}

/// 生成小端变长整数。
pub fn write_size_encoding(mut value: u64, first_byte_prefix: u8, out: &mut Vec<u8>) {
    let mut first = true;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if first {
            byte |= first_byte_prefix;
        }
        first = false;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// 内容预览：前 N 字节的安全文本表示。
pub fn preview(data: &[u8], max: usize) -> String {
    let slice = &data[..data.len().min(max)];
    let mut s = String::new();
    for &b in slice {
        if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else {
            s.push('·');
        }
    }
    if data.len() > max {
        s.push_str("…");
    }
    s
}
