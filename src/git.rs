use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            "ofs_delta" => Some(ObjType::OfsDelta),
            "ref_delta" => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// 计算 git 对象 id：sha1("<type> <size>\0<content>")
pub fn oid_hex(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(type_name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// delta 中的小端 7 位组变长整数，返回 (value, new_pos)。
pub fn read_size_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err("变长整数读取越界".into());
        }
        let c = buf[*pos];
        *pos += 1;
        value |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("变长整数过长".into());
        }
    }
    Ok(value)
}
