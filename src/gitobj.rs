use sha1::{Digest, Sha1};

pub const OBJ_TYPES: [&str; 8] = ["", "commit", "tree", "blob", "tag", "", "ofs_delta", "ref_delta"];

pub fn type_name(raw: u8) -> Option<&'static str> {
    OBJ_TYPES.get(raw as usize).copied().filter(|s| !s.is_empty())
}

pub fn object_id(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 解析 pack 对象头: 返回 (raw_type, declared_size, header_len)
pub fn parse_entry_header(data: &[u8], off: usize) -> Result<(u8, u64, usize), String> {
    let mut i = off;
    let first = *data.get(i).ok_or("对象头越界")?;
    i += 1;
    let raw_type = (first >> 4) & 0x7;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *data.get(i).ok_or("对象头截断")?;
        i += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("声明大小溢出".into());
        }
    }
    Ok((raw_type, size, i - off))
}

/// 解析 ofs-delta 的负偏移编码: 返回 (distance, len)
pub fn parse_ofs_distance(data: &[u8], off: usize) -> Result<(u64, usize), String> {
    let mut i = off;
    let mut c = *data.get(i).ok_or("ofs-delta 偏移截断")?;
    i += 1;
    let mut dist = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *data.get(i).ok_or("ofs-delta 偏移截断")?;
        i += 1;
        dist = ((dist + 1) << 7) | (c & 0x7f) as u64;
    }
    Ok((dist, i - off))
}

/// 7-bit 小端 varint (delta 头中的长度)
pub fn parse_varint(data: &[u8], off: usize) -> Result<(u64, usize), String> {
    let mut i = off;
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let c = *data.get(i).ok_or("varint 截断")?;
        i += 1;
        v |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("varint 溢出".into());
        }
        if c & 0x80 == 0 {
            break;
        }
    }
    Ok((v, i - off))
}
