use crate::git::{sha1_hex, ObjType};
use crate::zutil::decompress_bounded;

pub const HARD_CAP: usize = 512 * 1024 * 1024;

#[derive(Default, Clone, Debug)]
pub struct RawEntry {
    pub idx: usize,
    pub offset: u64,
    pub header_len: u64,
    pub data_offset: u64,
    pub data_len: u64,
    pub type_code: u8,
    pub type_name: String,
    pub declared_size: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub raw: Option<Vec<u8>>,
    pub raw_len: u64,
    pub parse_error: Option<String>,
}

#[derive(Default, Clone, Debug)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub trailer: String,
    pub entries: Vec<RawEntry>,
    pub checksum_ok: bool,
    pub error: Option<String>,
}

fn parse_entry_header(buf: &[u8], start: usize) -> Result<(u8, u64, usize), String> {
    let mut pos = start;
    let c = *buf.get(pos).ok_or("对象头缺失")?;
    pos += 1;
    let type_code = (c >> 4) & 0x7;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    let mut first = c;
    while first & 0x80 != 0 {
        let c = *buf.get(pos).ok_or("对象头变长大小被截断")?;
        pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        first = c;
    }
    Ok((type_code, size, pos))
}

/// ofs-delta 距离编码：返回 (distance, header_end)。
pub fn parse_ofs_distance(buf: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut pos = start;
    let mut c = *buf.get(pos).ok_or("ofs-delta 距离缺失")?;
    pos += 1;
    let mut distance = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *buf.get(pos).ok_or("ofs-delta 距离被截断")?;
        pos += 1;
        distance = distance
            .checked_add(1)
            .ok_or("ofs-delta 距离溢出")?
            .checked_shl(7)
            .ok_or("ofs-delta 距离溢出")?
            | ((c & 0x7f) as u64);
    }
    Ok((distance, pos))
}

fn parse_one(buf: &[u8], start: usize, data_end: usize, idx: usize) -> RawEntry {
    let mut e = RawEntry {
        idx,
        offset: start as u64,
        ..Default::default()
    };
    let (type_code, size, after_header) = match parse_entry_header(buf, start) {
        Ok(v) => v,
        Err(msg) => {
            e.parse_error = Some(msg);
            return e;
        }
    };
    e.header_len = (after_header - start) as u64;
    e.declared_size = size;
    let otype = match ObjType::from_code(type_code) {
        Some(t) => t,
        None => {
            e.parse_error = Some(format!("对象 #{idx} 使用保留类型 {type_code}"));
            return e;
        }
    };
    e.type_code = type_code;
    e.type_name = otype.name().to_string();
    let mut data_start = after_header;
    match otype {
        ObjType::OfsDelta => {
            let (distance, after) = match parse_ofs_distance(buf, data_start) {
                Ok(v) => v,
                Err(msg) => {
                    e.parse_error = Some(msg);
                    return e;
                }
            };
            e.header_len = (after - start) as u64;
            data_start = after;
            if distance > start as u64 {
                e.parse_error = Some(format!(
                    "ofs-delta 距离 {distance} 越过 pack 起点（对象偏移 {start}）"
                ));
                return e;
            }
            e.base_offset = Some(start as u64 - distance);
        }
        ObjType::RefDelta => {
            if data_start + 20 > data_end {
                e.parse_error = Some("ref-delta 的 20 字节 base oid 越界".into());
                return e;
            }
            e.base_oid = Some(hex::encode(&buf[data_start..data_start + 20]));
            data_start += 20;
            e.header_len = (data_start - start) as u64;
        }
        _ => {}
    }
    e.data_offset = data_start as u64;
    let cap = (size as usize).min(HARD_CAP);
    match decompress_bounded(&buf[data_start..data_end], cap) {
        Ok((raw, consumed)) => {
            e.data_len = consumed as u64;
            e.raw_len = raw.len() as u64;
            if raw.len() as u64 != size {
                e.parse_error = Some(format!(
                    "声明大小 {size} 与实际解压长度 {} 不一致（大小欺骗）",
                    raw.len()
                ));
            }
            e.raw = Some(raw);
        }
        Err(msg) => {
            e.parse_error = Some(msg);
        }
    }
    e
}

pub fn parse_pack(buf: &[u8]) -> PackInfo {
    let mut info = PackInfo::default();
    if buf.len() < 32 {
        info.error = Some("文件过小，不可能是合法 pack".into());
        return info;
    }
    if &buf[0..4] != b"PACK" {
        info.error = Some("缺少 PACK 魔数".into());
        return info;
    }
    info.version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    info.count = u32::from_be_bytes(buf[8..12].try_into().unwrap());
    let data_end = buf.len() - 20;
    let mut pos = 12usize;
    let mut fatal = None;
    for idx in 0..info.count as usize {
        if pos >= data_end {
            fatal = Some(format!("对象 #{idx} 起始偏移 {pos} 越过数据区"));
            break;
        }
        let e = parse_one(buf, pos, data_end, idx);
        let advance = match (e.data_len, e.parse_error.as_ref()) {
            (0, Some(_)) => None,
            _ => Some((e.data_offset + e.data_len) as usize),
        };
        info.entries.push(e);
        match advance {
            Some(next) => pos = next,
            None => {
                fatal = Some(format!("对象 #{idx} @{pos} 无法确定 zlib 边界，停止顺序解析"));
                break;
            }
        }
    }
    info.trailer = hex::encode(&buf[data_end..]);
    let actual = sha1_hex(&buf[..data_end]);
    info.checksum_ok = actual == info.trailer;
    let mut errs: Vec<String> = Vec::new();
    if let Some(m) = fatal {
        errs.push(m);
    }
    if !info.checksum_ok {
        errs.push(format!(
            "pack 尾部校验和不匹配: 声明 {} 实际 {actual}",
            info.trailer
        ));
    }
    if info.entries.len() != info.count as usize {
        errs.push(format!(
            "header 声明 {} 个对象，实际解析出 {} 个",
            info.count,
            info.entries.len()
        ));
    }
    info.error = if errs.is_empty() { None } else { Some(errs.join("; ")) };
    info
}
