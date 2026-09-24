//! Git pack 解析：header、对象类型、ofs/ref-delta、zlib 边界、校验和。
use crate::gitobj;
use crate::zlib;

#[derive(Clone, Debug)]
pub struct RawEntry {
    pub offset: u64,
    pub type_code: u8,
    pub declared_size: u64,
    pub data_off: u64,
    pub data_len: u64, // zlib 流长度（边界）
    pub base_ofs: Option<u64>,  // ofs-delta: base 的绝对偏移
    pub base_oid: Option<String>, // ref-delta: base oid
    pub inflated_len: Option<u64>,
    pub crc_actual: u32,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<RawEntry>,
    /// pack 内容 sha1（不含尾部 20 字节），用于与 idx 配套
    pub content_sha1: String,
    pub trailer_sha1: String,
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn merge_err(a: Option<String>, b: String) -> Option<String> {
    match a {
        Some(x) => Some(format!("{x}; {b}")),
        None => Some(b),
    }
}

pub fn parse_pack(bytes: &[u8]) -> Result<ParsedPack, String> {
    if bytes.len() < 12 + 20 {
        return Err("pack 太小，不是合法 PACK 文件".into());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = be32(bytes, 4);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let declared_count = be32(bytes, 8);
    let mut pos = 12usize;
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for _ in 0..declared_count {
        if pos >= bytes.len().saturating_sub(20) {
            errors.push(format!(
                "pack 截断: 仅解析出 {}/{} 个对象",
                entries.len(),
                declared_count
            ));
            break;
        }
        let start = pos as u64;
        let mut b = bytes[pos];
        pos += 1;
        let type_code = (b >> 4) & 0x7;
        let mut size = (b & 0x0f) as u64;
        let mut shift = 4u32;
        while b & 0x80 != 0 {
            if pos >= bytes.len() {
                return Err(format!("偏移 {start}: 对象头截断"));
            }
            b = bytes[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if shift > 63 {
                return Err(format!("偏移 {start}: 对象大小 varint 溢出"));
            }
        }
        let mut base_ofs = None;
        let mut base_oid = None;
        let mut perr: Option<String> = None;
        if type_code == gitobj::T_OFS_DELTA {
            if pos >= bytes.len() {
                return Err(format!("偏移 {start}: ofs-delta 偏移截断"));
            }
            let mut b2 = bytes[pos];
            pos += 1;
            let mut off = (b2 & 0x7f) as u64;
            while b2 & 0x80 != 0 {
                if pos >= bytes.len() {
                    return Err(format!("偏移 {start}: ofs-delta 偏移截断"));
                }
                b2 = bytes[pos];
                pos += 1;
                off = ((off + 1) << 7) | ((b2 & 0x7f) as u64);
            }
            if off > start {
                // ofs 距离越界：隔离该对象，继续解析后续
                perr = merge_err(
                    perr,
                    format!("ofs-delta 距离越界: 后退 {off} 字节超过当前偏移 {start}"),
                );
            } else {
                base_ofs = Some(start - off);
            }
        } else if type_code == gitobj::T_REF_DELTA {
            if pos + 20 > bytes.len() {
                return Err(format!("偏移 {start}: ref-delta base oid 截断"));
            }
            base_oid = Some(hex::encode(&bytes[pos..pos + 20]));
            pos += 20;
        }
        let data_off = pos as u64;
        match zlib::inflate_limited(&bytes[pos..], size) {
            Ok(inf) => {
                let ilen = inf.data.len() as u64;
                let mut e = RawEntry {
                    offset: start,
                    type_code,
                    declared_size: size,
                    data_off,
                    data_len: inf.consumed as u64,
                    base_ofs,
                    base_oid,
                    inflated_len: Some(ilen),
                    crc_actual: 0,
                    parse_error: perr.take(),
                };
                if ilen != size {
                    e.parse_error = merge_err(
                        e.parse_error.take(),
                        format!("大小欺骗: 声明解压大小 {size}，实际 {ilen}"),
                    );
                }
                let end = pos + inf.consumed;
                e.crc_actual = crc32fast::hash(&bytes[start as usize..end]);
                pos = end;
                entries.push(e);
            }
            Err(msg) => {
                entries.push(RawEntry {
                    offset: start,
                    type_code,
                    declared_size: size,
                    data_off,
                    data_len: 0,
                    base_ofs,
                    base_oid,
                    inflated_len: None,
                    crc_actual: 0,
                    parse_error: merge_err(perr, msg),
                });
                errors.push(format!(
                    "偏移 {start}: zlib 边界无法确定，后续对象边界不可信，停止解析本 pack"
                ));
                break;
            }
        }
    }
    if entries.len() as u32 != declared_count {
        errors.push(format!(
            "对象计数不符: 头部声明 {declared_count}，实际解析 {}",
            entries.len()
        ));
    }
    let body = &bytes[..bytes.len() - 20];
    let content_sha1 = gitobj::sha1_hex(body);
    let trailer_sha1 = hex::encode(&bytes[bytes.len() - 20..]);
    let checksum_ok = content_sha1 == trailer_sha1;
    if !checksum_ok {
        errors.push(format!(
            "pack 尾部校验和不匹配: 内容计算 {content_sha1}，尾部记录 {trailer_sha1}"
        ));
    }
    Ok(ParsedPack {
        version,
        declared_count,
        entries,
        content_sha1,
        trailer_sha1,
        checksum_ok,
        errors,
    })
}
