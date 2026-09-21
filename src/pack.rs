use crate::gitobj::{self, ObjType};

/// 单个对象解压上限（防止 zip bomb 拖垮分析进程）
pub const INFLATE_CAP: u64 = 512 * 1024 * 1024;

fn be_u32(data: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

fn be_u64(data: &[u8], pos: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[pos..pos + 8]);
    u64::from_be_bytes(b)
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub header_len: u64,
    /// ofs-delta: base 在 pack 内的绝对偏移
    pub base_offset: Option<u64>,
    /// ref-delta: base 的 object id
    pub base_oid: Option<String>,
    /// zlib 流起点（绝对偏移）
    pub data_start: u64,
    /// zlib 流长度（边界，由解压器实际消耗得出）
    pub data_len: u64,
    pub inflated: Vec<u8>,
    pub zlib_ok: bool,
    /// 头部声明大小 == 实际解压大小
    pub size_ok: bool,
    pub error: Option<String>,
}

pub struct ParsedPack {
    pub version: u32,
    pub object_count: u32,
    pub trailer_sha1: String,
    pub computed_sha1: String,
    pub checksum_ok: bool,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<String>,
}

pub fn parse_pack(bytes: &[u8]) -> Result<ParsedPack, String> {
    if bytes.len() < 12 + 20 {
        return Err("pack 文件过短（小于 header+trailer）".to_string());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".to_string());
    }
    let version = be_u32(bytes, 4);
    let object_count = be_u32(bytes, 8);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let body_end = bytes.len() - 20;
    let trailer_sha1 = hex::encode(&bytes[body_end..]);
    let computed_sha1 = gitobj::sha1_hex(&bytes[..body_end]);
    let checksum_ok = trailer_sha1 == computed_sha1;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for index in 0..object_count {
        if pos >= body_end {
            errors.push(format!(
                "第 {index} 个对象：对象区提前结束（声明 {object_count} 个对象）"
            ));
            break;
        }
        let offset = pos as u64;
        let mut cursor = pos;
        let mut byte = bytes[cursor];
        cursor += 1;
        let type_code = (byte >> 4) & 0x07;
        let obj_type = ObjType::from_code(type_code);
        let mut declared_size = (byte & 0x0f) as u64;
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            if cursor >= body_end {
                errors.push(format!("偏移 {offset}：对象头 varint 越界"));
                break;
            }
            byte = bytes[cursor];
            cursor += 1;
            declared_size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
        }
        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            ObjType::OfsDelta => {
                if cursor >= body_end {
                    errors.push(format!("偏移 {offset}：ofs-delta 偏移字段截断"));
                    break;
                }
                let mut c = bytes[cursor];
                cursor += 1;
                let mut distance = (c & 0x7f) as u64;
                while c & 0x80 != 0 {
                    if cursor >= body_end {
                        errors.push(format!("偏移 {offset}：ofs-delta 偏移字段截断"));
                        break;
                    }
                    c = bytes[cursor];
                    cursor += 1;
                    distance = ((distance + 1) << 7) | (c & 0x7f) as u64;
                }
                if distance > offset {
                    errors.push(format!(
                        "偏移 {offset}：ofs-delta 距离 {distance} 越界（指向 pack 起点之前）"
                    ));
                    base_offset = None;
                } else {
                    base_offset = Some(offset - distance);
                }
            }
            ObjType::RefDelta => {
                if cursor + 20 > body_end {
                    errors.push(format!("偏移 {offset}：ref-delta base oid 截断"));
                    break;
                }
                base_oid = Some(hex::encode(&bytes[cursor..cursor + 20]));
                cursor += 20;
            }
            _ => {}
        }
        let header_len = cursor as u64 - offset;
        let data_start = cursor as u64;
        match gitobj::zlib_inflate(&bytes[cursor..body_end], INFLATE_CAP) {
            Ok((inflated, consumed)) => {
                let size_ok = inflated.len() as u64 == declared_size;
                let error = if size_ok {
                    None
                } else {
                    Some(format!(
                        "大小欺骗：头部声明 {declared_size} 字节，实际解压 {} 字节",
                        inflated.len()
                    ))
                };
                entries.push(PackEntry {
                    offset,
                    obj_type,
                    declared_size,
                    header_len,
                    base_offset,
                    base_oid,
                    data_start,
                    data_len: consumed as u64,
                    inflated,
                    zlib_ok: true,
                    size_ok,
                    error,
                });
                pos = cursor + consumed;
            }
            Err(e) => {
                entries.push(PackEntry {
                    offset,
                    obj_type,
                    declared_size,
                    header_len,
                    base_offset,
                    base_oid,
                    data_start,
                    data_len: 0,
                    inflated: Vec::new(),
                    zlib_ok: false,
                    size_ok: false,
                    error: Some(e),
                });
                errors.push(format!(
                    "偏移 {offset}：zlib 边界无法确定，后续 {} 个对象无法定位",
                    object_count - index - 1
                ));
                break;
            }
        }
    }
    Ok(ParsedPack {
        version,
        object_count,
        trailer_sha1,
        computed_sha1,
        checksum_ok,
        entries,
        errors,
    })
}

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: Option<u32>,
}

pub struct ParsedIdx {
    pub version: u32,
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: Option<String>,
    pub checksum_ok: Option<bool>,
    pub errors: Vec<String>,
}

pub fn parse_idx(bytes: &[u8]) -> Result<ParsedIdx, String> {
    if bytes.len() >= 8 && bytes[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        parse_idx_v2(bytes)
    } else {
        parse_idx_v1(bytes)
    }
}

fn parse_idx_v2(bytes: &[u8]) -> Result<ParsedIdx, String> {
    let version = be_u32(bytes, 4);
    if version != 2 {
        return Err(format!("不支持的 index 版本 {version}"));
    }
    if bytes.len() < 8 + 256 * 4 + 40 {
        return Err("index v2 文件过短".to_string());
    }
    let fanout_start = 8usize;
    let count = be_u32(bytes, fanout_start + 255 * 4) as usize;
    let names_start = fanout_start + 256 * 4;
    let crc_start = names_start + count * 20;
    let off32_start = crc_start + count * 4;
    let off64_start = off32_start + count * 4;
    if bytes.len() < off64_start + 40 {
        return Err("index v2 文件截断".to_string());
    }
    let trailer_start = bytes.len() - 40;
    if off64_start > trailer_start {
        return Err("index v2 偏移表越界".to_string());
    }
    let large_count = (trailer_start - off64_start) / 8;
    let mut entries = Vec::with_capacity(count);
    let mut errors = Vec::new();
    for i in 0..count {
        let oid = hex::encode(&bytes[names_start + i * 20..names_start + i * 20 + 20]);
        let crc32 = be_u32(bytes, crc_start + i * 4);
        let raw = be_u32(bytes, off32_start + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            if idx >= large_count {
                errors.push(format!("oid {oid}：大偏移表下标 {idx} 越界"));
                continue;
            }
            be_u64(bytes, off64_start + idx * 8)
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid,
            offset,
            crc32: Some(crc32),
        });
    }
    let pack_sha1 = hex::encode(&bytes[trailer_start..trailer_start + 20]);
    let idx_sha1 = hex::encode(&bytes[trailer_start + 20..trailer_start + 40]);
    let computed = gitobj::sha1_hex(&bytes[..trailer_start + 20]);
    Ok(ParsedIdx {
        version: 2,
        entries,
        pack_sha1: Some(pack_sha1),
        checksum_ok: Some(computed == idx_sha1),
        errors,
    })
}

fn parse_idx_v1(bytes: &[u8]) -> Result<ParsedIdx, String> {
    if bytes.len() < 256 * 4 {
        return Err("index v1 文件过短".to_string());
    }
    let count = be_u32(bytes, 255 * 4) as usize;
    if bytes.len() != 256 * 4 + count * 24 {
        return Err(format!(
            "无法识别的 index 格式（长度 {} 与 v1 期望 {} 不符）",
            bytes.len(),
            256 * 4 + count * 24
        ));
    }
    // fanout 单调性校验
    let mut prev = 0u32;
    for i in 0..256 {
        let v = be_u32(bytes, i * 4);
        if v < prev {
            return Err("无法识别的 index 格式（fanout 非单调）".to_string());
        }
        prev = v;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let base = 256 * 4 + i * 24;
        let offset = be_u32(bytes, base) as u64;
        let oid = hex::encode(&bytes[base + 4..base + 24]);
        entries.push(IdxEntry {
            oid,
            offset,
            crc32: None,
        });
    }
    Ok(ParsedIdx {
        version: 1,
        entries,
        pack_sha1: None,
        checksum_ok: None,
        errors: Vec::new(),
    })
}

pub struct ParsedLoose {
    pub obj_type: String,
    pub size: u64,
    pub content: Vec<u8>,
    pub oid: String,
}

pub fn parse_loose(bytes: &[u8]) -> Result<ParsedLoose, String> {
    let (inflated, _consumed) = gitobj::zlib_inflate(bytes, INFLATE_CAP)?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象缺少头部 NUL 分隔符".to_string())?;
    let header = std::str::from_utf8(&inflated[..nul])
        .map_err(|_| "loose 对象头部不是合法 UTF-8".to_string())?;
    let (type_name, size_str) = header
        .split_once(' ')
        .ok_or_else(|| format!("loose 对象头部格式错误: {header:?}"))?;
    let size: u64 = size_str
        .parse()
        .map_err(|_| format!("loose 对象头部大小非法: {size_str:?}"))?;
    let content = inflated[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "大小欺骗：头部声明 {size} 字节，实际内容 {} 字节",
            content.len()
        ));
    }
    let oid = gitobj::object_id(type_name, &content);
    Ok(ParsedLoose {
        obj_type: type_name.to_string(),
        size,
        content,
        oid,
    })
}

/// 判断导入字节流的类型
pub fn detect_kind(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[0..4] == b"PACK" {
        return "pack";
    }
    if bytes.len() >= 4 && bytes[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        return "index";
    }
    if parse_idx_v1(bytes).is_ok() {
        return "index";
    }
    if gitobj::zlib_inflate(bytes, 1 << 20).is_ok() {
        return "loose";
    }
    "unknown"
}
