use crate::gitobj::{inflate_stream, InflateError};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: u8,
    pub declared_size: u64,
    pub data_offset: u64,
    pub data_len: u64,
    /// ofs-delta: base 在 pack 内的绝对偏移
    pub base_offset: Option<u64>,
    /// ref-delta: base 的 object id
    pub base_oid: Option<String>,
    pub inflated: Vec<u8>,
    pub crc32: u32,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_ok: bool,
    pub checksum: String,
    pub errors: Vec<String>,
}

fn parse_type_size(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= data.len() {
        return Err("对象头被截断".into());
    }
    let mut c = data[pos];
    pos += 1;
    let obj_type = (c >> 4) & 0x7;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4;
    while c & 0x80 != 0 {
        if pos >= data.len() {
            return Err("对象头被截断".into());
        }
        c = data[pos];
        pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象头 size 溢出".into());
        }
    }
    Ok((obj_type, size, pos))
}

fn parse_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= data.len() {
        return Err("ofs-delta 距离字段被截断".into());
    }
    let mut c = data[pos];
    pos += 1;
    let mut dist = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if pos >= data.len() {
            return Err("ofs-delta 距离字段被截断".into());
        }
        c = data[pos];
        pos += 1;
        dist = ((dist + 1) << 7) | (c & 0x7f) as u64;
    }
    Ok((dist, pos))
}

pub fn parse_pack(data: &[u8], hard_cap: u64) -> Result<ParsedPack, String> {
    if data.len() < 12 + 20 {
        return Err("pack 太小，缺少 header 或 trailer".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {}", version));
    }
    let declared_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let end = data.len() - 20;
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;

    for i in 0..declared_count {
        if pos >= end {
            errors.push(format!(
                "第 {} 个对象开始前数据已耗尽（声明 {} 个对象）",
                i, declared_count
            ));
            break;
        }
        let entry_start = pos;
        let mut entry_error: Option<String> = None;
        let (obj_type, declared_size, p1) = match parse_type_size(data, pos) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("偏移 {:#x}: {}", pos, e));
                break;
            }
        };
        pos = p1;
        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            1..=4 => {}
            6 => match parse_ofs_distance(data, pos) {
                Ok((dist, p2)) => {
                    pos = p2;
                    if dist == 0 || dist > entry_start as u64 {
                        entry_error = Some(format!(
                            "ofs 距离越界: 距离 {} 超出当前偏移 {:#x}",
                            dist, entry_start
                        ));
                    } else {
                        base_offset = Some(entry_start as u64 - dist);
                    }
                }
                Err(e) => {
                    errors.push(format!("偏移 {:#x}: {}", entry_start, e));
                    break;
                }
            },
            7 => {
                if pos + 20 > end {
                    errors.push(format!("偏移 {:#x}: ref-delta base oid 被截断", entry_start));
                    break;
                }
                base_oid = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {
                errors.push(format!("偏移 {:#x}: 未知对象类型 {}", entry_start, obj_type));
                break;
            }
        }
        let data_offset = pos;
        let inflated = match inflate_stream(&data[pos..end], hard_cap) {
            Ok(inf) => {
                pos += inf.consumed;
                inf.data
            }
            Err(InflateError::Truncated) => {
                errors.push(format!("偏移 {:#x}: zlib 流被截断，pack 后续对象无法定位", entry_start));
                break;
            }
            Err(InflateError::Corrupt(e)) => {
                errors.push(format!("偏移 {:#x}: zlib 数据损坏: {}", entry_start, e));
                break;
            }
            Err(InflateError::TooLarge { cap }) => {
                errors.push(format!(
                    "偏移 {:#x}: 解压输出超过硬上限 {} 字节，已隔离该对象及 pack 尾部",
                    entry_start, cap
                ));
                break;
            }
        };
        // 解压完成后比对声明大小：大小欺骗检测
        if inflated.len() as u64 != declared_size {
            entry_error = Some(format!(
                "大小欺骗: 头部声明 {} 字节，实际解压 {} 字节",
                declared_size,
                inflated.len()
            ));
        }
        let crc32 = crc32fast::hash(&data[entry_start..pos]);
        entries.push(PackEntry {
            offset: entry_start as u64,
            obj_type,
            declared_size,
            data_offset: data_offset as u64,
            data_len: (pos - data_offset) as u64,
            base_offset,
            base_oid,
            inflated,
            crc32,
            error: entry_error,
        });
    }
    if pos < end && entries.len() == declared_count as usize {
        errors.push(format!(
            "pack 尾部存在 {} 字节未声明的额外数据",
            end - pos
        ));
    }
    // 校验 ofs 目标是否指向已知 entry 起点
    let starts: std::collections::HashSet<u64> = entries.iter().map(|e| e.offset).collect();
    for e in entries.iter_mut() {
        if e.error.is_none() {
            if let Some(bo) = e.base_offset {
                if !starts.contains(&bo) {
                    e.error = Some(format!("ofs 目标 {:#x} 不是任何对象的起点", bo));
                }
            }
        }
    }
    let trailer = &data[data.len() - 20..];
    let mut h = Sha1::new();
    h.update(&data[..data.len() - 20]);
    let calc = h.finalize();
    let trailer_ok = calc.as_slice() == trailer;
    if !trailer_ok {
        errors.push(format!(
            "pack 校验和不匹配: 文件记录 {}，实际计算 {}",
            hex::encode(trailer),
            hex::encode(calc)
        ));
    }
    Ok(ParsedPack {
        version,
        declared_count,
        entries,
        trailer_ok,
        checksum: hex::encode(trailer),
        errors,
    })
}
