use crate::model::ObjType;
use crate::oid::{self, Oid};
use crate::zlib;

#[derive(Clone, Debug)]
pub struct PackEntry {
    /// 对象头在 pack 文件中的原始偏移
    pub offset: u64,
    pub obj_type: ObjType,
    /// 头部声明的（解压后）大小
    pub declared_size: u64,
    /// ofs-delta: 相对基点的负距离
    pub base_dist: Option<u64>,
    /// ref-delta: 基点 oid
    pub base_oid: Option<Oid>,
    /// 解压后的负载（完整对象内容或 delta 指令流）
    pub data: Vec<u8>,
    /// zlib 流长度（压缩边界）
    pub compressed_len: u64,
    /// 从对象头到 zlib 流结束的总长度
    pub raw_len: u64,
    /// 对原始字节计算的 CRC32（与 idx 对照）
    pub crc32: u32,
    /// 解析期发现的证据（如声明大小与实际不符）
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PackFile {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: Option<Oid>,
    pub errors: Vec<String>,
}

pub fn parse_pack(bytes: &[u8]) -> PackFile {
    let mut errors = Vec::new();
    let mut entries = Vec::new();
    let mut trailer = None;

    if bytes.len() < 12 + 20 {
        errors.push("pack 文件过短，缺少头部或校验和".to_string());
        return PackFile { version: 0, declared_count: 0, entries, trailer, errors };
    }
    if &bytes[0..4] != b"PACK" {
        errors.push("缺少 PACK 魔数".to_string());
        return PackFile { version: 0, declared_count: 0, entries, trailer, errors };
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 && version != 3 {
        errors.push(format!("不支持的 pack 版本 {version}"));
    }
    let declared_count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

    let body_end = bytes.len() - 20;
    let t: Oid = bytes[body_end..].try_into().unwrap();
    trailer = Some(t);
    let actual = oid::hash_bytes(&bytes[..body_end]);
    if actual != t {
        errors.push(format!(
            "pack 尾部校验和不匹配: 声明 {}，实际 {}",
            oid::to_hex(&t),
            oid::to_hex(&actual)
        ));
    }

    let mut pos = 12usize;
    for idx in 0..declared_count {
        if pos >= body_end {
            errors.push(format!(
                "pack 截断: 声明 {} 个对象，仅解析到 {} 个",
                declared_count, idx
            ));
            break;
        }
        let entry_offset = pos as u64;
        let mut c = bytes[pos];
        pos += 1;
        let type_code = (c >> 4) & 0x07;
        let mut size = (c & 0x0f) as u64;
        let mut shift = 4u32;
        while c & 0x80 != 0 {
            if pos >= body_end {
                errors.push(format!("对象 #{} 头部 varint 截断", idx));
                break;
            }
            c = bytes[pos];
            pos += 1;
            size |= ((c & 0x7f) as u64) << shift;
            shift += 7;
        }
        let obj_type = match ObjType::from_code(type_code) {
            Some(t) => t,
            None => {
                errors.push(format!("对象 #{} 类型码 {} 非法", idx, type_code));
                break;
            }
        };
        let mut base_dist = None;
        let mut base_oid = None;
        match obj_type {
            ObjType::OfsDelta => {
                if pos >= body_end {
                    errors.push(format!("对象 #{} ofs-delta 偏移截断", idx));
                    break;
                }
                let mut c = bytes[pos];
                pos += 1;
                let mut dist = (c & 0x7f) as u64;
                while c & 0x80 != 0 {
                    if pos >= body_end {
                        errors.push(format!("对象 #{} ofs-delta 偏移截断", idx));
                        break;
                    }
                    c = bytes[pos];
                    pos += 1;
                    dist = ((dist + 1) << 7) | (c & 0x7f) as u64;
                }
                base_dist = Some(dist);
            }
            ObjType::RefDelta => {
                if pos + 20 > body_end {
                    errors.push(format!("对象 #{} ref-delta base oid 截断", idx));
                    break;
                }
                base_oid = Some(bytes[pos..pos + 20].try_into().unwrap());
                pos += 20;
            }
            _ => {}
        }
        match zlib::decompress_bound(&bytes[pos..body_end]) {
            Ok((data, consumed)) => {
                pos += consumed;
                let mut evidence = Vec::new();
                if data.len() as u64 != size {
                    evidence.push(format!(
                        "大小欺骗: 头部声明 {} 字节，实际解压 {} 字节",
                        size,
                        data.len()
                    ));
                }
                let raw_len = pos as u64 - entry_offset;
                let crc32 = crc32fast::hash(&bytes[entry_offset as usize..pos]);
                entries.push(PackEntry {
                    offset: entry_offset,
                    obj_type,
                    declared_size: size,
                    base_dist,
                    base_oid,
                    data,
                    compressed_len: consumed as u64,
                    raw_len,
                    crc32,
                    evidence,
                });
            }
            Err(e) => {
                errors.push(format!(
                    "对象 #{} (偏移 {}) 解压失败: {}；后续对象边界不可信，停止解析本 pack",
                    idx, entry_offset, e
                ));
                break;
            }
        }
    }
    if entries.len() == declared_count as usize && pos != body_end {
        errors.push(format!(
            "pack 存在 {} 字节未解释的尾部数据（对象区结束于 {}，应为 {}）",
            body_end - pos,
            pos,
            body_end
        ));
    }
    PackFile { version, declared_count, entries, trailer, errors }
}
