//! PACK 文件解析：header、对象类型、ofs-delta / ref-delta 头、zlib 边界。

use crate::gitobj::{inflate_bounded, ObjType, OID_LEN};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub idx: usize,
    pub offset: u64,
    pub obj_type: ObjType,
    /// 头部声明的（解压后）大小
    pub hdr_size: u64,
    /// 对象头（含 delta 基信息）之后的压缩数据起点
    pub data_offset: u64,
    /// zlib 压缩流长度（边界由解压器 total_in 确定）
    pub data_len: u64,
    /// ofs-delta: base 在 pack 内的绝对偏移
    pub base_offset: Option<u64>,
    /// ref-delta: base 的 oid
    pub base_oid: Option<[u8; OID_LEN]>,
}

#[derive(Debug)]
pub struct PackScan {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    /// pack 尾部 sha1 校验是否通过
    pub trailer_ok: bool,
    pub trailer_oid: [u8; OID_LEN],
    /// 扫描过程中的结构性错误（截断等），条目解析到此处为止
    pub errors: Vec<String>,
}

/// 解析 pack 对象头：type + size varint。返回 (类型码, size, 消耗字节数)
fn parse_obj_header(data: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let mut p = pos;
    let b = data[p];
    p += 1;
    let code = (b >> 4) & 0x7;
    let mut size: u64 = (b & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cur = b;
    while cur & 0x80 != 0 {
        if p >= data.len() || shift > 60 {
            return None;
        }
        cur = data[p];
        p += 1;
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
    }
    Some((code, size, p - pos))
}

/// 解析 ofs-delta 的距离编码。返回 (距离, 消耗字节数)
fn parse_ofs_distance(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let mut p = pos;
    let mut b = data[p];
    p += 1;
    let mut n: u64 = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if p >= data.len() {
            return None;
        }
        b = data[p];
        p += 1;
        n = ((n + 1) << 7) | ((b & 0x7f) as u64);
    }
    Some((n, p - pos))
}

/// 扫描整个 pack。条目数据上限用于防止头部大小欺骗导致的海量解压。
pub fn scan_pack(data: &[u8]) -> Result<PackScan, String> {
    if data.len() < 12 + OID_LEN {
        return Err("pack 太小，缺少 header 或 trailer".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK magic".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let declared_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let body_end = data.len() - OID_LEN;
    let mut hasher = Sha1::new();
    hasher.update(&data[..body_end]);
    let digest = hasher.finalize();
    let mut trailer_oid = [0u8; OID_LEN];
    trailer_oid.copy_from_slice(&data[body_end..]);
    let trailer_ok = digest.as_slice() == trailer_oid;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos: usize = 12;
    for idx in 0..declared_count {
        if pos >= body_end {
            errors.push(format!(
                "条目 {idx}: 偏移 {pos} 越过 pack 数据末尾 {body_end}（截断）"
            ));
            break;
        }
        let offset = pos as u64;
        let (code, hdr_size, used) = match parse_obj_header(&data[..body_end], pos) {
            Some(v) => v,
            None => {
                errors.push(format!("条目 {idx} @ {offset}: 对象头损坏"));
                break;
            }
        };
        pos += used;
        let obj_type = match ObjType::from_pack_code(code) {
            Some(t) => t,
            None => {
                errors.push(format!("条目 {idx} @ {offset}: 未知类型码 {code}"));
                break;
            }
        };
        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            ObjType::OfsDelta => match parse_ofs_distance(&data[..body_end], pos) {
                Some((dist, used)) => {
                    pos += used;
                    if dist > offset {
                        errors.push(format!(
                            "条目 {idx} @ {offset}: ofs 距离 {dist} 越界（指向 pack 外）"
                        ));
                        // 仍记录条目，base_offset 置空
                    } else {
                        base_offset = Some(offset - dist);
                    }
                }
                None => {
                    errors.push(format!("条目 {idx} @ {offset}: ofs 距离编码损坏"));
                    break;
                }
            },
            ObjType::RefDelta => {
                if pos + OID_LEN > body_end {
                    errors.push(format!("条目 {idx} @ {offset}: ref-delta base oid 截断"));
                    break;
                }
                let mut oid = [0u8; OID_LEN];
                oid.copy_from_slice(&data[pos..pos + OID_LEN]);
                base_oid = Some(oid);
                pos += OID_LEN;
            }
            _ => {}
        }
        let data_offset = pos as u64;
        // 用受限解压确定 zlib 边界；上限给声明大小 + 余量，欺骗在还原阶段再严格判定
        let cap = hdr_size.saturating_add(4096).min(512 * 1024 * 1024);
        match inflate_bounded(&data[pos..body_end], cap) {
            Ok((_out, used)) => {
                entries.push(PackEntry {
                    idx,
                    offset,
                    obj_type,
                    hdr_size,
                    data_offset,
                    data_len: used as u64,
                    base_offset,
                    base_oid,
                });
                pos += used;
            }
            Err(e) => {
                errors.push(format!("条目 {idx} @ {offset}: zlib 边界确定失败: {e}"));
                break;
            }
        }
    }
    if entries.len() == declared_count as usize && pos != body_end {
        errors.push(format!(
            "条目扫描结束于 {pos}，与数据末尾 {body_end} 不一致（垃圾字节或计数错误）"
        ));
    }
    Ok(PackScan {
        version,
        declared_count,
        entries,
        trailer_ok,
        trailer_oid,
        errors,
    })
}
