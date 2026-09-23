//! pack / idx / loose object 的结构解析（纯 Rust，不调用系统 git）。

use crate::gitobj::*;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq)]
pub enum FileKind {
    Pack,
    Index,
    Loose,
    Unknown,
}

pub fn detect_kind(bytes: &[u8]) -> FileKind {
    if bytes.len() >= 4 && &bytes[..4] == b"PACK" {
        return FileKind::Pack;
    }
    if bytes.len() >= 4 && bytes[..4] == [0xff, 0x74, 0x4f, 0x63] {
        return FileKind::Index;
    }
    // loose object 是 zlib 流，且解压后以 "<type> <size>\0" 开头
    if bytes.len() >= 2 && bytes[0] == 0x78 {
        if let Ok((raw, _)) = zlib_decompress_bounded(bytes) {
            if let Some(nul) = raw.iter().position(|&b| b == 0) {
                let hdr = String::from_utf8_lossy(&raw[..nul]).to_string();
                let mut it = hdr.split(' ');
                if let (Some(t), Some(s)) = (it.next(), it.next()) {
                    if ["commit", "tree", "blob", "tag"].contains(&t)
                        && s.parse::<u64>().is_ok()
                    {
                        return FileKind::Loose;
                    }
                }
            }
        }
    }
    FileKind::Unknown
}

#[derive(Debug, Clone)]
pub enum BaseRef {
    /// ofs-delta：距离与计算出的 base 绝对偏移
    Ofs { distance: u64, base_offset: u64 },
    /// ref-delta：base 的 oid（hex）
    Ref(String),
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub otype: u8,
    pub declared_size: u64,
    pub hdr_len: u64,
    pub data_off: u64,
    pub data_len: u64,
    pub end_off: u64,
    pub base: Option<BaseRef>,
    pub compressed: Vec<u8>,
    pub parse_error: Option<String>,
}

pub struct PackParse {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: String,
    pub trailer_ok: bool,
    pub error: Option<String>,
}

pub fn parse_pack(bytes: &[u8]) -> Result<PackParse, String> {
    if bytes.len() < 12 + 20 {
        return Err("pack 太短，无法包含头部与校验和".into());
    }
    if &bytes[..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let declared_count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let body_end = bytes.len() - 20;
    let trailer = hex::encode(&bytes[body_end..]);
    let mut h = Sha1::new();
    h.update(&bytes[..body_end]);
    let trailer_ok = hex::encode(h.finalize()) == trailer;

    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut error: Option<String> = None;
    while pos < body_end && (entries.len() as u32) < declared_count {
        let entry_start = pos;
        let (otype, size) = match read_type_size(bytes, &mut pos) {
            Ok(v) => v,
            Err(e) => {
                error = Some(format!("偏移 {}: {}", entry_start, e));
                break;
            }
        };
        let base = match otype {
            OBJ_OFS_DELTA => match read_ofs_distance(bytes, &mut pos) {
                Ok(dist) => {
                    if dist > entry_start as u64 {
                        error = Some(format!(
                            "偏移 {}: ofs 距离越界（distance={} 超过当前偏移）",
                            entry_start, dist
                        ));
                        None
                    } else {
                        Some(BaseRef::Ofs {
                            distance: dist,
                            base_offset: entry_start as u64 - dist,
                        })
                    }
                }
                Err(e) => {
                    error = Some(format!("偏移 {}: {}", entry_start, e));
                    None
                }
            },
            OBJ_REF_DELTA => {
                if pos + 20 > body_end {
                    error = Some(format!("偏移 {}: ref-delta base oid 截断", entry_start));
                    None
                } else {
                    let oid = hex::encode(&bytes[pos..pos + 20]);
                    pos += 20;
                    Some(BaseRef::Ref(oid))
                }
            }
            _ => None,
        };
        if error.is_some() && base.is_none() && matches!(otype, OBJ_OFS_DELTA | OBJ_REF_DELTA) {
            break;
        }
        let data_off = pos;
        match zlib_decompress_bounded(&bytes[data_off..body_end]) {
            Ok((_raw, consumed)) => {
                let end_off = data_off + consumed;
                entries.push(PackEntry {
                    offset: entry_start as u64,
                    otype,
                    declared_size: size,
                    hdr_len: (data_off - entry_start) as u64,
                    data_off: data_off as u64,
                    data_len: consumed as u64,
                    end_off: end_off as u64,
                    base,
                    compressed: bytes[data_off..end_off].to_vec(),
                    parse_error: None,
                });
                pos = end_off;
            }
            Err(e) => {
                // 坏对象隔离：记录该对象，停止本 pack 后续解析（偏移未知），
                // 但不影响其他 pack / loose 的分析。
                entries.push(PackEntry {
                    offset: entry_start as u64,
                    otype,
                    declared_size: size,
                    hdr_len: (data_off - entry_start) as u64,
                    data_off: data_off as u64,
                    data_len: 0,
                    end_off: data_off as u64,
                    base,
                    compressed: Vec::new(),
                    parse_error: Some(format!("zlib 边界解析失败: {}", e)),
                });
                error = Some(format!(
                    "偏移 {} 起 zlib 流损坏，本 pack 后续对象无法定位",
                    entry_start
                ));
                break;
            }
        }
    }
    if entries.len() as u32 != declared_count && error.is_none() {
        error = Some(format!(
            "对象数不符：头部声明 {}，实际解析 {}",
            declared_count,
            entries.len()
        ));
    }
    Ok(PackParse {
        version,
        declared_count,
        entries,
        trailer,
        trailer_ok,
        error,
    })
}

pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

pub struct IdxParse {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub idx_sha1_ok: bool,
}

pub fn parse_idx(bytes: &[u8]) -> Result<IdxParse, String> {
    if bytes.len() < 8 + 256 * 4 + 40 {
        return Err("idx 文件太短".into());
    }
    if bytes[..4] != [0xff, 0x74, 0x4f, 0x63] {
        return Err("缺少 idx 魔数".into());
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 {
        return Err(format!("仅支持 idx v2，实际 v{}", version));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let b = 8 + i * 4;
        fanout[i] = u32::from_be_bytes([bytes[b], bytes[b + 1], bytes[b + 2], bytes[b + 3]]);
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            return Err("fanout 表非单调递增".into());
        }
    }
    let n = fanout[255] as usize;
    let need = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + 40;
    if bytes.len() < need {
        return Err(format!("idx 截断：需要至少 {} 字节，实际 {}", need, bytes.len()));
    }
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&bytes[oid_base + i * 20..oid_base + i * 20 + 20]);
        let c = crc_base + i * 4;
        let crc32 = u32::from_be_bytes([bytes[c], bytes[c + 1], bytes[c + 2], bytes[c + 3]]);
        let o = off_base + i * 4;
        let raw_off = u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let b = big_base + idx * 8;
            if b + 8 > bytes.len() {
                return Err("idx 大偏移表越界".into());
            }
            u64::from_be_bytes(bytes[b..b + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&bytes[bytes.len() - 40..bytes.len() - 20]);
    let idx_sha1 = hex::encode(&bytes[bytes.len() - 20..]);
    let mut h = Sha1::new();
    h.update(&bytes[..bytes.len() - 20]);
    let idx_sha1_ok = hex::encode(h.finalize()) == idx_sha1;
    Ok(IdxParse {
        fanout,
        entries,
        pack_sha1,
        idx_sha1,
        idx_sha1_ok,
    })
}

pub struct LooseParse {
    pub type_name: String,
    pub content: Vec<u8>,
    pub oid: String,
}

pub fn parse_loose(bytes: &[u8]) -> Result<LooseParse, String> {
    let (raw, _consumed) = zlib_decompress_bounded(bytes)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象缺少头部 NUL".to_string())?;
    let hdr = String::from_utf8_lossy(&raw[..nul]).to_string();
    let mut it = hdr.splitn(2, ' ');
    let type_name = it.next().ok_or("loose 头部缺少类型")?.to_string();
    let size: u64 = it
        .next()
        .ok_or("loose 头部缺少大小")?
        .parse()
        .map_err(|_| "loose 头部大小非法")?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose 大小欺骗：头部声明 {}，实际 {}",
            size,
            content.len()
        ));
    }
    let oid = object_id(&type_name, &content);
    Ok(LooseParse {
        type_name,
        content,
        oid,
    })
}
