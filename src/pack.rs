//! Git pack 与 pack index (v2) 的纯 Rust 解析：header、条目头、
//! ofs-delta 距离编码、ref-delta 基 oid、fanout 表。不调用系统 git。

use crate::gitobj;

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u32,
    pub count: u32,
}

pub fn parse_header(data: &[u8]) -> Result<PackHeader, String> {
    if data.len() < 12 {
        return Err("pack 文件太小，缺少头部".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    Ok(PackHeader { version, count })
}

#[derive(Debug, Clone)]
pub struct EntryHead {
    pub offset: u64,
    pub type_code: u8,
    pub declared_size: u64,
    /// ofs-delta：base 条目在 pack 内的绝对偏移
    pub base_offset: Option<u64>,
    /// ref-delta：base 对象的 oid
    pub base_oid: Option<String>,
    /// zlibzlib 压缩流的起始偏移
    pub data_start: u64,
}

pub fn parse_entry_head(data: &[u8], offset: u64) -> Result<EntryHead, String> {
    let mut p = offset as usize;
    let mut b = *data.get(p).ok_or("条目头越界")?;
    p += 1;
    let type_code = (b >> 4) & 0x07;
    if gitobj::type_name(type_code).is_none() {
        return Err(format!("未知对象类型码 {type_code}"));
    }
    let mut size = (b & 0x0f) as u64;
    let mut shift = 4u32;
    while b & 0x80 != 0 {
        b = *data.get(p).ok_or("条目头 size 越界")?;
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("条目声明大小溢出".into());
        }
    }
    let (base_offset, base_oid) = match type_code {
        6 => {
            // ofs-delta：变长距离编码
            let mut b2 = *data.get(p).ok_or("ofs-delta 距离越界")?;
            p += 1;
            let mut dist = (b2 & 0x7f) as u64;
            while b2 & 0x80 != 0 {
                b2 = *data.get(p).ok_or("ofs-delta 距离越界")?;
                p += 1;
                dist = ((dist + 1) << 7) | (b2 & 0x7f) as u64;
            }
            if dist == 0 || dist > offset {
                return Err(format!(
                    "ofs-delta 距离越界: 距离 {dist}, 条目偏移 {offset}"
                ));
            }
            (Some(offset - dist), None)
        }
        7 => {
            let oid_bytes = data.get(p..p + 20).ok_or("ref-delta base oid 越界")?;
            p += 20;
            (None, Some(gitobj::hex(oid_bytes)))
        }
        _ => (None, None),
    };
    Ok(EntryHead {
        offset,
        type_code,
        declared_size: size,
        base_offset,
        base_oid,
        data_start: p as u64,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Idx {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
}

/// 解析 idx v2（\\377tOc）。校验 fanout 单调性与每个 oid 首字节分桶是否一致。
pub fn parse_idx(data: &[u8]) -> Result<Idx, String> {
    if data.len() < 8 + 256 * 4 {
        return Err("idx 文件太小".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 idx v2 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version}"));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(data[8 + i * 4..12 + i * 4].try_into().unwrap());
        if i > 0 && fanout[i] < fanout[i - 1] {
            return Err("fanout 表非单调递增".into());
        }
    }
    let count = fanout[255] as usize;
    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + count * 20;
    let off_start = crc_start + count * 4;
    let big_start = off_start + count * 4;
    if data.len() < big_start {
        return Err("idx 文件被截断".into());
    }
    let mut entries = Vec::with_capacity(count);
    let mut per_bucket = [0u32; 256];
    for i in 0..count {
        let oid = gitobj::hex(&data[oid_start + i * 20..oid_start + i * 20 + 20]);
        let crc32 = u32::from_be_bytes(data[crc_start + i * 4..crc_start + i * 4 + 4].try_into().unwrap());
        let raw_off = u32::from_be_bytes(data[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap());
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let p = big_start + idx * 8;
            let b = data.get(p..p + 8).ok_or("idx 大偏移表越界")?;
            u64::from_be_bytes(b.try_into().unwrap())
        } else {
            raw_off as u64
        };
        let first = oid.as_bytes()[0];
        let bucket = u8::from_str_radix(&oid[0..2], 16).map_err(|_| "oid 非 hex")?;
        let _ = first;
        per_bucket[bucket as usize] += 1;
        entries.push(IdxEntry { oid, crc32, offset });
    }
    // 校验 fanout 与实际 oid 首字节分布一致
    let mut acc = 0u32;
    for i in 0..256 {
        acc += per_bucket[i];
        if acc != fanout[i] {
            return Err(format!("fanout[{i}]={} 与实际 oid 分布 {acc} 不符", fanout[i]));
        }
    }
    Ok(Idx { fanout, entries })
}

/// 根据内容嗅探导入文件类型。
pub fn detect_kind(data: &[u8]) -> &'static str {
    if data.starts_with(b"PACK") {
        "pack"
    } else if data.starts_with(b"\xfftOc") {
        "idx"
    } else if data.len() >= 2 && looks_like_zlib(data) {
        "loose"
    } else {
        "unknown"
    }
}

fn looks_like_zlib(data: &[u8]) -> bool {
    let cmf = data[0] as u16;
    let flg = data[1] as u16;
    (cmf & 0x0f) == 8 && (cmf * 256 + flg) % 31 == 0
}
