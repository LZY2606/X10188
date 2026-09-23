use crate::delta::parse_delta;
use crate::hash::sha1_bytes;
use crate::oid::Oid;
use crate::types::GitType;
use crate::zlib::inflate_zlib;
use serde::Serialize;
use std::collections::BTreeSet;

pub const PACK_MAGIC: &[u8; 4] = b"PACK";

#[derive(Clone, Debug, Serialize)]
pub struct PackHeader {
    pub version: u32,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackEntry {
    pub index: u32,
    pub offset: u64,
    pub end_offset: u64,
    pub kind: GitType,
    pub size_declared: u64,
    /// ofs-delta: base 在 pack 内的绝对偏移（距离越界时为 None）
    pub base_offset: Option<u64>,
    pub base_distance: Option<u64>,
    /// ref-delta: base 的 oid
    pub base_oid: Option<Oid>,
    pub inflated: Option<Vec<u8>>,
    pub delta_base_size: Option<u64>,
    pub delta_result_size: Option<u64>,
    pub crc32: u32,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PackParse {
    pub header: Option<PackHeader>,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<String>,
    pub pack_checksum: Option<String>,
    pub checksum_ok: Option<bool>,
}

/// 解析 pack。idx_offsets 提供已知条目偏移表，用于在单个条目损坏时跳过并继续。
pub fn parse_pack(data: &[u8], idx_offsets: Option<&BTreeSet<u64>>) -> PackParse {
    let mut res = PackParse::default();
    if data.len() < 12 + 20 {
        res.errors.push(format!("文件太小 ({} 字节)，不是有效 pack", data.len()));
        return res;
    }
    if &data[0..4] != PACK_MAGIC {
        res.errors.push("缺少 PACK 魔数".to_string());
        return res;
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != 2 && version != 3 {
        res.errors.push(format!("不支持的 pack 版本 {version}"));
        return res;
    }
    res.header = Some(PackHeader { version, count });

    let body_end = data.len() - 20;
    let mut pos: usize = 12;
    let mut idx: u32 = 0;
    while idx < count && pos < body_end {
        let entry_start = pos;
        match parse_entry(data, body_end, entry_start, idx) {
            Ok((entry, next)) => {
                pos = next;
                res.entries.push(entry);
            }
            Err(e) => {
                res.errors.push(format!("条目 #{idx} @0x{entry_start:x}: {e}"));
                res.entries.push(PackEntry {
                    index: idx,
                    offset: entry_start as u64,
                    end_offset: entry_start as u64,
                    kind: GitType::Blob,
                    size_declared: 0,
                    base_offset: None,
                    base_distance: None,
                    base_oid: None,
                    inflated: None,
                    delta_base_size: None,
                    delta_result_size: None,
                    crc32: 0,
                    parse_error: Some(e),
                });
                // 尝试借助 index 偏移表跳过坏条目，隔离错误继续解析
                if let Some(offsets) = idx_offsets {
                    match offsets.range((entry_start as u64 + 1)..).next() {
                        Some(&next) if (next as usize) < body_end => {
                            pos = next as usize;
                        }
                        _ => break,
                    }
                } else {
                    break;
                }
            }
        }
        idx += 1;
    }
    if res.entries.len() < count as usize {
        res.errors.push(format!(
            "头部声明 {count} 个对象，实际解析出 {} 个",
            res.entries.len()
        ));
    }

    let trailer = &data[data.len() - 20..];
    res.pack_checksum = Some(hex::encode(trailer));
    res.checksum_ok = Some(sha1_bytes(&data[..data.len() - 20]) == trailer);
    res
}

fn parse_entry(
    data: &[u8],
    body_end: usize,
    start: usize,
    index: u32,
) -> Result<(PackEntry, usize), String> {
    let mut pos = start;
    let read_u8 = |pos: &mut usize| -> Result<u8, String> {
        if *pos >= body_end {
            return Err("条目头部被截断".to_string());
        }
        let b = data[*pos];
        *pos += 1;
        Ok(b)
    };

    let mut c = read_u8(&mut pos)?;
    let type_code = (c >> 4) & 0x7;
    let kind = GitType::from_pack_code(type_code)
        .ok_or_else(|| format!("未知对象类型码 {type_code}"))?;
    let mut size: u64 = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = read_u8(&mut pos)?;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("条目大小字段过长".to_string());
        }
    }

    let mut base_offset = None;
    let mut base_distance = None;
    let mut base_oid = None;
    match kind {
        GitType::OfsDelta => {
            let mut c = read_u8(&mut pos)?;
            let mut dist: u64 = (c & 0x7f) as u64;
            while c & 0x80 != 0 {
                c = read_u8(&mut pos)?;
                dist = ((dist + 1) << 7) | ((c & 0x7f) as u64);
            }
            base_distance = Some(dist);
            base_offset = (start as u64).checked_sub(dist);
        }
        GitType::RefDelta => {
            if pos + 20 > body_end {
                return Err("ref-delta base oid 被截断".to_string());
            }
            base_oid = Oid::from_bytes(&data[pos..pos + 20]);
            pos += 20;
        }
        _ => {}
    }

    let (inflated, parse_error, consumed) = match inflate_zlib(&data[pos..body_end], size) {
        Ok((out, consumed)) => (Some(out), None, consumed),
        Err(e) => {
            // 无法确定 zlib 边界时，条目到此为止
            (None, Some(e.to_string()), 0)
        }
    };
    let end = pos + consumed;

    let (delta_base_size, delta_result_size) = if kind.is_delta() {
        match inflated.as_ref().map(|d| parse_delta(d)) {
            Some(Ok(p)) => (Some(p.base_size), Some(p.result_size)),
            Some(Err(e)) => {
                let msg = e.to_string();
                return Ok((
                    PackEntry {
                        index,
                        offset: start as u64,
                        end_offset: end as u64,
                        kind,
                        size_declared: size,
                        base_offset,
                        base_distance,
                        base_oid,
                        inflated,
                        delta_base_size: None,
                        delta_result_size: None,
                        crc32: crc32fast::hash(&data[start..end]),
                        parse_error: Some(format!("delta 指令解析失败: {msg}")),
                    },
                    end,
                ));
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    Ok((
        PackEntry {
            index,
            offset: start as u64,
            end_offset: end as u64,
            kind,
            size_declared: size,
            base_offset,
            base_distance,
            base_oid,
            inflated,
            delta_base_size,
            delta_result_size,
            crc32: crc32fast::hash(&data[start..end]),
            parse_error,
        },
        end,
    ))
}
