//! Git pack file parsing: header, object entries, ofs/ref deltas, zlib boundaries.

use crate::gitobj::ObjType;
use crate::inflate::inflate_bounded;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub typ: ObjType,
    pub declared_size: u64,
    /// Absolute offset where the zlib stream begins.
    pub data_offset: u64,
    /// Compressed zlib stream length (boundary detected by the inflater).
    pub data_len: u64,
    /// Offset one past the end of this entry.
    pub end_offset: u64,
    /// ofs-delta: absolute offset of the base entry in the same pack.
    pub base_offset: Option<u64>,
    /// ref-delta: base object id.
    pub base_oid: Option<String>,
    /// crc32 of the raw entry bytes (offset..end_offset), for idx comparison.
    pub crc32: u32,
    /// Actual decompressed size (None when inflation failed).
    pub inflated_size: Option<u64>,
    pub parse_error: Option<String>,
}

#[derive(Debug)]
pub struct PackParse {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    /// Pack-level errors (truncation, resync failures, ...).
    pub errors: Vec<String>,
    pub trailer_ok: bool,
    pub trailer_expected: String,
    pub trailer_actual: String,
}

fn read_size_type(data: &[u8], pos: &mut usize) -> Result<(u8, u64), String> {
    if *pos >= data.len() {
        return Err("对象头截断".into());
    }
    let mut b = data[*pos];
    *pos += 1;
    let typ = (b >> 4) & 0x7;
    let mut size = (b & 0x0f) as u64;
    let mut shift = 4u32;
    while b & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("对象头 varint 截断".into());
        }
        b = data[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象大小 varint 过长".into());
        }
    }
    Ok((typ, size))
}

fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= data.len() {
        return Err("ofs-delta 距离截断".into());
    }
    let mut b = data[*pos];
    *pos += 1;
    let mut dist = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("ofs-delta 距离 varint 截断".into());
        }
        b = data[*pos];
        *pos += 1;
        dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
    }
    Ok(dist)
}

/// Parse a whole pack. `resync_offsets` (usually from a matching idx) lets the
/// parser skip past an entry whose zlib stream cannot be bounded.
pub fn parse_pack(
    data: &[u8],
    resync_offsets: Option<&BTreeSet<u64>>,
    inflate_limit: u64,
) -> Result<PackParse, String> {
    if data.len() < 12 + 20 {
        return Err(format!("文件太小 ({} 字节)，不是 pack", data.len()));
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let declared_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let body_end = data.len() - 20;
    let trailer_actual = hex::encode(&data[body_end..]);
    let trailer_expected = crate::gitobj::sha1_hex(&data[..body_end]);
    let trailer_ok = trailer_actual == trailer_expected;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for idx in 0..declared_count {
        if pos >= body_end {
            errors.push(format!(
                "第 {idx} 个对象起始偏移 {pos} 越过 pack 主体末尾 {body_end}（声明 {declared_count} 个对象）"
            ));
            break;
        }
        let entry_start = pos as u64;
        match parse_entry(data, body_end, entry_start, inflate_limit) {
            Ok(entry) => {
                pos = entry.end_offset as usize;
                entries.push(entry);
            }
            Err(e) => {
                // Isolate the bad entry; try to resync at the next known offset.
                let next = resync_offsets.and_then(|offs| {
                    offs.range((entry_start + 1)..=(body_end as u64)).next().copied()
                });
                match next {
                    Some(n) => {
                        errors.push(format!(
                            "偏移 {entry_start} 的对象解析失败（{e}），借助 index 在 {n} 处重新同步"
                        ));
                        entries.push(PackEntry {
                            offset: entry_start,
                            typ: ObjType::Blob,
                            declared_size: 0,
                            data_offset: entry_start,
                            data_len: 0,
                            end_offset: n,
                            base_offset: None,
                            base_oid: None,
                            crc32: crc32fast::hash(&data[entry_start as usize..n as usize]),
                            inflated_size: None,
                            parse_error: Some(e),
                        });
                        pos = n as usize;
                    }
                    None => {
                        errors.push(format!(
                            "偏移 {entry_start} 的对象解析失败且无法重新同步，跳过后续对象: {e}"
                        ));
                        break;
                    }
                }
            }
        }
    }
    Ok(PackParse {
        version,
        declared_count,
        entries,
        errors,
        trailer_ok,
        trailer_expected,
        trailer_actual,
    })
}

fn parse_entry(
    data: &[u8],
    body_end: usize,
    offset: u64,
    inflate_limit: u64,
) -> Result<PackEntry, String> {
    let mut pos = offset as usize;
    let (typ_code, declared_size) = read_size_type(data, &mut pos)?;
    let typ = ObjType::from_code(typ_code).ok_or_else(|| format!("未知对象类型码 {typ_code}"))?;
    let mut base_offset = None;
    let mut base_oid = None;
    match typ {
        ObjType::OfsDelta => {
            let dist = read_ofs_distance(data, &mut pos)?;
            if dist > offset {
                return Err(format!(
                    "ofs-delta 距离越界: 自身偏移 {offset}，回退距离 {dist}"
                ));
            }
            base_offset = Some(offset - dist);
        }
        ObjType::RefDelta => {
            if pos + 20 > data.len() {
                return Err("ref-delta base oid 截断".into());
            }
            base_oid = Some(hex::encode(&data[pos..pos + 20]));
            pos += 20;
        }
        _ => {}
    }
    let data_offset = pos as u64;
    if pos >= body_end {
        return Err("zlib 流起点越过 pack 主体末尾".into());
    }
    let inflated = inflate_bounded(&data[pos..body_end], inflate_limit)
        .map_err(|e| format!("zlib 解压失败: {e}"))?;
    let end_offset = data_offset + inflated.consumed;
    Ok(PackEntry {
        offset,
        typ,
        declared_size,
        data_offset,
        data_len: inflated.consumed,
        end_offset,
        base_offset,
        base_oid,
        crc32: crc32fast::hash(&data[offset as usize..end_offset as usize]),
        inflated_size: Some(inflated.data.len() as u64),
        parse_error: None,
    })
}
