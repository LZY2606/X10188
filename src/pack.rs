//! Pack / index / loose object 解析(不调用系统 git)。

use crate::gitobj::{hex_encode, sha1_hex, ObjType};
use flate2::{Decompress, FlushDecompress};

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub offset: u64,
    pub typ: ObjType,
    pub declared_size: u64,
    pub data_start: u64,
    pub data_end: u64, // zlib 流结束位置(边界)
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_ok: bool,
    pub error: Option<String>,
}

/// 受限解压 zlib 流,返回 (输出, 消耗的输入字节数)。
/// max_out 为输出上限(含),超过即报错,防止大小欺骗/解压炸弹。
pub fn inflate_bounded(data: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), String> {
    let cap = max_out.min(256 << 20) as usize;
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(1 << 20));
    let chunk = 65536usize;
    loop {
        let in_pos = d.total_in() as usize;
        if in_pos >= data.len() {
            return Err(format!("zlib 流在第 {} 字节处被截断", in_pos));
        }
        let before_out = d.total_out() as usize;
        let room = cap.saturating_sub(before_out);
        if room == 0 {
            return Err(format!("解压输出超过上限 {} 字节", max_out));
        }
        let want = chunk.min(room);
        out.resize(before_out + want, 0);
        let status = d
            .decompress(
                &data[in_pos..],
                &mut out[before_out..before_out + want],
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 解压失败: {}", e))?;
        let produced = d.total_out() as usize;
        out.truncate(produced);
        match status {
            flate2::Status::StreamEnd => {
                return Ok((out, d.total_in() as usize));
            }
            _ => {
                if produced as u64 > max_out {
                    return Err(format!("解压输出超过上限 {} 字节", max_out));
                }
                if d.total_in() as usize == in_pos && produced == before_out {
                    return Err("zlib 流无进展(数据损坏)".to_string());
                }
            }
        }
    }
}

pub fn parse_pack(data: &[u8]) -> PackFile {
    let mut pf = PackFile {
        version: 0,
        count: 0,
        entries: Vec::new(),
        trailer_ok: false,
        error: None,
    };
    if data.len() < 12 + 20 {
        pf.error = Some("pack 太短,缺少 header/trailer".into());
        return pf;
    }
    if &data[0..4] != b"PACK" {
        pf.error = Some("缺少 PACK 魔数".into());
        return pf;
    }
    pf.version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    pf.count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if pf.version != 2 && pf.version != 3 {
        pf.error = Some(format!("不支持的 pack 版本 {}", pf.version));
        return pf;
    }
    // trailer 校验
    let body = &data[..data.len() - 20];
    let trailer = &data[data.len() - 20..];
    pf.trailer_ok = sha1_hex(body) == hex_encode(trailer);

    let mut pos: u64 = 12;
    for _ in 0..pf.count {
        if pos as usize >= body.len() {
            pf.error = Some(format!("对象列表在偏移 {} 处截断", pos));
            break;
        }
        let entry_offset = pos;
        let mut idx = pos as usize;
        let b0 = data[idx];
        idx += 1;
        let typ_code = (b0 >> 4) & 0x7;
        let mut size: u64 = (b0 & 0x0f) as u64;
        let mut shift = 4u32;
        let mut b = b0;
        while b & 0x80 != 0 {
            if idx >= body.len() {
                break;
            }
            b = data[idx];
            idx += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        let typ = match ObjType::from_u8(typ_code) {
            Some(t) => t,
            None => {
                pf.entries.push(PackEntry {
                    offset: entry_offset,
                    typ: ObjType::Blob,
                    declared_size: size,
                    data_start: idx as u64,
                    data_end: idx as u64,
                    base_offset: None,
                    base_oid: None,
                    error: Some(format!("未知对象类型 {}", typ_code)),
                });
                // 无法定位下一个对象,停止解析
                pf.error = Some(format!("偏移 {} 处类型非法,解析中止", entry_offset));
                break;
            }
        };
        let mut base_offset = None;
        let mut base_oid = None;
        let mut entry_error = None;
        match typ {
            ObjType::OfsDelta => {
                if idx >= body.len() {
                    entry_error = Some("ofs-delta 偏移字段截断".into());
                } else {
                    let mut b = data[idx];
                    idx += 1;
                    let mut ofs: u64 = (b & 0x7f) as u64;
                    while b & 0x80 != 0 {
                        if idx >= body.len() {
                            break;
                        }
                        b = data[idx];
                        idx += 1;
                        ofs = ((ofs + 1) << 7) | ((b & 0x7f) as u64);
                    }
                    if ofs == 0 || ofs > entry_offset {
                        entry_error = Some(format!(
                            "ofs-delta 距离 {} 越界(对象偏移 {})",
                            ofs, entry_offset
                        ));
                    } else {
                        base_offset = Some(entry_offset - ofs);
                    }
                }
            }
            ObjType::RefDelta => {
                if idx + 20 > body.len() {
                    entry_error = Some("ref-delta base oid 截断".into());
                } else {
                    base_oid = Some(hex_encode(&data[idx..idx + 20]));
                    idx += 20;
                }
            }
            _ => {}
        }
        let data_start = idx as u64;
        // 找 zlib 边界:上限取声明大小(留给调用方核对),这里只定位流终点
        let max_probe = (body.len() - idx) as u64;
        let (data_end, zerr) = match inflate_bounded(&data[idx..body.len()], max_probe.max(1)) {
            Ok((_out, consumed)) => ((idx + consumed) as u64, None),
            Err(e) => (body.len() as u64, Some(e)),
        };
        if let Some(e) = zerr {
            entry_error = Some(match entry_error {
                Some(prev) => format!("{}; {}", prev, e),
                None => e,
            });
        }
        pf.entries.push(PackEntry {
            offset: entry_offset,
            typ,
            declared_size: size,
            data_start,
            data_end,
            base_offset,
            base_oid,
            error: entry_error,
        });
        pos = data_end.max(data_start + 1);
    }
    if pf.entries.len() != pf.count as usize && pf.error.is_none() {
        pf.error = Some(format!(
            "header 声明 {} 个对象,实际解析出 {}",
            pf.count,
            pf.entries.len()
        ));
    }
    pf
}

#[derive(Clone, Debug)]
pub struct IdxRow {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub rows: Vec<IdxRow>,
    pub error: Option<String>,
}

pub fn parse_idx(data: &[u8]) -> IdxFile {
    let mut f = IdxFile {
        version: 2,
        fanout: [0; 256],
        rows: Vec::new(),
        error: None,
    };
    if data.len() < 8 + 256 * 4 {
        f.error = Some("index 太短".into());
        return f;
    }
    let mut pos = 0usize;
    if data[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        f.version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        pos = 8;
        if f.version != 2 {
            f.error = Some(format!("不支持的 index 版本 {}", f.version));
            return f;
        }
    } else {
        f.error = Some("仅支持 index v2".into());
        return f;
    }
    for i in 0..256 {
        f.fanout[i] = u32::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
    }
    let n = f.fanout[255] as usize;
    let need = pos + n * 20 + n * 4 + n * 4;
    if data.len() < need + 40 {
        f.error = Some(format!("index 截断:需要至少 {} 字节", need + 40));
        return f;
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(hex_encode(&data[pos..pos + 20]));
        pos += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]));
        pos += 4;
    }
    let mut offs = Vec::with_capacity(n);
    let mut large_idx = Vec::new();
    for i in 0..n {
        let v = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        if v & 0x8000_0000 != 0 {
            large_idx.push((i, (v & 0x7fff_ffff) as usize));
            offs.push(0u64);
        } else {
            offs.push(v as u64);
        }
    }
    for (i, li) in large_idx {
        let p = pos + li * 8;
        if p + 8 > data.len() {
            f.error = Some("大偏移表截断".into());
            return f;
        }
        offs[i] = u64::from_be_bytes([
            data[p],
            data[p + 1],
            data[p + 2],
            data[p + 3],
            data[p + 4],
            data[p + 5],
            data[p + 6],
            data[p + 7],
        ]);
    }
    for i in 0..n {
        f.rows.push(IdxRow {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset: offs[i],
        });
    }
    f
}

/// 解析 loose object (zlib 压缩的 "<type> <len>\0<content>")
pub fn parse_loose(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let (raw, _consumed) = inflate_bounded(data, 256 << 20)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose object 缺少 header 终止符".to_string())?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose header 非 UTF-8")?;
    let mut it = header.splitn(2, ' ');
    let typ = it.next().unwrap_or("");
    let len: usize = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "loose header 缺少长度".to_string())?;
    match typ {
        "commit" | "tree" | "blob" | "tag" => {}
        _ => return Err(format!("loose object 类型非法: {}", typ)),
    }
    let content = &raw[nul + 1..];
    if content.len() != len {
        return Err(format!(
            "loose object 大小欺骗:声明 {} 实际 {}",
            len,
            content.len()
        ));
    }
    Ok((typ.to_string(), content.to_vec()))
}
