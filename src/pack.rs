use flate2::{Decompress, FlushDecompress, Status};

use crate::gitutil;

/// 单个 pack 条目的扫描结果(保留原始偏移与边界)。
#[derive(Clone, Debug)]
pub struct PackEntry {
    pub offset: u64,
    pub end_offset: u64,
    pub type_code: u8,
    pub declared_size: u64,
    pub header_len: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub crc32: u32,
}

#[derive(Clone, Debug)]
pub struct PackScan {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha1: String,
    pub trailer_ok: bool,
    pub warnings: Vec<String>,
}

/// 解析 pack 对象头: 返回 (type_code, declared_size, header_len)
pub fn parse_entry_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    let start = pos;
    let mut p = pos;
    let mut byte = *data.get(p).ok_or("对象头越界: 缺少首字节")?;
    p += 1;
    let type_code = (byte >> 4) & 0x7;
    let mut size = (byte & 0x0f) as u64;
    let mut shift = 4u32;
    while byte & 0x80 != 0 {
        byte = *data.get(p).ok_or("对象头越界: varint 截断")?;
        p += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象头 varint 过长".into());
        }
    }
    Ok((type_code, size, p - start))
}

/// 解析 ofs-delta 的距离编码, 返回 (distance, consumed)
pub fn parse_ofs_distance(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let start = pos;
    let mut p = pos;
    let mut byte = *data.get(p).ok_or("ofs-delta 距离越界")?;
    p += 1;
    let mut off = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        byte = *data.get(p).ok_or("ofs-delta 距离越界")?;
        p += 1;
        off = ((off + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok((off, p - start))
}

/// 找出 zlib 流在 data 中的结束位置(消费的字节数), 用于确定对象边界。
pub fn zlib_stream_end(data: &[u8]) -> Result<usize, String> {
    let mut d = Decompress::new(true);
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in() as usize;
        if in_before >= data.len() {
            return Err("zlib 流意外截断".into());
        }
        let status = d
            .decompress(&data[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        match status {
            Status::StreamEnd => return Ok(d.total_in() as usize),
            Status::Ok => {}
            Status::BufError => {
                if d.total_in() as usize == in_before {
                    return Err("zlib 流无法继续(数据损坏或截断)".into());
                }
            }
        }
    }
}

/// 完整解压一个 zlib 流, 返回 (内容, 消费字节数)。max_out 为硬上限, 防止解压炸弹。
pub fn zlib_decompress(data: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in() as usize;
        if in_before > data.len() {
            return Err("zlib 内部状态错误".into());
        }
        if in_before == data.len() {
            return Err("zlib 流意外截断".into());
        }
        let status = d
            .decompress(&data[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - out.len();
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > max_out {
            return Err(format!("展开超过硬上限 {max_out} 字节, 拒绝继续"));
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok => {}
            Status::BufError => {
                if d.total_in() as usize == in_before {
                    return Err("zlib 流无法继续(数据损坏或截断)".into());
                }
            }
        }
    }
}

/// 扫描整个 pack 文件, 记录每个条目的偏移、类型、base 引用与 zlib 边界。
pub fn parse_pack(data: &[u8]) -> Result<PackScan, String> {
    if data.len() < 12 + 20 {
        return Err("pack 文件过短".into());
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
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut pos = 12usize;
    while pos < body_end && (entries.len() as u32) < declared_count {
        let entry_offset = pos as u64;
        let (type_code, declared_size, hlen) = parse_entry_header(data, pos)?;
        pos += hlen;
        let mut base_offset = None;
        let mut base_oid = None;
        match type_code {
            gitutil::OBJ_OFS_DELTA => {
                let (dist, used) = parse_ofs_distance(data, pos)?;
                pos += used;
                if dist == 0 || dist > entry_offset {
                    warnings.push(format!(
                        "条目 @{entry_offset}: ofs 距离 {dist} 越界"
                    ));
                } else {
                    base_offset = Some(entry_offset - dist);
                }
            }
            gitutil::OBJ_REF_DELTA => {
                if pos + 20 > body_end {
                    return Err(format!("条目 @{entry_offset}: ref-delta base oid 截断"));
                }
                base_oid = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            gitutil::OBJ_COMMIT | gitutil::OBJ_TREE | gitutil::OBJ_BLOB | gitutil::OBJ_TAG => {}
            other => {
                return Err(format!("条目 @{entry_offset}: 未知对象类型 {other}"));
            }
        }
        let consumed = zlib_stream_end(&data[pos..body_end])
            .map_err(|e| format!("条目 @{entry_offset}: {e}"))?;
        let end = pos + consumed;
        let mut crc = flate2::Crc::new();
        crc.update(&data[entry_offset as usize..end]);
        entries.push(PackEntry {
            offset: entry_offset,
            end_offset: end as u64,
            type_code,
            declared_size,
            header_len: (end as u64) - entry_offset,
            base_offset,
            base_oid,
            crc32: crc.sum(),
        });
        pos = end;
    }
    if (entries.len() as u32) != declared_count {
        warnings.push(format!(
            "头部声明 {declared_count} 个对象, 实际扫描到 {}",
            entries.len()
        ));
    }
    if pos != body_end {
        warnings.push(format!(
            "扫描结束于 {pos}, 与 pack 主体末尾 {body_end} 不一致"
        ));
    }
    let trailer_sha1 = hex::encode(&data[body_end..]);
    let trailer_ok = gitutil::sha1_hex(&data[..body_end]) == trailer_sha1;
    if !trailer_ok {
        warnings.push("pack 尾部校验和不匹配".into());
    }
    Ok(PackScan {
        version,
        declared_count,
        entries,
        trailer_sha1,
        trailer_ok,
        warnings,
    })
}
