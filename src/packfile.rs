use crate::gitobj;
use crc32fast::Hasher as Crc32;
use flate2::{Decompress, FlushDecompress, Status};

/// One parsed object entry inside a pack.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub seq: usize,
    pub offset: u64,
    pub type_code: u8,
    pub size_declared: u64,
    /// Absolute offset of the base object (ofs-delta only).
    pub base_offset: Option<u64>,
    /// Base object id (ref-delta only).
    pub base_oid: Option<[u8; 20]>,
    /// Offset where the zlib stream starts.
    pub data_start: u64,
    /// Offset one past the end of the zlib stream.
    pub data_end: u64,
    /// Inflated zlib payload (full content, or delta program for delta entries).
    pub payload: Vec<u8>,
    /// CRC-32 of the raw on-disk bytes `offset..data_end`.
    pub crc32: u32,
    /// Non-fatal parse problem; the entry is isolated but parsing continues.
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    /// Pack-level problems (bad magic, trailing garbage, count mismatch...).
    pub errors: Vec<String>,
}

/// Inflate a zlib stream starting at `input[0]`.
/// Returns (inflated bytes, compressed bytes consumed).
pub fn inflate_zlib(input: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let consumed = d.total_in() as usize;
        if consumed > input.len() {
            return Err("zlib 解压器越界消费输入".into());
        }
        if consumed == input.len() {
            return Err(format!(
                "zlib 流截断: 已消费 {} 字节, 输出 {} 字节, 流未结束",
                consumed,
                out.len()
            ));
        }
        let before_out = d.total_out() as usize;
        let status = d
            .decompress(&input[consumed..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - before_out;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > max_out {
            return Err(format!(
                "解压输出超过安全上限 {} 字节 (疑似解压炸弹)",
                max_out
            ));
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if produced == 0 && d.total_in() as usize == consumed {
                    return Err("zlib 流无法继续 (输入耗尽或损坏)".into());
                }
            }
        }
    }
}

fn parse_entry(data: &[u8], pos: usize, seq: usize, max_out: u64) -> Result<PackEntry, String> {
    let offset = pos as u64;
    let mut p = pos;
    let mut parse_error: Option<String> = None;

    // Object header: type + size varint.
    let mut c = *data.get(p).ok_or("对象头越界")?;
    p += 1;
    let type_code = (c >> 4) & 0x7;
    let mut size: u64 = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = *data.get(p).ok_or("对象头 size varint 越界")?;
        p += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象头 size varint 过长".into());
        }
    }

    let mut base_offset = None;
    let mut base_oid = None;
    match type_code {
        6 => {
            // ofs-delta: negative offset varint.
            let mut c = *data.get(p).ok_or("ofs-delta 偏移越界")?;
            p += 1;
            let mut dist: u64 = (c & 0x7f) as u64;
            while c & 0x80 != 0 {
                c = *data.get(p).ok_or("ofs-delta 偏移 varint 越界")?;
                p += 1;
                dist = ((dist + 1) << 7) | ((c & 0x7f) as u64);
                if dist > (1 << 62) {
                    return Err("ofs-delta 距离溢出".into());
                }
            }
            if dist > offset {
                parse_error = Some(format!(
                    "ofs 距离越界: 条目偏移 {}, 向后距离 {} 指到文件头之前",
                    offset, dist
                ));
                base_offset = None;
            } else {
                base_offset = Some(offset - dist);
            }
        }
        7 => {
            // ref-delta: 20-byte base oid.
            if p + 20 > data.len() {
                return Err("ref-delta base oid 越界".into());
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[p..p + 20]);
            base_oid = Some(oid);
            p += 20;
        }
        1..=4 => {}
        other => return Err(format!("未知对象类型码 {}", other)),
    }

    let data_start = p as u64;
    let (payload, consumed) = inflate_zlib(&data[p..], max_out)?;
    let data_end = data_start + consumed as u64;

    if payload.len() as u64 != size {
        parse_error = Some(match parse_error {
            Some(e) => format!(
                "{}; 大小欺骗: 头部声明 {} 字节, 实际解压 {} 字节",
                e,
                size,
                payload.len()
            ),
            None => format!(
                "大小欺骗: 头部声明 {} 字节, 实际解压 {} 字节",
                size,
                payload.len()
            ),
        });
    }

    let mut crc = Crc32::new();
    crc.update(&data[offset as usize..data_end as usize]);
    let crc32 = crc.finalize();

    Ok(PackEntry {
        seq,
        offset,
        type_code,
        size_declared: size,
        base_offset,
        base_oid,
        data_start,
        data_end,
        payload,
        crc32,
        parse_error,
    })
}

pub fn parse_pack(data: &[u8], max_out: u64) -> Result<PackFile, String> {
    if data.len() < 12 {
        return Err("文件太小, 不是 pack".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {}", version));
    }
    let declared_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for seq in 0..declared_count as usize {
        if pos >= data.len() {
            errors.push(format!(
                "pack 截断: 声明 {} 个对象, 只解析到 {} 个",
                declared_count, seq
            ));
            break;
        }
        match parse_entry(data, pos, seq, max_out) {
            Ok(e) => {
                pos = e.data_end as usize;
                entries.push(e);
            }
            Err(err) => {
                errors.push(format!("对象 #{} (偏移 {}): {}", seq, pos, err));
                break;
            }
        }
    }
    if entries.len() == declared_count as usize {
        let trailer = &data[pos..];
        if trailer.len() < 20 {
            errors.push("pack 尾部缺少 20 字节校验和".into());
        } else if trailer.len() > 20 {
            errors.push(format!("pack 尾部多出 {} 字节垃圾", trailer.len() - 20));
        }
    }
    Ok(PackFile {
        version,
        declared_count,
        entries,
        errors,
    })
}

// ---------------- idx (v2 / v1) ----------------

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxFile, String> {
    if data.len() < 4 * 256 {
        return Err("文件太小, 不是 idx".into());
    }
    if data[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        parse_idx_v2(data)
    } else {
        parse_idx_v1(data)
    }
}

fn parse_idx_v2(data: &[u8]) -> Result<IdxFile, String> {
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {}", version));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let b = 8 + i * 4;
        fanout[i] = u32::from_be_bytes([data[b], data[b + 1], data[b + 2], data[b + 3]]);
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            return Err(format!("fanout 表在桶 {} 处非单调", i));
        }
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    if data.len() < off_base + n * 4 {
        return Err("idx 截断".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let c = crc_base + i * 4;
        let crc32 = u32::from_be_bytes([data[c], data[c + 1], data[c + 2], data[c + 3]]);
        let o = off_base + i * 4;
        let raw = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let b = big_base + idx * 8;
            if b + 8 > data.len() {
                return Err("idx 大偏移表越界".into());
            }
            u64::from_be_bytes(data[b..b + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    Ok(IdxFile {
        version: 2,
        fanout,
        entries,
    })
}

fn parse_idx_v1(data: &[u8]) -> Result<IdxFile, String> {
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let b = i * 4;
        fanout[i] = u32::from_be_bytes([data[b], data[b + 1], data[b + 2], data[b + 3]]);
    }
    let n = fanout[255] as usize;
    let base = 256 * 4;
    if data.len() < base + n * 24 {
        return Err("idx v1 截断".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let b = base + i * 24;
        let offset = u32::from_be_bytes([data[b], data[b + 1], data[b + 2], data[b + 3]]) as u64;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[b + 4..b + 24]);
        entries.push(IdxEntry { oid, crc32: 0, offset });
    }
    Ok(IdxFile {
        version: 1,
        fanout,
        entries,
    })
}

/// Loose object: zlib of "<type> <size>\0<content>".
#[derive(Debug, Clone)]
pub struct LooseObject {
    pub type_name: String,
    pub content: Vec<u8>,
    pub oid: [u8; 20],
}

pub fn parse_loose(data: &[u8], max_out: u64) -> Result<LooseObject, String> {
    let (raw, _) = inflate_zlib(data, max_out)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose 对象缺少头部 NUL")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let (tname, size_s) = header
        .split_once(' ')
        .ok_or("loose 头部缺少空格分隔")?;
    let size: u64 = size_s.parse().map_err(|_| "loose 头部大小非法")?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose 大小欺骗: 头部声明 {} 字节, 实际 {} 字节",
            size,
            content.len()
        ));
    }
    if !["commit", "tree", "blob", "tag"].contains(&tname) {
        return Err(format!("loose 类型未知: {}", tname));
    }
    let oid = gitobj::object_id(tname, &content);
    Ok(LooseObject {
        type_name: tname.to_string(),
        content,
        oid,
    })
}
