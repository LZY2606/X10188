//! PACK 文件解析：header、对象类型、ofs/ref-delta、zlib 流边界。

use crate::gitutil::*;
use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub offset: u64,
    pub header_len: u64,
    pub otype: ObjType,
    pub declared_size: u64,
    /// ofs-delta: 相对距离（entry.offset - distance = base offset）
    pub base_distance: Option<u64>,
    /// ref-delta: base 的 oid
    pub base_oid: Option<String>,
    pub data_offset: u64,
    pub data_len: u64, // zlib 压缩流长度
    pub decompressed_len: u64,
    pub size_spoofed: bool, // 解压结果与声明大小不符
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: String, // sha1 hex
    pub trailer_ok: bool,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub enum PackError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u32),
    Truncated(String),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackError::TooShort => write!(f, "文件太短，不是合法 pack"),
            PackError::BadMagic => write!(f, "缺少 PACK 魔数"),
            PackError::UnsupportedVersion(v) => write!(f, "不支持的 pack 版本 {v}"),
            PackError::Truncated(m) => write!(f, "pack 截断: {m}"),
        }
    }
}

/// 解压 zlib 流并返回 (输出, 消耗的输入字节数)。
/// `cap` 限制最大输出字节，防止解压炸弹；超出时报错。
pub fn inflate_bounded(input: &[u8], cap: u64) -> Result<(Vec<u8>, u64), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let in_before = d.total_in();
        let out_before = d.total_out();
        let remaining = cap.saturating_sub(out_before) as usize;
        if remaining == 0 {
            return Err(format!("解压输出超过上限 {cap} 字节"));
        }
        let slice_end = std::cmp::min(buf.len(), remaining);
        let status = d
            .decompress(
                &input[in_before as usize..],
                &mut buf[..slice_end],
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = (d.total_out() - out_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => return Ok((out, d.total_in())),
            Status::Ok | Status::BufError => {
                if d.total_in() as usize >= input.len() && produced == 0 {
                    return Err("zlib 流提前结束（数据截断）".to_string());
                }
            }
        }
    }
}

pub fn parse_pack(data: &[u8]) -> Result<ParsedPack, PackError> {
    if data.len() < 12 + 20 {
        return Err(PackError::TooShort);
    }
    if &data[0..4] != b"PACK" {
        return Err(PackError::BadMagic);
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(PackError::UnsupportedVersion(version));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let trailer_start = data.len() - 20;
    let trailer = hex::encode(&data[trailer_start..]);
    let mut h = sha1::Sha1::new();
    use sha1::Digest;
    h.update(&data[..trailer_start]);
    let trailer_ok = hex::encode(h.finalize()) == trailer;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for idx in 0..count as usize {
        if pos >= trailer_start {
            errors.push(format!("对象 #{idx} 起始偏移 {pos} 超出数据区"));
            break;
        }
        let entry_offset = pos as u64;
        let (tcode, size, hlen) = parse_entry_header(data, pos)
            .ok_or_else(|| PackError::Truncated(format!("对象 #{idx} 头部越界")))?;
        pos += hlen;
        let otype = ObjType::from_pack_code(tcode)
            .ok_or_else(|| PackError::Truncated(format!("对象 #{idx} 未知类型码 {tcode}")))?;
        let mut base_distance = None;
        let mut base_oid = None;
        match otype {
            ObjType::OfsDelta => {
                let (dist, used) = parse_ofs_distance(data, pos)
                    .ok_or_else(|| PackError::Truncated(format!("对象 #{idx} ofs 距离越界")))?;
                pos += used;
                base_distance = Some(dist);
            }
            ObjType::RefDelta => {
                if pos + 20 > trailer_start {
                    return Err(PackError::Truncated(format!("对象 #{idx} ref-delta base oid 越界")));
                }
                base_oid = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {}
        }
        let data_offset = pos as u64;
        // 用声明大小作为解压上限；若声明被伪造（偏小），允许放宽到 64MiB 再判定 spoof
        let cap = std::cmp::max(size, 1) * 4 + 1024;
        let cap = std::cmp::min(cap, 64 * 1024 * 1024);
        match inflate_bounded(&data[pos..trailer_start], cap) {
            Ok((raw, consumed)) => {
                let spoofed = raw.len() as u64 != size;
                entries.push(PackEntry {
                    index: idx,
                    offset: entry_offset,
                    header_len: hlen as u64,
                    otype,
                    declared_size: size,
                    base_distance,
                    base_oid,
                    data_offset,
                    data_len: consumed,
                    decompressed_len: raw.len() as u64,
                    size_spoofed: spoofed,
                });
                pos += consumed as usize;
            }
            Err(e) => {
                errors.push(format!("对象 #{idx} (offset {entry_offset}): {e}"));
                break;
            }
        }
    }
    if entries.len() < count as usize && errors.is_empty() {
        errors.push(format!(
            "声明 {count} 个对象，仅解析出 {}",
            entries.len()
        ));
    }
    Ok(ParsedPack {
        version,
        count,
        entries,
        trailer,
        trailer_ok,
        errors,
    })
}
