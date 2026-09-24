//! Git pack 解析：header、对象类型、ofs/ref-delta 头、zlib 边界。
//! 不使用系统 git。

use anyhow::{bail, Result};
use flate2::{Decompress, FlushDecompress, Status};

pub const PACK_HEADER_LEN: u64 = 12;
/// 解压上限，防止恶意构造的膨胀数据耗尽内存。
pub const INFLATE_CAP: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl EntryKind {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Commit,
            2 => Self::Tree,
            3 => Self::Blob,
            4 => Self::Tag,
            6 => Self::OfsDelta,
            7 => Self::RefDelta,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            Self::OfsDelta => "ofs-delta",
            Self::RefDelta => "ref-delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, Self::OfsDelta | Self::RefDelta)
    }
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "commit" => Self::Commit,
            "tree" => Self::Tree,
            "blob" => Self::Blob,
            "tag" => Self::Tag,
            "ofs-delta" => Self::OfsDelta,
            "ref-delta" => Self::RefDelta,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub kind: EntryKind,
    /// 头部声明的（还原后）大小
    pub declared_size: u64,
    /// 压缩数据起点（含 delta 的 base 信息之后）
    pub data_offset: u64,
    /// zlib 流长度（边界）
    pub data_len: u64,
    pub inflated_len: u64,
    /// ofs-delta: 负距离（相对本对象头起点）
    pub ofs_distance: Option<u64>,
    /// ofs-delta: 解析出的 base 绝对偏移（越界时为 None）
    pub base_offset: Option<u64>,
    /// ref-delta: base oid
    pub base_oid: Option<[u8; 20]>,
    pub crc32: u32,
    /// 单对象级解析错误（不影响其它对象）
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Pack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// 尾部 sha1（前 len-20 字节的校验和），以及是否匹配
    pub trailer_sha1: String,
    pub trailer_ok: bool,
}

/// 解压 zlib 流并返回 (解压结果, 消耗的输入字节数) —— 即 zlib 边界。
pub fn inflate_bound(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= data.len() {
            bail!("zlib 流被截断");
        }
        let status = d
            .decompress(&data[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| anyhow::anyhow!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        if out.len() > INFLATE_CAP {
            bail!("解压大小超过安全上限");
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if produced == 0 && d.total_in() as usize == in_before {
                    bail!("zlib 流无进展（数据损坏）");
                }
            }
        }
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_pack(data: &[u8]) -> Result<Pack> {
    if data.len() < PACK_HEADER_LEN as usize + 20 || &data[0..4] != b"PACK" {
        bail!("不是 pack 文件（缺少 PACK 魔数）");
    }
    let version = be32(&data[4..8]);
    let count = be32(&data[8..12]);
    if version != 2 && version != 3 {
        bail!("不支持的 pack 版本 {version}");
    }
    let body_end = data.len() - 20;
    let trailer_sha1 = hex::encode(&data[body_end..]);
    let trailer_ok = crate::gitutil::sha1_hex(&data[..body_end]) == trailer_sha1;

    let mut entries = Vec::new();
    let mut pos = PACK_HEADER_LEN as usize;
    for _ in 0..count {
        if pos >= body_end {
            bail!("pack 对象数量超过实际数据（截断）");
        }
        let start = pos;
        let mut entry = PackEntry {
            offset: start as u64,
            kind: EntryKind::Blob,
            declared_size: 0,
            data_offset: 0,
            data_len: 0,
            inflated_len: 0,
            ofs_distance: None,
            base_offset: None,
            base_oid: None,
            crc32: 0,
            parse_error: None,
        };
        // 对象头：类型 + 变长大小
        let mut b = data[pos];
        pos += 1;
        let kind_code = (b >> 4) & 0x7;
        let mut size = (b & 0x0f) as u64;
        let mut shift = 4u32;
        while b & 0x80 != 0 {
            if pos >= body_end {
                entry.parse_error = Some("对象头截断".into());
                entries.push(entry);
                return Ok(Pack { version, count, entries, trailer_sha1, trailer_ok });
            }
            b = data[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        entry.declared_size = size;
        entry.kind = match EntryKind::from_code(kind_code) {
            Some(k) => k,
            None => {
                entry.parse_error = Some(format!("未知对象类型 {kind_code}"));
                entries.push(entry);
                continue;
            }
        };
        // delta 的 base 信息
        match entry.kind {
            EntryKind::OfsDelta => {
                let mut b = data[pos];
                pos += 1;
                let mut dist = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    b = data[pos];
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
                }
                entry.ofs_distance = Some(dist);
                let s = start as u64;
                if dist == 0 || dist > s - PACK_HEADER_LEN {
                    entry.parse_error =
                        Some(format!("ofs 距离越界: -{dist} 超出 pack 起始范围"));
                } else {
                    entry.base_offset = Some(s - dist);
                }
            }
            EntryKind::RefDelta => {
                if pos + 20 > body_end {
                    entry.parse_error = Some("ref-delta base oid 截断".into());
                    entries.push(entry);
                    continue;
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&data[pos..pos + 20]);
                entry.base_oid = Some(oid);
                pos += 20;
            }
            _ => {}
        }
        entry.data_offset = pos as u64;
        // zlib 边界
        match inflate_bound(&data[pos..body_end]) {
            Ok((inflated, consumed)) => {
                entry.inflated_len = inflated.len() as u64;
                entry.data_len = consumed as u64;
                pos += consumed;
            }
            Err(e) => {
                entry.parse_error = Some(format!("{e:#}"));
                entry.data_len = (body_end - pos) as u64;
                entries.push(entry);
                // zlib 边界未知，后续对象无法定位，隔离到此为止
                return Ok(Pack { version, count, entries, trailer_sha1, trailer_ok });
            }
        }
        entry.crc32 = crate::gitutil::crc32(&data[start..pos]);
        entries.push(entry);
    }
    Ok(Pack { version, count, entries, trailer_sha1, trailer_ok })
}
