//! Git pack / pack-index 解析（不调用系统 git）。

use crc32fast::Hasher as CrcHasher;
use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }
    pub fn git_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    /// 从条目起点到 zlib 流起点的头部字节数
    pub header_len: u64,
    pub data_start: u64,
    /// zlib 流结束位置（边界）
    pub data_end: u64,
    /// ofs-delta：base 在 pack 内的绝对偏移
    pub base_offset: Option<u64>,
    /// ref-delta：base 的 oid（hex）
    pub base_oid: Option<String>,
    pub crc32: u32,
    /// 解压后的内容（完整对象内容或 delta 指令流）
    pub inflated: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_oid: String,
    pub trailer_ok: bool,
    pub errors: Vec<String>,
}

/// 流式解压 zlib，返回 (输出, 消耗的输入字节数)。
/// `size_cap`：声明大小 +1，用于在解压到一半时发现“大小欺骗”。
fn inflate_bounded(input: &[u8], size_cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let chunk = 8192usize;
    loop {
        let before_in = d.total_in() as usize;
        let before_out = d.total_out() as usize;
        let end = (pos + chunk).min(input.len());
        // 输出缓冲：本次最多再产出 cap+1
        let want = (size_cap + 1).saturating_sub(out.len() as u64).max(4096) as usize;
        out.resize(out.len() + want, 0u8);
        let res = d
            .decompress(&input[pos..end], &mut out[before_out..], FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - before_out;
        out.truncate(before_out + produced);
        pos += d.total_in() as usize - before_in;
        if out.len() as u64 > size_cap {
            return Err(format!(
                "大小欺骗：解压到一半输出已超过声明大小 {} 字节",
                size_cap - 1
            ));
        }
        match res {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if pos >= input.len() {
                    return Err("zlib 流被截断：输入耗尽但未到达流结尾".to_string());
                }
            }
        }
    }
}

/// 完整解压（loose object 用），返回 (输出, 消耗字节数)。
pub fn inflate_all(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    inflate_bounded(input, u64::MAX - 1)
}

pub fn git_oid(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn parse_pack(data: &[u8]) -> PackFile {
    let mut errors = Vec::new();
    let mut entries = Vec::new();
    let mut version = 0u32;
    let mut declared_count = 0u32;
    let mut trailer_oid = String::new();
    let mut trailer_ok = false;

    if data.len() < 12 + 20 {
        errors.push("文件太短，不是合法 pack".into());
        return PackFile { version, declared_count, entries, trailer_oid, trailer_ok, errors };
    }
    if &data[0..4] != b"PACK" {
        errors.push("缺少 PACK 魔数".into());
        return PackFile { version, declared_count, entries, trailer_oid, trailer_ok, errors };
    }
    version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    declared_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if version != 2 && version != 3 {
        errors.push(format!("不支持的 pack 版本 {version}"));
    }

    // 校验尾部 sha1
    let body_end = data.len() - 20;
    let mut h = Sha1::new();
    h.update(&data[..body_end]);
    let expect = hex::encode(h.finalize());
    trailer_oid = hex::encode(&data[body_end..]);
    trailer_ok = expect == trailer_oid;
    if !trailer_ok {
        errors.push(format!(
            "pack 尾部校验失败：期望 {expect}，实际 {trailer_oid}"
        ));
    }

    let mut pos = 12usize;
    for idx in 0..declared_count {
        if pos >= body_end {
            errors.push(format!("第 {idx} 个条目起点越界，pack 被截断"));
            break;
        }
        let entry_offset = pos as u64;
        match parse_entry(data, pos, body_end, entry_offset) {
            Ok((entry, next)) => {
                pos = next;
                entries.push(entry);
            }
            Err(e) => {
                errors.push(format!("条目 #{idx} (偏移 {entry_offset}) 解析失败：{e}"));
                break; // zlib 边界未知，无法继续定位后续条目
            }
        }
    }
    if entries.len() == declared_count as usize && pos != body_end {
        errors.push(format!(
            "条目结束后存在 {} 字节多余数据",
            body_end as i64 - pos as i64
        ));
    }

    PackFile { version, declared_count, entries, trailer_oid, trailer_ok, errors }
}

fn parse_entry(
    data: &[u8],
    mut pos: usize,
    limit: usize,
    entry_offset: u64,
) -> Result<(PackEntry, usize), String> {
    // 类型 + 大小 varint
    let mut c = *data.get(pos).ok_or("条目头部越界")?;
    pos += 1;
    let type_code = (c >> 4) & 0x7;
    let obj_type = ObjType::from_code(type_code)
        .ok_or_else(|| format!("未知对象类型码 {type_code}"))?;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = *data.get(pos).ok_or("大小 varint 越界")?;
        pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("大小 varint 过长".into());
        }
    }

    let mut base_offset = None;
    let mut base_oid = None;
    match obj_type {
        ObjType::OfsDelta => {
            let mut b = *data.get(pos).ok_or("ofs-delta 偏移越界")?;
            pos += 1;
            let mut dist = (b & 0x7f) as u64;
            while b & 0x80 != 0 {
                b = *data.get(pos).ok_or("ofs-delta 偏移越界")?;
                pos += 1;
                dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
            }
            if dist > entry_offset {
                return Err(format!(
                    "ofs 距离越界：距离 {dist} 超过条目偏移 {entry_offset}"
                ));
            }
            base_offset = Some(entry_offset - dist);
        }
        ObjType::RefDelta => {
            if pos + 20 > limit {
                return Err("ref-delta base oid 越界".into());
            }
            base_oid = Some(hex::encode(&data[pos..pos + 20]));
            pos += 20;
        }
        _ => {}
    }

    let data_start = pos as u64;
    let header_len = data_start - entry_offset;
    let (inflated, consumed, error) = match inflate_bounded(&data[pos..limit], size + 1) {
        Ok((out, used)) => {
            if out.len() as u64 != size {
                (
                    None,
                    used,
                    Some(format!(
                        "大小不符：声明 {size} 字节，实际解压 {} 字节",
                        out.len()
                    )),
                )
            } else {
                (Some(out), used, None)
            }
        }
        Err(e) => (None, 0, Some(e)),
    };
    let data_end = data_start + consumed as u64;

    let mut crc = CrcHasher::new();
    crc.update(&data[entry_offset as usize..data_end as usize]);
    let crc32 = crc.finalize();

    Ok((
        PackEntry {
            offset: entry_offset,
            obj_type,
            declared_size: size,
            header_len,
            data_start,
            data_end,
            base_offset,
            base_oid,
            crc32,
            inflated,
            error,
        },
        data_end as usize,
    ))
}

// ---------------- pack index (v2) ----------------

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub idx_checksum: String,
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

pub fn parse_idx(data: &[u8]) -> IdxFile {
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    let mut entries = Vec::new();
    let mut version = 1;
    let mut pack_checksum = String::new();
    let mut idx_checksum = String::new();
    let mut checksum_ok = false;

    if data.len() < 4 + 256 * 4 + 40 {
        errors.push("idx 文件太短".into());
        return IdxFile { version, fanout, entries, pack_checksum, idx_checksum, checksum_ok, errors };
    }

    let body_end = data.len() - 20;
    let mut h = Sha1::new();
    h.update(&data[..body_end]);
    checksum_ok = hex::encode(h.finalize()) == hex::encode(&data[body_end..]);
    idx_checksum = hex::encode(&data[body_end..]);
    if !checksum_ok {
        errors.push("idx 自身校验和失败".into());
    }

    if &data[0..4] == b"\xfftOc" {
        version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 {
            errors.push(format!("不支持的 idx 版本 {version}"));
            return IdxFile { version, fanout, entries, pack_checksum, idx_checksum, checksum_ok, errors };
        }
        let mut p = 8usize;
        for i in 0..256 {
            fanout[i] = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            p += 4;
        }
        for i in 1..256 {
            if fanout[i] < fanout[i - 1] {
                errors.push(format!("fanout 表在桶 {i} 处非单调递增"));
            }
        }
        let n = fanout[255] as usize;
        let need = p + n * 20 + n * 4 + n * 4 + 20;
        if need > body_end {
            errors.push(format!("idx 条目区越界：需要 {need}，正文仅 {body_end}"));
            return IdxFile { version, fanout, entries, pack_checksum, idx_checksum, checksum_ok, errors };
        }
        let oid_base = p;
        let crc_base = oid_base + n * 20;
        let off_base = crc_base + n * 4;
        let ext_base = off_base + n * 4;
        for i in 0..n {
            let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
            let crc32 = u32::from_be_bytes([
                data[crc_base + i * 4],
                data[crc_base + i * 4 + 1],
                data[crc_base + i * 4 + 2],
                data[crc_base + i * 4 + 3],
            ]);
            let raw = u32::from_be_bytes([
                data[off_base + i * 4],
                data[off_base + i * 4 + 1],
                data[off_base + i * 4 + 2],
                data[off_base + i * 4 + 3],
            ]);
            let offset = if raw & 0x8000_0000 != 0 {
                let ext_idx = (raw & 0x7fff_ffff) as usize;
                let at = ext_base + ext_idx * 8;
                if at + 8 > body_end {
                    errors.push(format!("条目 {i} 的 64 位偏移表越界"));
                    0
                } else {
                    u64::from_be_bytes([
                        data[at], data[at + 1], data[at + 2], data[at + 3],
                        data[at + 4], data[at + 5], data[at + 6], data[at + 7],
                    ])
                }
            } else {
                raw as u64
            };
            entries.push(IdxEntry { oid, crc32, offset });
        }
        let pk = body_end - 20;
        pack_checksum = hex::encode(&data[pk..pk + 20]);
    } else {
        errors.push("仅支持 idx v2（缺少 \\xfftOc 魔数）".into());
    }

    IdxFile { version, fanout, entries, pack_checksum, idx_checksum, checksum_ok, errors }
}

/// 对比 idx 与 pack，返回不配套证据。
pub fn cross_check(idx: &IdxFile, pack: &PackFile) -> Vec<String> {
    let mut issues = Vec::new();
    if !pack.trailer_oid.is_empty() && idx.pack_checksum != pack.trailer_oid {
        issues.push(format!(
            "idx 记录的 pack 校验和 {} 与 pack 实际 {} 不一致",
            idx.pack_checksum, pack.trailer_oid
        ));
    }
    if idx.entries.len() != pack.entries.len() {
        issues.push(format!(
            "idx 条目数 {} 与 pack 条目数 {} 不一致",
            idx.entries.len(),
            pack.entries.len()
        ));
    }
    for ie in &idx.entries {
        match pack.entries.iter().find(|pe| pe.offset == ie.offset) {
            None => issues.push(format!(
                "idx 条目 {} 指向 pack 中不存在的偏移 {}",
                ie.oid, ie.offset
            )),
            Some(pe) => {
                if pe.crc32 != ie.crc32 {
                    issues.push(format!(
                        "偏移 {} CRC 不配套：idx={:08x} pack={:08x}",
                        ie.offset, ie.crc32, pe.crc32
                    ));
                }
            }
        }
    }
    issues
}
