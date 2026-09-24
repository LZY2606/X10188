//! PACK 容器解析：header、对象条目、ofs/ref delta 引用、zlib 边界与 trailer。

use super::zlib::inflate_to_end;
use super::{ObjType, Oid};

/// 单对象解压上限（防止恶意膨胀耗尽内存）。
pub const MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RawEntry {
    /// 条目在 pack 文件中的起始偏移（类型/大小字节起点）。
    pub offset: u64,
    pub kind: Option<ObjType>,
    /// 条目头声称的解压后大小。
    pub claimed_size: Option<u64>,
    /// ofs-delta 基对象绝对偏移。
    pub base_offset: Option<u64>,
    /// ref-delta 基对象 oid。
    pub base_oid: Option<Oid>,
    /// 压缩数据（zlib 流）的字节范围。
    pub compressed_range: Option<(u64, u64)>,
    /// 条目整体字节范围（含头部与 zlib 流）。
    pub entry_range: (u64, u64),
    /// 成功解压出的原始数据（delta 则为 delta 指令字节）。
    pub inflated: Option<Vec<u8>>,
    /// 实际解压后字节数。
    pub actual_size: Option<usize>,
    /// 从 entry 字节计算出的 CRC32。
    pub crc32: Option<u32>,
    /// 解析/解压失败时的错误证据。
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    /// pack 文件长度。
    pub file_len: u64,
    /// 末尾 20 字节 SHA1（pack 自身校验和）。
    pub stored_checksum: Oid,
    /// 对除 trailer 外全部字节重算的 SHA1。
    pub computed_checksum: Oid,
    pub checksum_ok: bool,
    pub entries: Vec<RawEntry>,
    /// 与整体结构相关的致命错误（无法继续扫描）。
    pub fatal_error: Option<String>,
}

/// 从 index 得到的（offset -> oid）映射，用于解压失败后重同步。
pub type OffsetOidMap = std::collections::HashMap<u64, Oid>;

pub fn parse_pack(data: &[u8], index_offsets: Option<&[u64]>) -> ParsedPack {
    let mut pack = ParsedPack {
        version: 0,
        count: 0,
        file_len: data.len() as u64,
        stored_checksum: Oid([0u8; 20]),
        computed_checksum: Oid([0u8; 20]),
        checksum_ok: false,
        entries: Vec::new(),
        fatal_error: None,
    };

    if data.len() < 12 + 20 {
        pack.fatal_error = Some("pack 文件短于 32 字节，缺少 header/trailer".to_string());
        return pack;
    }
    if &data[0..4] != b"PACK" {
        pack.fatal_error = Some(format!(
            "pack 魔数错误：期望 PACK，实际 {:?}",
            &data[0..4]
        ));
        return pack;
    }
    pack.version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    pack.count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if pack.version != 2 {
        pack.fatal_error = Some(format!("不支持的 pack 版本 {}", pack.version));
        return pack;
    }
    let trailer_start = data.len() - 20;
    let mut chk = Oid([0u8; 20]);
    chk.0.copy_from_slice(&data[trailer_start..]);
    pack.stored_checksum = chk;
    pack.computed_checksum = super::sha1_bytes(&data[..trailer_start]);
    pack.checksum_ok = pack.stored_checksum == pack.computed_checksum;

    // index 偏移表（排序后用于重同步）。
    let mut sorted_idx: Vec<u64> = index_offsets
        .map(|v| v.iter().copied().filter(|o| (12..trailer_start as u64).contains(o)).collect())
        .unwrap_or_default();
    sorted_idx.sort_unstable();
    sorted_idx.dedup();

    let mut pos = 12usize;
    for _ in 0..pack.count.max(1) as usize {
        if pos >= trailer_start {
            if pack.entries.len() != pack.count as usize {
                pack.fatal_error = Some(format!(
                    "对象数 {} 与 header 声称的 {} 不符（提前到达 trailer）",
                    pack.entries.len(),
                    pack.count
                ));
            }
            break;
        }
        let entry_start = pos;
        let mut entry = RawEntry {
            offset: entry_start as u64,
            kind: None,
            claimed_size: None,
            base_offset: None,
            base_oid: None,
            compressed_range: None,
            entry_range: (entry_start as u64, entry_start as u64),
            inflated: None,
            actual_size: None,
            crc32: None,
            parse_error: None,
        };

        if let Err(e) = read_entry_header(data, trailer_start, &mut pos, &mut entry) {
            entry.parse_error = Some(e);
            entry.entry_range.1 = pos as u64;
            pack.entries.push(entry);
            if !resync(data, trailer_start, &sorted_idx, &mut pos) {
                pack.fatal_error = Some(
                    "条目头解析失败且无配套 index 可重同步，停止扫描".to_string(),
                );
                break;
            }
            continue;
        }

        let comp_start = pos;
        match inflate_to_end(data, pos, MAX_OBJECT_BYTES) {
            Ok((out, consumed)) => {
                pos += consumed;
                entry.compressed_range = Some((comp_start as u64, pos as u64));
                entry.actual_size = Some(out.len());
                entry.entry_range.1 = pos as u64;
                if let Some(claimed) = entry.claimed_size {
                    if out.len() as u64 != claimed {
                        entry.parse_error = Some(format!(
                            "大小欺骗：头部声称 {} 字节，实际解压 {} 字节",
                            claimed,
                            out.len()
                        ));
                    }
                }
                entry.inflated = Some(out);
            }
            Err(e) => {
                entry.parse_error = Some(e);
                entry.entry_range.1 = pos as u64;
                pack.entries.push(entry);
                if !resync(data, trailer_start, &sorted_idx, &mut pos) {
                    pack.fatal_error = Some(
                        "zlib 流损坏且无配套 index 可重同步，停止扫描".to_string(),
                    );
                    break;
                }
                continue;
            }
        }
        let end = pos;
        let crc = crc32fast::hash(&data[entry_start..end]);
        entry.crc32 = Some(crc);
        entry.entry_range = (entry_start as u64, end as u64);
        pack.entries.push(entry);
    }

    if pack.entries.len() != pack.count as usize && pack.fatal_error.is_none() {
        pack.fatal_error = Some(format!(
            "对象数 {} 与 header 声称的 {} 不符",
            pack.entries.len(),
            pack.count
        ));
    }
    pack
}

fn read_entry_header(
    data: &[u8],
    end: usize,
    pos: &mut usize,
    entry: &mut RawEntry,
) -> Result<(), String> {
    let first = *data
        .get(*pos)
        .ok_or_else(|| "条目头缺失".to_string())?;
    let kind_code = (first >> 4) & 0x7;
    let kind = ObjType::from_pack_code(kind_code)
        .ok_or_else(|| format!("非法对象类型码 {}", kind_code))?;
    entry.kind = Some(kind);

    let (size, after) = super::read_size_encoding(data, *pos)?;
    // 第一个字节的低 4 位是大小的最低 4 位，read_size_encoding 已按 7 位分组，
    // 需要按 git 规则重组：首字节低 4 位 + 后续字节各 7 位。
    let mut claimed: u64 = (first & 0x0f) as u64;
    if first & 0x80 != 0 {
        let mut shift = 4u32;
        let mut p = *pos + 1;
        loop {
            let b = *data.get(p).ok_or_else(|| "size 续字节缺失".to_string())?;
            claimed |= ((b & 0x7f) as u64) << shift;
            p += 1;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err("size 编码过长".to_string());
            }
        }
    }
    let _ = size;
    entry.claimed_size = Some(claimed);
    *pos = after;

    if *pos > end {
        return Err("条目头越过 trailer".to_string());
    }

    match kind {
        ObjType::OfsDelta => {
            let mut ofs_pos = *pos;
            let b = *data
                .get(ofs_pos)
                .ok_or_else(|| "ofs-delta 偏移字节缺失".to_string())?;
            ofs_pos += 1;
            let mut back: u64 = (b & 0x7f) as u64;
            while b & 0x80 != 0 {
                let b = *data
                    .get(ofs_pos)
                    .ok_or_else(|| "ofs-delta 偏移续字节缺失".to_string())?;
                ofs_pos += 1;
                back = ((back + 1) << 7) | (b & 0x7f) as u64;
            }
            *pos = ofs_pos;
            let base = entry
                .offset
                .checked_sub(back)
                .ok_or_else(|| format!("ofs-delta 负向距离 {} 越界", back))?;
            if base < 12 || base >= entry.offset {
                return Err(format!("ofs-delta 基偏移 {} 越界（应在 12..{}）", base, entry.offset));
            }
            entry.base_offset = Some(base);
        }
        ObjType::RefDelta => {
            if *pos + 20 > end {
                return Err("ref-delta 基 oid 的 20 字节缺失".to_string());
            }
            let mut o = Oid([0u8; 20]);
            o.0.copy_from_slice(&data[*pos..*pos + 20]);
            *pos += 20;
            entry.base_oid = Some(o);
        }
        _ => {}
    }
    Ok(())
}

fn resync(
    data: &[u8],
    trailer_start: usize,
    sorted_idx: &[u64],
    pos: &mut usize,
) -> bool {
    // 找到严格大于当前位置的下一个 index 偏移；没有 index 就无法安全重同步。
    for off in sorted_idx {
        let off = *off as usize;
        if off > *pos && off < trailer_start {
            // 简单校验该位置确实像条目头（类型码合法）。
            if let Some(&b) = data.get(off) {
                let code = (b >> 4) & 0x7;
                if (1..=4).contains(&code) || code == 6 || code == 7 {
                    *pos = off;
                    return true;
                }
            }
            *pos = off;
            return true;
        }
    }
    false
}
