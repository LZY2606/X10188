//! pack 文件解析：header、变长对象头、ofs-delta/ref-delta、
//! zlib 边界定位（不依赖声明大小）、SHA1 trailer 校验。
//!
//! 损坏处理原则：某个对象坏掉时隔离它并尽力重同步，
//! 继续分析后续对象；所有问题以证据字符串记录。

use super::zlib::inflate_one;
use super::{sha1_bytes, GitType};

#[derive(Debug, Clone)]
pub enum EntryKind {
    Base(GitType),
    OfsDelta { negative_offset: u64 },
    RefDelta { base_oid: [u8; 20] },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// 在 pack 中的序号（0 起）
    pub ordinal: usize,
    /// 对象头起始绝对偏移
    pub header_offset: u64,
    /// 压缩数据起始绝对偏移
    pub data_offset: u64,
    /// 压缩对象（头+数据）结束偏移，即下一对象起点
    pub end_offset: u64,
    /// 对象头声明的解压后大小（delta 对象即 delta 数据长度）
    pub declared_size: u64,
    pub kind: EntryKind,
    /// 解压出的原始字节（base=对象体；delta=delta 指令数据）
    pub inflated: Option<Vec<u8>>,
    /// 该对象的问题证据（隔离用），None 表示干净
    pub problem: Option<String>,
    /// 真实输出超过声明大小
    pub overshoot: bool,
    /// 真实输出小于声明大小
    pub undershoot: bool,
    /// 是否通过重同步才定位到边界
    pub resynced: bool,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub file_errors: Vec<String>,
    pub trailer_expected: [u8; 20],
    pub trailer_actual: [u8; 20],
    pub trailer_ok: bool,
    pub data_len: usize,
}

#[derive(Debug, Clone)]
struct RawHeader {
    kind_code: u8,
    size: u64,
    header_len: usize,
}

fn read_entry_header(buf: &[u8], pos: usize) -> Result<RawHeader, String> {
    if pos >= buf.len() {
        return Err("对象头越界".into());
    }
    let first = buf[pos];
    let kind_code = (first >> 4) & 0x7;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut p = pos + 1;
    let mut b = first;
    while b & 0x80 != 0 {
        if p >= buf.len() {
            return Err("变长对象头被截断".into());
        }
        b = buf[p];
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok(RawHeader {
        kind_code,
        size,
        header_len: p - pos,
    })
}

/// ofs-delta 的“负偏移”变长编码
fn read_ofs_delta(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= buf.len() {
        return Err("ofs-delta 偏移被截断".into());
    }
    let mut b = buf[pos];
    let mut p = pos + 1;
    let mut ofs = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if p >= buf.len() {
            return Err("ofs-delta 偏移被截断".into());
        }
        b = buf[p];
        p += 1;
        ofs = ofs.wrapping_add(1);
        ofs = (ofs << 7) | (b & 0x7f) as u64;
    }
    Ok((ofs, p - pos))
}

fn plausible_header(buf: &[u8], pos: usize) -> Option<RawHeader> {
    let h = read_entry_header(buf, pos).ok()?;
    if !(1..=7).contains(&h.kind_code) {
        return None;
    }
    Some(h)
}

/// 在解压失败后尝试重同步：优先使用 index 提供的已知偏移，
/// 否则在有限窗口内扫描“头合法 + zlib 能完整结束”的位置。
fn resync(
    buf: &[u8],
    from: usize,
    hint_offsets: Option<&[u64]>,
    declared: u64,
    safety: u64,
) -> Option<(usize, super::zlib::InflateOutcome)> {
    if let Some(hints) = hint_offsets {
        for &h in hints {
            let h = h as usize;
            if h <= from || h >= buf.len() {
                continue;
            }
            if plausible_header(buf, h).is_none() {
                continue;
            }
            if let Ok(o) = inflate_one(buf, h + plausible_header(buf, h).unwrap().header_len, declared, safety) {
                return Some((h, o));
            }
        }
    }
    let limit = (from + 4096).min(buf.len().saturating_sub(20));
    for p in (from + 1)..limit {
        let Some(h) = plausible_header(buf, p) else {
            continue;
        };
        if let Ok(o) = inflate_one(buf, p + h.header_len, declared, safety) {
            // 要求结束点仍在文件内且确实消费了若干字节
            if p + h.header_len + o.consumed <= buf.len() - 20 && o.consumed > 0 {
                return Some((p, o));
            }
        }
    }
    None
}

pub fn parse_pack(buf: &[u8]) -> PackFile {
    parse_pack_with_hints(buf, None, 512 * 1024 * 1024)
}

pub fn parse_pack_with_hints(
    buf: &[u8],
    hint_offsets: Option<&[u64]>,
    safety_limit: u64,
) -> PackFile {
    let mut file_errors: Vec<String> = Vec::new();

    if buf.len() < 32 {
        file_errors.push("文件长度不足 pack 最小长度(32字节)".into());
        return PackFile {
            version: 0,
            count: 0,
            entries: vec![],
            file_errors,
            trailer_expected: [0u8; 20],
            trailer_actual: [0u8; 20],
            trailer_ok: false,
            data_len: buf.len(),
        };
    }
    if &buf[0..4] != b"PACK" {
        file_errors.push("pack 魔数错误（应为 PACK）".into());
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let count = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if version != 2 {
        file_errors.push(format!("不支持的 pack 版本: {version}（仅支持 v2）"));
    }

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut pos = 12usize;
    let mut aborted = false;

    for ordinal in 0..count as usize {
        if pos + 20 > buf.len() {
            file_errors.push(format!("第 {ordinal} 个对象：偏移 {pos} 处数据被截断"));
            aborted = true;
            break;
        }
        let header_offset = pos as u64;
        let hdr = match read_entry_header(buf, pos) {
            Ok(h) => h,
            Err(e) => {
                file_errors.push(format!("第 {ordinal} 个对象 @{pos}: {e}"));
                aborted = true;
                break;
            }
        };
        if !(1..=7).contains(&hdr.kind_code) {
            file_errors.push(format!(
                "第 {ordinal} 个对象 @{pos}: 非法对象类型码 {}",
                hdr.kind_code
            ));
            aborted = true;
            break;
        }
        pos += hdr.header_len;

        let kind = match hdr.kind_code {
            6 => {
                match read_ofs_delta(buf, pos) {
                    Ok((negative_offset, n)) => {
                        pos += n;
                        EntryKind::OfsDelta { negative_offset }
                    }
                    Err(e) => {
                        file_errors.push(format!("第 {ordinal} 个对象 @{pos}: {e}"));
                        aborted = true;
                        break;
                    }
                }
            }
            7 => {
                if pos + 20 > buf.len() {
                    file_errors
                        .push(format!("第 {ordinal} 个对象: ref-delta base oid 被截断"));
                    aborted = true;
                    break;
                }
                let mut base = [0u8; 20];
                base.copy_from_slice(&buf[pos..pos + 20]);
                pos += 20;
                EntryKind::RefDelta { base_oid: base }
            }
            code => {
                let Some(t) = GitType::from_code(code) else {
                    unreachable!()
                };
                EntryKind::Base(t)
            }
        };

        let data_offset = pos as u64;
        let infl = inflate_one(buf, pos, hdr.size, safety_limit);
        let mut entry = PackEntry {
            ordinal,
            header_offset,
            data_offset,
            end_offset: 0,
            declared_size: hdr.size,
            kind,
            inflated: None,
            problem: None,
            overshoot: false,
            undershoot: false,
            resynced: false,
        };

        match infl {
            Ok(o) => {
                let actual = o.data.len() as u64;
                pos += o.consumed;
                entry.end_offset = pos as u64;
                entry.inflated = Some(o.data);
                entry.overshoot = o.overshoot;
                if o.overshoot {
                    entry.problem = Some(format!(
                        "大小欺骗(溢出)：对象头声明 {} 字节，zlib 实际解压 {} 字节",
                        hdr.size, actual
                    ));
                } else if actual != hdr.size {
                    entry.undershoot = true;
                    entry.problem = Some(format!(
                        "大小欺骗(不足)：对象头声明 {} 字节，zlib 实际解压 {} 字节",
                        hdr.size, actual
                    ));
                }
            }
            Err(e) => {
                let msg = match &e {
                    super::zlib::InflateError::Truncated => "zlib 流被截断".to_string(),
                    super::zlib::InflateError::SafetyLimitExceeded { limit } => {
                        format!("解压输出超过安全上限 {limit} 字节")
                    }
                    super::zlib::InflateError::Zlib(s) => format!("zlib 错误: {s}"),
                    super::zlib::InflateError::Overshoot { .. } => unreachable!(),
                };
                file_errors.push(format!(
                    "第 {ordinal} 个对象 @{data_offset}: {msg}，尝试重同步"
                ));
                match resync(buf, pos, hint_offsets, hdr.size, safety_limit) {
                    Some((new_pos, _o)) => {
                        // 坏对象隔离：无法恢复其真实内容；new_pos 是“下一个对象”起点
                        entry.resynced = true;
                        entry.end_offset = new_pos as u64;
                        entry.problem =
                            Some(format!("{msg}；已隔离，边界重同步至下一个对象 @{new_pos}"));
                        entries.push(entry);
                        pos = new_pos;
                        continue;
                    }
                    None => {
                        entry.problem = Some(format!("{msg}；无法定位下一个对象边界"));
                        // 隔离：结束后续对象的解析
                        entries.push(entry);
                        aborted = true;
                        break;
                    }
                }
            }
        }
        entries.push(entry);
    }

    if entries.len() != count as usize && !aborted {
        file_errors.push(format!(
            "对象数量不符：header 声明 {} 个，实际解析 {} 个",
            count,
            entries.len()
        ));
    }

    // trailer
    let mut trailer_expected = [0u8; 20];
    let mut trailer_actual = [0u8; 20];
    let mut trailer_ok = false;
    if buf.len() >= 20 {
        let body_end = buf.len() - 20;
        trailer_expected = sha1_bytes(&buf[..body_end]);
        trailer_actual.copy_from_slice(&buf[body_end..]);
        trailer_ok = trailer_expected == trailer_actual;
        if !trailer_ok {
            file_errors.push(
                "pack SHA1 trailer 校验失败（文件被篡改或损坏），trailer="
                    .to_string()
                    + &hex::encode(trailer_actual)
                    + " 实际计算="
                    + &hex::encode(trailer_expected),
            );
        }
    }

    PackFile {
        version,
        count,
        entries,
        file_errors,
        trailer_expected,
        trailer_actual,
        trailer_ok,
        data_len: buf.len(),
    }
}
