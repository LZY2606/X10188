//! PACK v2 文件解析：header、对象条目顺序扫描、trailer 校验。
//!
//! 这里只负责“布局与压缩层”：对象是否能解压、大小是否欺骗、CRC 是否吻合。
//! delta 链的语义还原在 `resolver` 中完成。
//!
//! 当有配套 index 时，`parse_pack_with_offsets` 用 index 给出的偏移逐个定位
//! 条目，可以隔离单个坏对象而不中断整体扫描；没有 index 时采用顺序扫描，
//! 一旦某条目无法确定下一起点就停止（并留下证据）。

use crate::hash::sha1_hex;
use crate::types::{Evidence, ObjType, PackEntry, PackReport};
use crate::zlib::{evidence_for, inflate_stream};

pub const PACK_MAGIC: &[u8; 4] = b"PACK";
pub const PACK_MAGIC_STR: &str = "PACK";
pub const HEADER_LEN: usize = 12;

/// 解析 size+type 变长 header。返回 `(类型, 声明大小, header字节数)`。
pub fn read_entry_header(buf: &[u8], pos: usize) -> Result<(ObjType, u64, usize), String> {
    if pos >= buf.len() {
        return Err("对象 header 起点超出文件".into());
    }
    let first = buf[pos];
    let stype = ObjType::from_nibble((first >> 4) & 0x7);
    let mut size = (first & 0x7f) as u64;
    let mut shift = 4;
    let mut used = 1;
    let mut p = pos + 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        if p >= buf.len() {
            return Err("size 编码被截断".into());
        }
        cur = buf[p];
        if shift < 64 {
            size |= ((cur & 0x7f) as u64) << shift;
        }
        shift += 7;
        used += 1;
        p += 1;
    }
    Ok((stype, size, used))
}

/// 读取 ofs-delta 的负偏移编码（紧跟在 entry header 之后）。
/// 返回 `(base 绝对偏移, 编码字节数)`。
pub fn read_ofs_delta(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= buf.len() {
        return Err("ofs-delta 编码缺失".into());
    }
    let mut p = pos;
    let mut b = buf[p];
    let mut ofs = (b & 0x7f) as u64;
    p += 1;
    while b & 0x80 != 0 {
        if p >= buf.len() {
            return Err("ofs-delta 编码被截断".into());
        }
        ofs = ofs.wrapping_add(1);
        ofs <<= 7;
        b = buf[p];
        ofs |= (b & 0x7f) as u64;
        p += 1;
    }
    Ok((ofs, p - pos))
}

#[derive(Default)]
struct ScanCtx {
    entries: Vec<PackEntry>,
    evidence: Vec<Evidence>,
}

/// 对单个条目做解析：读 header（含 delta 引用头）+ 解压。
fn parse_entry_at(buf: &[u8], offset: u64) -> Result<(PackEntry, crate::types::InflateOutcome), (PackEntry, String)> {
    let pos = offset as usize;
    let mut ev = Vec::new();
    let (stype, declared, header_len) = match read_entry_header(buf, pos) {
        Ok(v) => v,
        Err(e) => {
            let ent = PackEntry {
                offset,
                header_len: 0,
                meta_len: 0,
                stype: ObjType::Bad,
                declared_size: 0,
                inflated_size: None,
                comp_offset: pos as u64,
                comp_len: None,
                base_offset: None,
                base_oid: None,
                evidence: vec![Evidence::new("bad_entry_header", e, Some(offset), None)],
            };
            return Err((ent, "无法解析条目 header".into()));
        }
    };
    if stype == ObjType::Bad {
        ev.push(Evidence::new(
            "bad_type",
            format!("对象 header 的类型字段为保留值，位于偏移 {offset}"),
            Some(offset),
            Some(header_len as u64),
        ));
    }

    let mut meta_len = header_len;
    let mut base_offset = None;
    let mut base_oid = None;

    if stype == ObjType::OfsDelta {
        match read_ofs_delta(buf, pos + header_len) {
            Ok((rel, n)) => {
                meta_len += n;
                if rel > offset {
                    ev.push(Evidence::new(
                        "ofs_out_of_range",
                        format!("ofs-delta 距离 {rel} 越过了本对象偏移 {offset}（base 在文件起点之前）"),
                        Some(offset),
                        Some(n as u64),
                    ));
                } else {
                    base_offset = Some(offset - rel);
                }
            }
            Err(e) => ev.push(Evidence::new("bad_ofs_delta", e, Some((pos + header_len) as u64), None)),
        }
    } else if stype == ObjType::RefDelta {
        let s = pos + header_len;
        if s + 20 > buf.len() {
            ev.push(Evidence::new("truncated_ref_delta", "ref-delta 的 20 字节 base oid 被截断", Some(s as u64), None));
        } else {
            base_oid = Some(hex::encode(&buf[s..s + 20]));
            meta_len += 20;
        }
    }

    let comp_offset = pos + meta_len;
    let mut entry = PackEntry {
        offset,
        header_len,
        meta_len,
        stype,
        declared_size: declared,
        inflated_size: None,
        comp_offset: comp_offset as u64,
        comp_len: None,
        base_offset,
        base_oid,
        evidence: ev,
    };

    match inflate_stream(buf, comp_offset, Some(declared)) {
        Ok(inf) => {
            entry.inflated_size = Some(inf.data.len() as u64);
            entry.comp_len = Some(inf.comp_len as u64);
            Ok((entry, inf))
        }
        Err(e) => {
            entry.inflated_size = if e.partial.is_empty() { None } else { Some(e.partial.len() as u64) };
            entry.comp_len = if e.consumed_in == 0 { None } else { Some(e.consumed_in as u64) };
            entry.evidence.push(evidence_for(&e, comp_offset as u64));
            Err((entry, e.message))
        }
    }
}

/// 解压后的数据通过回调交给上层（store），这里在 pack.rs 里不保留对象体。
/// 为了让 importer 拿到解压结果，定义带数据的中间类型。
pub struct ParsedEntry {
    pub entry: PackEntry,
    /// delta 条目时是原始 delta 指令字节；普通对象时是对象体（未经 Git 头包装）。
    pub inflated: Vec<u8>,
}

/// 用 index 提供的偏移集合解析 pack。`offsets` 会被排序去重。
/// 每个坏对象只影响自身：偏移由 index 提供，扫描不会因一个坏条目而失去同步。
pub fn parse_pack_with_offsets(buf: &[u8], offsets: &[u64]) -> PackParseResult {
    let mut report = parse_header(buf);
    let mut parsed = Vec::new();

    let mut sorted: Vec<u64> = offsets.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let body_end = match report.trailer_oid {
        Some(_) => buf.len().saturating_sub(20),
        None => buf.len(),
    };

    for &off in &sorted {
        if (off as usize) < HEADER_LEN || off as usize >= body_end {
            report.evidence.push(Evidence::new(
                "index_offset_out_of_range",
                format!("index 给出的偏移 {off} 不在 pack 对象区内"),
                Some(off),
                None,
            ));
            continue;
        }
        match parse_entry_at(buf, off) {
            Ok((entry, inf)) => {
                parsed.push(ParsedEntry { entry, inflated: inf.data });
            }
            Err((entry, _msg)) => {
                // 解压失败也保留条目（inflated 不可用）。
                parsed.push(ParsedEntry { entry, inflated: Vec::new() });
            }
        }
    }
    parsed.sort_by_key(|p| p.entry.offset);
    report.entries = parsed.iter().map(|p| p.entry.clone()).collect();
    finalize_checksum(buf, &mut report);
    PackParseResult { report, parsed }
}

/// 没有 index 时的顺序扫描：每个条目必须干净解压，否则失去同步、停止扫描。
pub fn parse_pack_sequential(buf: &[u8]) -> PackParseResult {
    let mut report = parse_header(buf);
    let mut parsed = Vec::new();

    let body_end = match report.trailer_oid {
        Some(_) => buf.len().saturating_sub(20),
        None => buf.len(),
    };

    let mut pos = HEADER_LEN;
    while pos < body_end {
        match parse_entry_at(buf, pos as u64) {
            Ok((entry, inf)) => {
                let step = entry.meta_len + entry.comp_len.unwrap_or(0) as usize;
                parsed.push(ParsedEntry { entry, inflated: inf.data });
                pos += step;
            }
            Err((entry, msg)) => {
                parsed.push(ParsedEntry { entry: entry.clone(), inflated: Vec::new() });
                report.evidence.push(Evidence::new(
                    "scan_stopped",
                    format!("顺序扫描在偏移 {pos} 失去同步并停止：{msg}"),
                    Some(pos as u64),
                    None,
                ));
                break;
            }
        }
    }
    parsed.sort_by_key(|p| p.entry.offset);
    report.entries = parsed.iter().map(|p| p.entry.clone()).collect();
    finalize_checksum(buf, &mut report);
    PackParseResult { report, parsed }
}

pub struct PackParseResult {
    pub report: PackReport,
    pub parsed: Vec<ParsedEntry>,
}

fn parse_header(buf: &[u8]) -> PackReport {
    let mut ev = Vec::new();
    if buf.len() < HEADER_LEN {
        ev.push(Evidence::new("truncated_pack_header", "pack 文件不足 12 字节 header", None, Some(buf.len() as u64)));
        return PackReport {
            version: 0,
            num_objects: 0,
            data_start: HEADER_LEN as u64,
            entries: Vec::new(),
            trailer_oid: None,
            computed_checksum: None,
            evidence: ev,
        };
    }
    if &buf[0..4] != PACK_MAGIC {
        ev.push(Evidence::new("bad_pack_magic", format!("magic 不是 PACK：{:?}", &buf[0..4]), Some(0), Some(4)));
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let num_objects = u32::from_be_bytes(buf[8..12].try_into().unwrap());
    if version != 2 {
        ev.push(Evidence::new("unsupported_pack_version", format!("仅支持 pack v2，发现 v{version}"), Some(4), Some(4)));
    }
    let trailer_oid = if buf.len() >= HEADER_LEN + 20 {
        Some(hex::encode(&buf[buf.len() - 20..]))
    } else {
        ev.push(Evidence::new("missing_pack_trailer", "文件过短，缺少 20 字节 trailer SHA1", None, None));
        None
    };
    PackReport {
        version,
        num_objects,
        data_start: HEADER_LEN as u64,
        entries: Vec::new(),
        trailer_oid,
        computed_checksum: None,
        evidence: ev,
    }
}

fn finalize_checksum(buf: &[u8], report: &mut PackReport) {
    if buf.len() >= 20 {
        let body_end = buf.len() - 20;
        let computed = sha1_hex(&buf[..body_end]);
        report.computed_checksum = Some(computed.clone());
        if let Some(expected) = &report.trailer_oid {
            if expected != &computed {
                report.evidence.push(Evidence::new(
                    "pack_checksum_mismatch",
                    format!("pack trailer {expected} 与重算 {computed} 不符，文件被篡改或截断"),
                    Some(body_end as u64),
                    Some(20),
                ));
            }
        }
    }
}
