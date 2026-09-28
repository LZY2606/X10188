//! pack v2 解析：header、entry（含 ofs/ref delta 头）、zlib 边界与 trailer。

use crate::encoding::{
    git_object_id, oid_hex, read_ofs_delta, read_pack_entry_header, sha1_bytes,
};
use crate::types::{EntryKind, Evidence, GitType};
use crate::zlib::{inflate_raw, InflateError};

/// 单个已扫描的 pack entry（隔离保存，其他 entry 损坏不影响它）。
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub entry_offset: u64,
    pub zlib_offset: u64,
    pub zlib_len: u64,
    pub kind: EntryKind,
    pub declared_size: u64,
    /// ofs-delta：base 的绝对偏移（越界时仍给出值，由证据标记）
    pub ofs_base: Option<i64>,
    pub ref_base: Option<[u8; 20]>,
    /// 非 delta 为对象内容；delta 为 delta payload；paused/spoof 时为 None
    pub inflated: Option<Vec<u8>>,
    /// sha1(`<type> <len>\0<body>`) 重算结果（仅非 delta）
    pub computed_oid: Option<[u8; 20]>,
    pub adler_ok: bool,
    /// idx 给出的 CRC32 与 entry 压缩字节的比对结果
    pub idx_crc_ok: Option<bool>,
    pub idx_oid: Option<[u8; 20]>,
    pub evidences: Vec<Evidence>,
    /// 预算门未通过，调用方可在预算恢复后重试
    pub budget_paused: bool,
    /// 大小欺骗 / zlib 损坏，扫描在本 entry 后中止
    pub scan_aborts_after: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub object_count: u32,
    pub entries: Vec<PackEntry>,
    pub header_ok: bool,
    pub trailer_ok: bool,
    pub trailer_offset: u64,
    pub evidences: Vec<Evidence>,
    /// 本次扫描成功展开并计入预算的字节数
    pub budget_used: u64,
    /// 扫描是否因预算暂停而提前结束（可重试）
    pub scan_paused: bool,
}

pub struct ScanBudget {
    pub remaining: u64,
    pub per_object_cap: u64,
}

pub fn parse_pack(data: &[u8], budget: &ScanBudget) -> ParsedPack {
    let mut evidences = Vec::new();
    let mut entries = Vec::new();
    let mut budget_used = 0u64;
    let mut scan_paused = false;

    if data.len() < 32 || &data[..4] != b"PACK" {
        return ParsedPack {
            object_count: 0,
            entries,
            header_ok: false,
            trailer_ok: false,
            trailer_offset: 0,
            evidences: vec![Evidence::new("bad_pack_header", "缺少 PACK 魔数或文件过短")],
            budget_used: 0,
            scan_paused: false,
        };
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != 2 {
        evidences.push(Evidence::new(
            "unsupported_pack_version",
            format!("仅支持 pack v2，实际为 v{version}"),
        ));
    }
    let trailer_offset = data.len().saturating_sub(20) as u64;
    let trailer_ok = sha1_bytes(&data[..data.len() - 20]) == data[data.len() - 20..];
    if !trailer_ok {
        evidences.push(
            Evidence::new("pack_checksum_mismatch", "pack 尾部 SHA1 与内容不一致")
                .at(trailer_offset),
        );
    }

    let mut pos = 12usize;
    for idx in 0..object_count as usize {
        let entry_offset = pos as u64;
        match parse_entry(data, &mut pos, budget, entry_offset) {
            Some(e) => {
                if e.budget_paused {
                    scan_paused = true;
                }
                if !e.budget_paused && !e.scan_aborts_after {
                    if let Some(body) = &e.inflated {
                        let spoof = e
                            .evidences
                            .iter()
                            .any(|v| v.code == "size_spoof" || v.code == "zlib_adler_mismatch");
                        if !spoof {
                            budget_used = budget_used.saturating_add(body.len() as u64);
                        }
                    }
                }
                entries.push(e);
                if entries.last().unwrap().scan_aborts_after {
                    evidences.push(Evidence::new(
                        "scan_aborted",
                        format!("entry #{idx} 后无法继续定位边界，本 pack 后续对象待隔离"),
                    ));
                    break;
                }
                if scan_paused {
                    evidences.push(Evidence::new(
                        "scan_paused",
                        format!("entry #{idx} 触发预算，扫描暂停，可在追加预算后重试"),
                    ));
                    break;
                }
            }
            None => {
                evidences.push(
                    Evidence::new("entry_unparseable", format!("entry #{idx} 无法解析"))
                        .at(entry_offset),
                );
                break;
            }
        }
    }

    if entries.len() as u32 != object_count && !scan_paused {
        evidences.push(Evidence::new(
            "object_count_mismatch",
            format!("header 声明 {object_count} 个对象，实际解析 {}", entries.len()),
        ));
    }

    ParsedPack {
        object_count,
        entries,
        header_ok: version == 2,
        trailer_ok,
        trailer_offset,
        evidences,
        budget_used,
        scan_paused,
    }
}

fn parse_entry(
    data: &[u8],
    pos: &mut usize,
    budget: &ScanBudget,
    entry_offset: u64,
) -> Option<PackEntry> {
    let (type_code, declared_size, header_len) = read_pack_entry_header(data, *pos)?;
    let kind = EntryKind::from_pack_code(type_code)?;
    let mut p = *pos + header_len;

    let mut ofs_base = None;
    let mut ref_base = None;
    let mut evidences = Vec::new();

    match kind {
        EntryKind::OfsDelta => {
            let (neg, n) = read_ofs_delta(data, p)?;
            p += n;
            let base_abs = entry_offset as i64 - neg as i64;
            if neg > entry_offset || base_abs < 12 || base_abs as u64 >= data.len() as u64 - 20 {
                evidences.push(
                    Evidence::new(
                        "ofs_distance_out_of_range",
                        format!("ofs-delta 距离 {neg} 越界（entry@{entry_offset}）"),
                    )
                    .at(entry_offset),
                );
            }
            ofs_base = Some(base_abs);
        }
        EntryKind::RefDelta => {
            let oid: [u8; 20] = data.get(p..p + 20)?.try_into().ok()?;
            p += 20;
            ref_base = Some(oid);
        }
        _ => {}
    }

    let zlib_offset = p as u64;
    let mut entry = PackEntry {
        entry_offset,
        zlib_offset,
        zlib_len: 0,
        kind,
        declared_size,
        ofs_base,
        ref_base,
        inflated: None,
        computed_oid: None,
        adler_ok: false,
        idx_crc_ok: None,
        idx_oid: None,
        evidences,
        budget_paused: false,
        scan_aborts_after: false,
    };

    // 预算门 1：单对象比例
    if declared_size > budget.per_object_cap {
        entry.budget_paused = true;
        entry.scan_aborts_after = true;
        entry.evidences.push(Evidence::new(
            "budget_paused",
            format!("声明大小 {declared_size} 超过单对象上限 {}，未展开", budget.per_object_cap),
        ));
        *pos = p;
        return Some(entry);
    }
    // 预算门 2：总额
    if declared_size > budget.remaining {
        entry.budget_paused = true;
        entry.scan_aborts_after = true;
        entry.evidences.push(Evidence::new(
            "budget_paused",
            format!("声明大小 {declared_size} 超过总预算剩余 {}，未展开", budget.remaining),
        ));
        *pos = p;
        return Some(entry);
    }

    match inflate_raw(data, p, budget.per_object_cap) {
        Ok(inf) => {
            entry.zlib_len = inf.consumed as u64;
            entry.adler_ok = inf.adler_ok;
            *pos = p + inf.consumed;
            if !inf.adler_ok {
                entry.evidences.push(
                    Evidence::new("zlib_adler_mismatch", "zlib ADLER32 校验失败")
                        .at(zlib_offset),
                );
                entry.scan_aborts_after = true;
                return Some(entry);
            }
            if inf.data.len() as u64 != declared_size {
                entry.evidences.push(Evidence::new(
                    "size_spoof",
                    format!(
                        "header 声明 {} 字节，实际解压 {} 字节（解压到一半即可判定大小欺骗）",
                        declared_size,
                        inf.data.len()
                    ),
                ));
                // 边界已知，不保留膨胀内容，扫描可继续
                if let EntryKind::Plain(t) = entry.kind {
                    entry.computed_oid = Some(git_object_id(t, &inf.data));
                }
                return Some(entry);
            }
            if inf.data.len() as u64 > budget.remaining {
                entry.budget_paused = true;
                entry.scan_aborts_after = true;
                entry.evidences.push(Evidence::new(
                    "budget_paused",
                    format!("展开 {} 字节超过总预算剩余 {}", inf.data.len(), budget.remaining),
                ));
                return Some(entry);
            }
            if let EntryKind::Plain(t) = entry.kind {
                let oid = git_object_id(t, &inf.data);
                entry.computed_oid = Some(oid);
            }
            entry.inflated = Some(inf.data);
            Some(entry)
        }
        Err(InflateError::CapExceeded) => {
            // 声明值已在单对象上限内，却展开超出 => 大小欺骗
            entry.evidences.push(Evidence::new(
                "size_spoof",
                format!(
                    "声明 {declared_size} 字节但展开超过单对象上限 {}，判定大小欺骗",
                    budget.per_object_cap
                ),
            ));
            entry.scan_aborts_after = true;
            *pos = p;
            Some(entry)
        }
        Err(other) => {
            entry.evidences.push(Evidence::new(
                "zlib_corrupt",
                format!("zlib 解压失败：{other:?}"),
            ));
            entry.scan_aborts_after = true;
            *pos = p;
            Some(entry)
        }
    }
}

/// loose object：zlib(`<type> <len>\0<body>`)。
pub struct LooseObject {
    pub kind: GitType,
    pub content: Vec<u8>,
    pub computed_oid: [u8; 20],
    pub adler_ok: bool,
    pub evidences: Vec<Evidence>,
}

pub fn parse_loose(data: &[u8], cap: u64) -> Option<LooseObject> {
    let inf = inflate_raw(data, 0, cap).ok()?;
    let nul = inf.data.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&inf.data[..nul]).ok()?;
    let (type_name, len_str) = header.split_once(' ')?;
    let declared_len: usize = len_str.parse().ok()?;
    let kind = match type_name {
        "commit" => GitType::Commit,
        "tree" => GitType::Tree,
        "blob" => GitType::Blob,
        "tag" => GitType::Tag,
        _ => return None,
    };
    let body = inf.data[nul + 1..].to_vec();
    let mut evidences = Vec::new();
    if body.len() != declared_len {
        evidences.push(Evidence::new(
            "size_spoof",
            format!("loose header 声明 {declared_len}，实际 {}", body.len()),
        ));
    }
    if !inf.adler_ok {
        evidences.push(Evidence::new("zlib_adler_mismatch", "loose zlib ADLER32 校验失败"));
    }
    let computed_oid = git_object_id(kind, &body);
    Some(LooseObject {
        kind,
        content: body,
        computed_oid,
        adler_ok: inf.adler_ok,
        evidences,
    })
}

pub fn is_probably_pack(data: &[u8]) -> bool {
    data.len() >= 12 && &data[..4] == b"PACK"
}

pub fn is_probably_idx(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..4] == b"\xfftOc"
}

pub fn describe_plain_oid(entry: &PackEntry) -> Option<String> {
    entry.computed_oid.map(oid_hex)
}
