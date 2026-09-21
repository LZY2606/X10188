//! Git pack v2 与 pack index（v1/v2）解析。
//!
//! 解析产物保留原始偏移（entry 在 pack 中的起点、zlib 边界、header 长度），
//! 并逐对象隔离错误：单条 entry 损坏不会影响同包内其他对象的取证。

use sha1::{Digest, Sha1};

use crate::gitid::{read_size_encoding, ObjType, Oid};
use crate::zutil::{crc32_of, inflate_zlib_bounded, InflateError};

pub const PACK_SIG: [u8; 4] = *b"PACK";
pub const IDX_SIG: [u8; 4] = *b"\xfftOc";

/// 单个 pack entry 解析后的记录（尚未做 delta 还原）。
#[derive(Debug, Clone)]
pub struct ParsedEntry {
    /// entry 在 pack 文件中的绝对偏移（对象类型字节起点）。
    pub offset: u64,
    /// 对象头（类型 + 未压缩大小 + delta 引用）占用的字节数，zlib 数据紧随其后。
    pub header_len: usize,
    pub kind: ParsedEntryKind,
    /// 头中声明的“未压缩数据大小”：
    /// - 普通对象：对象 payload 大小；
    /// - delta：delta 指令流的未压缩大小（不是最终对象大小）。
    pub declared_size: u64,
    /// 解压后的原始数据（普通对象 payload 或 delta 指令字节）。
    pub data: Vec<u8>,
    /// zlib 压缩数据在 pack 中的 [start, end) 范围。
    pub zlib_range: (usize, usize),
    /// 该 entry 压缩字节（从 entry 起点到 zlib 流结束）的 CRC32，用于 index 比对。
    pub crc32: u32,
    /// 大小欺骗 / 截断 / 损坏等“导致该 entry 不可用”的错误；
    /// 出错时 `data` 仍保留为已解压到的部分用于取证，但不会参与还原。
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ParsedEntryKind {
    Base(ObjType),
    OfsDelta {
        /// 负向偏移解析出的“base entry 绝对偏移”。
        base_offset: u64,
    },
    RefDelta {
        base_oid: Oid,
    },
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<ParsedEntry>,
    /// 包级错误（magic/version/计数/trailer 不可信）；存在时 entries 可能不完整。
    pub fatal: Option<String>,
    pub trailer_sha1: Option<Oid>,
    pub computed_sha1: Option<Oid>,
    pub trailer_ok: bool,
}

/// pack index 中的单条记录。
#[derive(Debug, Clone)]
pub struct IdxRecord {
    pub oid: Oid,
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub version: u8, // 1 或 2
    pub fanout: [u32; 256],
    pub records: Vec<IdxRecord>,
    /// index 自校验问题（fanout 不单调、sha1 trailer 不符等）。
    pub problems: Vec<String>,
    /// 该 index 声称对应的 pack 的 sha1。
    pub pack_checksum: Option<Oid>,
}

/// 解压单条对象时使用的安全上限（防 zip-bomb / 大小欺骗拖垮分析机）。
pub const INFLATE_HARD_CAP: usize = 512 * 1024 * 1024;

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解析 ofs-delta 使用的“偏移编码”。
fn read_ofs_encoding(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= data.len() {
        return Err("ofs-delta 偏移字节缺失".into());
    }
    let mut byte = data[*pos];
    *pos += 1;
    let mut ofs = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("ofs-delta 偏移编码被截断".into());
        }
        ofs += 1;
        ofs <<= 7;
        byte = data[*pos];
        *pos += 1;
        ofs |= (byte & 0x7f) as u64;
    }
    Ok(ofs)
}

/// 解析整个 pack 文件。
///
/// `hinted_offsets`：来自配套 index 的 entry 绝对偏移（可空）。当某个对象的
/// zlib 流损坏导致我们无法确定流边界时，会用下一个已知偏移重新对齐扫描，
/// 从而“隔离坏对象、继续分析其他对象”。
pub fn parse_pack(bytes: &[u8], hinted_offsets: Option<&[u64]>) -> ParsedPack {
    let mut fatal: Option<String> = None;


    if bytes.len() < 32 {
        return fatal_pack("文件长度小于 pack 最小尺寸（32 字节）");
    }
    if bytes[0..4] != PACK_SIG {
        return fatal_pack("缺少 PACK 魔数（不是 pack 文件）");
    }
    let version = u32_be(&bytes[4..8]);
    if version != 2 {
        return fatal_pack(&format!("不支持的 pack 版本：{version}（仅支持 v2）"));
    }
    let num_objects = u32_be(&bytes[8..12]);

    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut scan_error: Option<String> = None;
    let mut next_hint = {
        let mut h: Vec<u64> = hinted_offsets.unwrap_or(&[]).to_vec();
        h.sort_unstable();
        h.dedup();
        h.into_iter().filter(|o| (*o as usize) >= 12).peekable()
    };

    let mut idx = 0u32;
    while idx < num_objects {
        // 跳过 index 提示中“已经位于我们身后”的偏移；若当前位置没有 entry，
        // 则借助下一个提示偏移重新对齐（前一个坏对象把边界吃掉了）。
        while let Some(&h) = next_hint.peek() {
            if (h as usize) < pos {
                next_hint.next();
            } else if (h as usize) > pos {
                scan_error.get_or_insert_with(|| {
                    format!("扫描在偏移 {pos} 失步，借助 index 重新对齐到偏移 {h}")
                });
                pos = h as usize;
                break;
            } else {
                next_hint.next();
                break;
            }
        }

        if pos >= bytes.len() - 20 {
            scan_error = Some(format!(
                "在读取第 {idx} 个对象（共声明 {num_objects}）时到达文件尾"
            ));
            break;
        }
        let entry_start = pos;
        let first = bytes[pos];
        let type_code = (first >> 4) & 0b111;
        let msb_continues = first & 0x80 != 0;

        let mut hdr = 1usize;
        let mut declared_size: u64 = 0;

        // 大小：首字节低 4 位（ofs/ref delta 情况下首字节低 3 位）
        let mut header_problem: Option<String> = None;
        if !msb_continues {
            declared_size = (first & 0x0f) as u64;
        } else {
            let mut size = (first & 0x0f) as u64;
            let mut shift = 4u32;
            loop {
                if pos + hdr >= bytes.len() {
                    header_problem = Some("对象大小变长编码被截断".into());
                    break;
                }
                let b = bytes[pos + hdr];
                hdr += 1;
                size |= ((b & 0x7f) as u64) << shift;
                shift += 7;
                if b & 0x80 == 0 {
                    break;
                }
                if shift > 63 {
                    header_problem = Some("对象大小编码过长".into());
                    break;
                }
            }
            declared_size = size;
        }

        let kind: Option<ParsedEntryKind> = match type_code {
            1 | 2 | 3 | 4 => Some(ParsedEntryKind::Base(
                ObjType::from_pack_code(type_code).expect("validated"),
            )),
            6 => {
                let mut p = pos + hdr;
                match read_ofs_encoding(bytes, &mut p) {
                    Ok(negative) => {
                        hdr = p - pos;
                        match (entry_start as u64).checked_sub(negative) {
                            Some(bo) if (bo as usize) < 12 => {
                                header_problem = Some(
                                    "ofs-delta 距离指向 pack 头区域（非法）".into(),
                                );
                                Some(ParsedEntryKind::OfsDelta { base_offset: 0 })
                            }
                            Some(bo) => Some(ParsedEntryKind::OfsDelta { base_offset: bo }),
                            None => {
                                header_problem = Some(format!(
                                    "ofs-delta 负距离越界：{negative}"
                                ));
                                Some(ParsedEntryKind::OfsDelta { base_offset: 0 })
                            }
                        }
                    }
                    Err(e) => {
                        header_problem = Some(format!("ofs-delta 解析失败：{e}"));
                        None
                    }
                }
            }
            7 => {
                if pos + hdr + 20 > bytes.len() - 20 {
                    header_problem =
                        Some("ref-delta 的 20 字节 base oid 越界".into());
                    None
                } else {
                    let mut oid = Oid::default();
                    oid.copy_from_slice(&bytes[pos + hdr..pos + hdr + 20]);
                    hdr += 20;
                    Some(ParsedEntryKind::RefDelta { base_oid: oid })
                }
            }
            other => {
                header_problem = Some(format!("使用未知对象类型码 {other}"));
                None
            }
        };

        let zlib_start = pos + hdr;
        let mut zlib_end = zlib_start;
        let mut data = Vec::new();
        let mut entry_error = header_problem;

        if entry_error.is_none() {
            let hard_limit = (declared_size as usize)
                .checked_add(1)
                .unwrap_or(usize::MAX)
                .min(INFLATE_HARD_CAP);
            match inflate_zlib_bounded(
                &bytes[zlib_start..],
                hard_limit,
                Some(declared_size as usize),
            ) {
                Ok(o) => {
                    zlib_end = zlib_start + o.consumed;
                    if o.data.len() as u64 != declared_size {
                        entry_error = Some(format!(
                            "大小欺骗：头声明未压缩大小 {declared_size}，实际解压 {} 字节",
                            o.data.len()
                        ));
                    }
                    data = o.data;
                }
                Err(f) => {
                    zlib_end = zlib_start + f.consumed;
                    entry_error = Some(match f.kind {
                        InflateError::LimitExceeded { produced, limit } => format!(
                            "大小欺骗/超预算：实际解压至少 {produced} 字节，超过允许上限 {limit}（头声明 {declared_size}）"
                        ),
                        InflateError::Truncated => {
                            "zlib 流在结束前被截断（解压到一半才发现数据不足）".into()
                        }
                        InflateError::Corrupt(e) => format!("zlib/deflate 数据损坏：{e}"),
                        InflateError::Adler32Mismatch => "zlib adler32 校验失败".into(),
                    });
                }
            }
        }

        let crc_end = zlib_end.max(zlib_start);
        let crc = crc32_of(&bytes[entry_start..crc_end]);
        entries.push(ParsedEntry {
            offset: entry_start as u64,
            header_len: hdr,
            kind: kind.unwrap_or(ParsedEntryKind::Base(ObjType::Blob)),
            declared_size,
            data,
            zlib_range: (zlib_start, zlib_end),
            crc32: crc,
            error: entry_error,
        });

        // 定位下一条 entry：正常情况下紧跟 zlib 流；若本对象损坏导致边界未知，
        // 则借助 index 提示偏移重新对齐；都没有就只能终止扫描。
        let next_pos = if zlib_end > zlib_start {
            zlib_end
        } else {
            let hint = next_hint
                .clone()
                .find(|h| (*h as usize) > entry_start);
            match hint {
                Some(h) => {
                    scan_error.get_or_insert_with(|| {
                        format!(
                            "偏移 {entry_start} 的对象损坏且 zlib 边界未知，借助 index 跳过到 {h}"
                        )
                    });
                    h as usize
                }
                None => {
                    scan_error = Some(format!(
                        "偏移 {entry_start} 的对象损坏，且无 index 偏移可用于重新对齐，停止扫描"
                    ));
                    break;
                }
            }
        };
        pos = next_pos;
        idx += 1;
    }

    if scan_error.is_none() && entries.len() as u32 != num_objects {
        scan_error = Some(format!(
            "pack 声明 {num_objects} 个对象，实际解析出 {} 个",
            entries.len()
        ));
    }

    let (trailer_sha1, computed_sha1, trailer_ok) = if bytes.len() >= 20 {
        let mut t = Oid::default();
        t.copy_from_slice(&bytes[bytes.len() - 20..]);
        let body_end = bytes.len() - 20;
        // 注意：只有当我们扫描到 trailer 前、且中间没有空洞时，computed 才有意义。
        let scanned_all = scan_error.is_none() && pos == bytes.len() - 20;
        let computed = if scanned_all {
            let mut h2 = Sha1::new();
            Digest::update(&mut h2, &bytes[..bytes.len() - 20]);
            let c: Oid = h2.finalize().into();
            Some(c)
        } else {
            None
        };
        let ok = computed.map(|c| c == t).unwrap_or(false);
        (Some(t), computed, ok)
    } else {
        (None, None, false)
    };

    if scan_error.is_some() {
        fatal = scan_error;
    }

    ParsedPack {
        version,
        num_objects,
        entries,
        fatal,
        trailer_sha1,
        computed_sha1,
        trailer_ok,
    }
}

fn fatal_pack(msg: &str) -> ParsedPack {
    ParsedPack {
        version: 0,
        num_objects: 0,
        entries: Vec::new(),
        fatal: Some(msg.to_string()),
        trailer_sha1: None,
        computed_sha1: None,
        trailer_ok: false,
    }
}

fn sha1_of(bytes: &[u8]) -> Oid {
    let mut h = Sha1::new();
    Digest::update(&mut h, bytes);
    h.finalize().into()
}

/// 解析 pack index（自动识别 v1 / v2），并做 fanout 一致性检查。
pub fn parse_index(bytes: &[u8]) -> Result<ParsedIndex, String> {
    if bytes.len() < 8 {
        return Err("index 文件过短".into());
    }
    let mut problems = Vec::new();

    if bytes[0..4] == IDX_SIG {
        let version = u32_be(&bytes[4..8]);
        if version != 2 {
            return Err(format!("不支持的 index v{version}（仅支持 v2）"));
        }
        // fanout：256 个 u32，位于偏移 8
        let mut fanout = [0u32; 256];
        for i in 0..256 {
            fanout[i] = u32_be(&bytes[8 + 4 * i..12 + 4 * i]);
        }
        let n = fanout[255] as usize;
        for w in fanout.windows(2) {
            if w[0] > w[1] {
                problems.push("fanout 表非单调递增（index 已损坏）".into());
            }
        }
        let mut p = 8 + 256 * 4;
        let need = p + n * (20 + 4 + 4) + 40;
        if bytes.len() < need {
            return Err(format!("index v2 长度不足：需要 {need}，实际 {}", bytes.len()));
        }
        let oids = p;
        p += n * 20;
        let crcs = p;
        p += n * 4;
        let offs = p;
        p += n * 4;

        let mut records = Vec::with_capacity(n);
        for i in 0..n {
            let mut oid = Oid::default();
            oid.copy_from_slice(&bytes[oids + i * 20..oids + (i + 1) * 20]);
            let crc = u32_be(&bytes[crcs + i * 4..crcs + i * 4 + 4]);
            let raw_off = u32_be(&bytes[offs + i * 4..offs + i * 4 + 4]);
            let offset = if raw_off & 0x8000_0000 != 0 {
                let idx = (raw_off & 0x7fff_ffff) as usize;
                let base = p + idx * 8;
                if base + 8 > bytes.len() - 40 {
                    return Err(format!("index v2 大偏移表项 {i} 越界"));
                }
                u64::from_be_bytes(bytes[base..base + 8].try_into().unwrap())
            } else {
                raw_off as u64
            };
            records.push(IdxRecord {
                oid,
                offset,
                crc32: Some(crc),
            });
        }

        let pack_checksum = {
            let mut o = Oid::default();
            o.copy_from_slice(&bytes[bytes.len() - 40..bytes.len() - 20]);
            o
        };
        let idx_checksum = {
            let mut o = Oid::default();
            o.copy_from_slice(&bytes[bytes.len() - 20..]);
            o
        };
        let calc_idx = sha1_of(&bytes[..bytes.len() - 20]);
        if calc_idx != idx_checksum {
            problems.push(format!(
                "index 尾部自校验 SHA1 不符：声明 {}，实算 {}",
                crate::gitid::oid_hex(&idx_checksum),
                crate::gitid::oid_hex(&calc_idx)
            ));
        }
        let mut sorted = records.iter().map(|r| r.oid).collect::<Vec<_>>();
        sorted.sort();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            problems.push("index 中存在重复 oid".into());
        }

        Ok(ParsedIndex {
            version: 2,
            fanout,
            records,
            problems,
            pack_checksum: Some(pack_checksum),
        })
    } else {
        // v1：256 个 fanout，随后每条 24 字节（4 偏移 + 20 oid），最后 40 字节校验。
        let mut fanout = [0u32; 256];
        for i in 0..256 {
            fanout[i] = u32_be(&bytes[4 * i..4 * i + 4]);
        }
        let n = fanout[255] as usize;
        let need = 256 * 4 + n * 24 + 40;
        if bytes.len() < need {
            return Err(format!("index v1 长度不足：需要 {need}，实际 {}", bytes.len()));
        }
        let mut records = Vec::with_capacity(n);
        for i in 0..n {
            let base = 256 * 4 + i * 24;
            let offset = u32_be(&bytes[base..base + 4]) as u64;
            let mut oid = Oid::default();
            oid.copy_from_slice(&bytes[base + 4..base + 24]);
            records.push(IdxRecord {
                oid,
                offset,
                crc32: None,
            });
        }
        let pack_checksum = {
            let mut o = Oid::default();
            o.copy_from_slice(&bytes[bytes.len() - 40..bytes.len() - 20]);
            o
        };
        Ok(ParsedIndex {
            version: 1,
            fanout,
            records,
            problems: Vec::new(),
            pack_checksum: Some(pack_checksum),
        })
    }
}

impl ParsedPack {
    /// 已成功解析的 entry 偏移集合。
    pub fn known_offsets(&self) -> Vec<u64> {
        self.entries.iter().map(|e| e.offset).collect()
    }
}
