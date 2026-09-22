use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::error::PError;
use crate::oid::Oid;
use crate::types::EntryType;
use crate::zlib::inflate_stream;

/// 单个对象解压的硬上限（防 zip bomb），512 MiB。
pub const HARD_INFLATE_LIMIT: u64 = 512 * 1024 * 1024;

/// 解析出的一个 pack 条目（已解压 delta/base 负载）。
#[derive(Debug, Clone)]
pub struct ParsedEntry {
    /// 在包内的对象起始偏移（指向类型字节）。
    pub offset: u64,
    pub etype: EntryType,
    /// 对非 delta 条目的声明类型。
    pub kind: Option<crate::types::ObjKind>,
    /// ofs-delta：基对象偏移。
    pub base_offset: Option<u64>,
    /// ref-delta：基对象 20 字节 oid。
    pub base_ref: Option<Oid>,
    /// 头部声明的（解压后）大小。
    pub declared_size: u64,
    /// header 占用字节数 [offset, data_start)。
    pub header_len: usize,
    /// 压缩数据起点。
    pub data_start: u64,
    /// 实际解出的负载字节数。
    pub inflated_size: u64,
    /// zlib 边界：压缩数据占用字节数。
    pub zlib_consumed: usize,
    /// 压缩数据（用于 index CRC32 校验取证）。
    pub compressed: Vec<u8>,
    /// 解压后的负载：base 即对象内容；delta 即 delta 指令数据。
    pub payload: Vec<u8>,
    /// 该条目自身解析错误（隔离坏对象后继续）。
    pub error: Option<PError>,
}

/// 256 个 fanout 桶（pack 本身没有 fanout，这里按对象偏移做分布供布局展示）。
#[derive(Debug, Clone, Serialize)]
pub struct PackFanout {
    pub buckets: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<ParsedEntry>,
    /// 包尾 SHA-1（文件给出的）。
    pub trailer_sha: Oid,
    /// 对包体计算得到的 SHA-1。
    pub computed_sha: Oid,
    pub checksum_ok: bool,
    /// 包级解析错误（导致整包不可信）。
    pub fatal: Option<PError>,
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_entry_header(buf: &[u8], pos: &mut usize) -> Result<ParsedEntry, PError> {
    let offset = *pos as u64;
    if *pos >= buf.len() {
        return Err(PError::Truncated {
            what: "对象头".to_string(),
            at: *pos,
            need: 1,
        });
    }
    let first = buf[*pos];
    *pos += 1;
    let type_num = (first >> 4) & 0x7;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut cont = first & 0x80 != 0;
    while cont {
        if *pos >= buf.len() {
            return Err(PError::Truncated {
                what: "对象大小续字节".to_string(),
                at: *pos,
                need: 1,
            });
        }
        let b = buf[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & 0x80 != 0;
    }

    let etype: EntryType;
    let mut kind = None;
    let mut base_offset = None;
    let mut base_ref = None;

    match type_num {
        1 | 2 | 3 | 4 => {
            let k = crate::types::ObjKind::from_type_num(type_num).unwrap();
            etype = EntryType::Base(k);
            kind = Some(k);
        }
        6 => {
            // ofs-delta：编码负向偏移
            etype = EntryType::OfsDelta;
            if *pos >= buf.len() {
                return Err(PError::Truncated {
                    what: "ofs-delta 偏移".to_string(),
                    at: *pos,
                    need: 1,
                });
            }
            let mut b = buf[*pos];
            *pos += 1;
            let mut distance: u64 = (b & 0x7f) as u64;
            while b & 0x80 != 0 {
                if *pos >= buf.len() {
                    return Err(PError::Truncated {
                        what: "ofs-delta 偏移续字节".to_string(),
                        at: *pos,
                        need: 1,
                    });
                }
                b = buf[*pos];
                *pos += 1;
                distance = ((distance + 1) << 7) | (b & 0x7f) as u64;
            }
            if distance > offset {
                return Err(PError::OfsOutOfBounds {
                    at: offset,
                    distance,
                });
            }
            base_offset = Some(offset - distance);
        }
        7 => {
            // ref-delta：20 字节 base oid
            etype = EntryType::RefDelta;
            if *pos + 20 > buf.len() {
                return Err(PError::Truncated {
                    what: "ref-delta base oid".to_string(),
                    at: *pos,
                    need: 20,
                });
            }
            base_ref = Some(Oid::from_slice(&buf[*pos..*pos+20]).map_err(PError::Io)?);
            *pos += 20;
        }
        other => return Err(PError::UnknownType(other)),
    }

    let header_len = (*pos as u64 - offset) as usize;
    Ok(ParsedEntry {
        offset,
        etype,
        kind,
        base_offset,
        base_ref,
        declared_size: size,
        header_len,
        data_start: *pos as u64,
        inflated_size: 0,
        zlib_consumed: 0,
        compressed: Vec::new(),
        payload: Vec::new(),
        error: None,
    })
}

/// 解析整个 pack 文件。
pub fn parse_pack(buf: &[u8]) -> ParsedPack {
    let mut pack = ParsedPack {
        version: 0,
        declared_count: 0,
        entries: Vec::new(),
        trailer_sha: Oid::zero(),
        computed_sha: Oid::zero(),
        checksum_ok: false,
        fatal: None,
    };

    if buf.len() < 32 {
        pack.fatal = Some(PError::Truncated {
            what: "pack 整体".to_string(),
            at: buf.len(),
            need: 32,
        });
        return pack;
    }
    if &buf[0..4] != b"PACK" {
        pack.fatal = Some(PError::BadSignature {
            what: "pack".to_string(),
            sig: hex::encode(&buf[0..4]),
        });
        return pack;
    }
    pack.version = u32be(&buf[4..8]);
    if pack.version != 2 {
        pack.fatal = Some(PError::UnsupportedPackVersion(pack.version));
        return pack;
    }
    pack.declared_count = u32be(&buf[8..12]);

    // 包体：[12 .. len-20)
    let body_end = buf.len() - 20;
    let trailer = &buf[body_end..body_end + 20];
    pack.trailer_sha = Oid::from_slice(trailer).unwrap_or(Oid::zero());
    let mut h = Sha1::new();
    h.update(&buf[..body_end]);
    let r = h.finalize();
    let mut cs = [0u8; 20];
    cs.copy_from_slice(&r);
    pack.computed_sha = Oid(cs);
    pack.checksum_ok = pack.computed_sha == pack.trailer_sha;

    let mut pos = 12usize;
    let mut idx_by_offset: std::collections::BTreeMap<u64, usize> =
        std::collections::BTreeMap::new();

    while pos < body_end {
        if pack.entries.len() as u32 >= pack.declared_count {
            // 声明数量已到但还有数据：说明结构异常，记录后停止。
            pack.fatal.get_or_insert_with(|| PError::ObjectCountMismatch {
                declared: pack.declared_count,
                parsed: pack.entries.len(),
            });
            break;
        }
        let entry_offset = pos as u64;
        let mut entry = match read_entry_header(buf, &mut pos) {
            Ok(e) => e,
            Err(e) => {
                // 头部都无法解析：无法可靠定位下一个对象。
                pack.fatal = Some(e);
                break;
            }
        };

        // ofs-delta 基址存在性检查（不阻断解压，记录为条目错误）。
        if let Some(bo) = entry.base_offset {
            if !idx_by_offset.contains_key(&bo) {
                entry.error = Some(PError::OfsNoEntry(bo));
            }
        }

        let src = &buf[pos..body_end];
        match inflate_stream(src, entry.declared_size, HARD_INFLATE_LIMIT) {
            Ok(inf) => {
                entry.zlib_consumed = inf.consumed;
                entry.inflated_size = inf.data.len() as u64;
                entry.payload = inf.data;
                entry.compressed = src[..inf.consumed].to_vec();
                pos += inf.consumed;
            }
            Err(e) => {
                // 隔离坏对象：若该对象的偏移可用于“跳过”，我们无法可靠跳过，
                // 因此记录到该条目并停止继续顺序解析（损坏点之后不可信）。
                entry.inflated_size = 0;
                entry.error = Some(e);
                pack.entries.push(entry);
                idx_by_offset.insert(entry_offset, pack.entries.len() - 1);
                if pack.fatal.is_none() {
                    pack.fatal = Some(PError::Zlib(format!(
                        "偏移 {} 处对象解压失败，其后对象无法顺序定位",
                        entry_offset
                    )));
                }
                break;
            }
        }

        pack.entries.push(entry);
        idx_by_offset.insert(entry_offset, pack.entries.len() - 1);
    }

    if pack.fatal.is_none() && pack.entries.len() as u32 != pack.declared_count {
        pack.fatal = Some(PError::ObjectCountMismatch {
            declared: pack.declared_count,
            parsed: pack.entries.len(),
        });
    }

    pack
}

/// 依据 index 给出的偏移尝试只解压并校验某个对象（坏 CRC 取证）。
pub fn inflate_at(buf: &[u8], data_start: u64, declared_size: u64) -> Result<crate::zlib::Inflated, PError> {
    let start = data_start as usize;
    if start >= buf.len() - 20 {
        return Err(PError::Bounds("data_start 越过包体".to_string()));
    }
    inflate_stream(&buf[start..buf.len() - 20], declared_size, HARD_INFLATE_LIMIT)
}
