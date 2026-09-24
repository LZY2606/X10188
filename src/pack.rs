//! Git pack 与 idx(v2) 解析：header、对象类型、ofs/ref-delta、zlib 边界、fanout、CRC。

use crate::model::{is_delta_kind, kind_name};
use crate::zlib::inflate_bounded;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct ParsedEntry {
    pub offset: u64,
    pub kind: String,
    pub declared_size: u64,
    pub data_offset: u64,
    pub data_end: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub crc32: u32,
    pub data: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<ParsedEntry>,
    pub trailer_ok: bool,
    pub pack_sha1: String,
    pub errors: Vec<String>,
}

fn be32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// 解析 pack。逐对象解析，坏对象记录错误并隔离；zlib 边界无法确定时停止后续解析。
pub fn parse_pack(buf: &[u8]) -> Result<ParsedPack, String> {
    if buf.len() < 12 + 20 {
        return Err("文件太小，不是合法 pack".into());
    }
    if &buf[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = be32(buf, 4);
    let count = be32(buf, 8);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {}", version));
    }
    let trailer_pos = buf.len() - 20;
    let pack_sha1 = hex::encode(&buf[trailer_pos..]);
    let mut h = Sha1::new();
    h.update(&buf[..trailer_pos]);
    let trailer_ok = hex::encode(h.finalize()) == pack_sha1;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos: usize = 12;

    for i in 0..count {
        if pos >= trailer_pos {
            errors.push(format!("第 {} 个对象超出包体，声明数量 {} 与实际不符", i, count));
            break;
        }
        let entry_offset = pos as u64;
        // 对象头 varint：msb 续位，bits 4..6 类型，低 4 位 + 后续 7 位组为大小
        let mut byte = buf[pos];
        pos += 1;
        let kind_code = (byte >> 4) & 0x07;
        let mut size = (byte & 0x0f) as u64;
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            if pos >= trailer_pos || shift >= 64 {
                return Err(format!("对象 @{} 头部 varint 损坏", entry_offset));
            }
            byte = buf[pos];
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
        }
        let kind = kind_name(kind_code).to_string();
        let mut base_offset = None;
        let mut base_oid = None;
        let mut error: Option<String> = None;

        match kind_code {
            6 => {
                // ofs-delta：负偏移编码
                let mut b = buf[pos];
                pos += 1;
                let mut off = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    if pos >= trailer_pos {
                        return Err(format!("ofs-delta @{} 偏移编码截断", entry_offset));
                    }
                    b = buf[pos];
                    pos += 1;
                    off = ((off + 1) << 7) | ((b & 0x7f) as u64);
                }
                if off == 0 || off > entry_offset {
                    error = Some(format!(
                        "ofs 距离越界：distance={} 超出当前对象偏移 {}",
                        off, entry_offset
                    ));
                } else {
                    base_offset = Some(entry_offset - off);
                }
            }
            7 => {
                // ref-delta：20 字节 base oid
                if pos + 20 > trailer_pos {
                    return Err(format!("ref-delta @{} base oid 截断", entry_offset));
                }
                base_oid = Some(hex::encode(&buf[pos..pos + 20]));
                pos += 20;
            }
            1..=4 => {}
            _ => {
                error = Some(format!("未知对象类型码 {}", kind_code));
            }
        }

        let data_offset = pos as u64;
        let mut data = None;
        let mut data_end = trailer_pos as u64;
        match inflate_bounded(&buf[pos..trailer_pos]) {
            Ok((raw, consumed)) => {
                data_end = (pos + consumed) as u64;
                pos += consumed;
                if raw.len() as u64 != size && error.is_none() {
                    error = Some(format!(
                        "大小欺骗：头部声明 {} 字节，实际解压 {} 字节",
                        size,
                        raw.len()
                    ));
                }
                data = Some(raw);
            }
            Err(e) => {
                if error.is_none() {
                    error = Some(format!("对象 @{} zlib 解压失败: {}", entry_offset, e));
                }
                // 无法确定 zlib 边界，后续对象无法定位，停止解析
                let crc = crc32fast::hash(&buf[entry_offset as usize..trailer_pos]);
                entries.push(ParsedEntry {
                    offset: entry_offset,
                    kind,
                    declared_size: size,
                    data_offset,
                    data_end,
                    base_offset,
                    base_oid,
                    crc32: crc,
                    data,
                    error,
                });
                errors.push(format!(
                    "第 {} 个对象 (@{}) 后无法定位 zlib 边界，剩余对象被隔离",
                    i, entry_offset
                ));
                break;
            }
        }
        let crc = crc32fast::hash(&buf[entry_offset as usize..data_end as usize]);
        entries.push(ParsedEntry {
            offset: entry_offset,
            kind,
            declared_size: size,
            data_offset,
            data_end,
            base_offset,
            base_oid,
            crc32: crc,
            data,
            error,
        });
    }

    Ok(ParsedPack {
        version,
        count,
        entries,
        trailer_ok,
        pack_sha1,
        errors,
    })
}

// ---------------- idx v2 ----------------

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub self_ok: bool,
}

pub fn parse_idx(buf: &[u8]) -> Result<ParsedIdx, String> {
    if buf.len() < 8 + 256 * 4 + 40 {
        return Err("idx 文件太小".into());
    }
    if &buf[0..4] != b"\xfftOc" {
        return Err("仅支持 idx v2（缺少 \\xfftOc 魔数）".into());
    }
    if be32(buf, 4) != 2 {
        return Err("仅支持 idx 版本 2".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = be32(buf, 8 + i * 4);
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    if buf.len() < big_base + 40 {
        return Err("idx 文件截断".into());
    }
    let trailer_pos = buf.len() - 20;
    let pack_sha1 = hex::encode(&buf[trailer_pos - 20..trailer_pos]);
    let mut h = Sha1::new();
    h.update(&buf[..trailer_pos]);
    let self_ok = hex::encode(h.finalize()) == hex::encode(&buf[trailer_pos..]);

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&buf[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 = be32(buf, crc_base + i * 4);
        let raw_off = be32(buf, off_base + i * 4);
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let at = big_base + idx * 8;
            if at + 8 > trailer_pos - 20 {
                return Err("idx 64 位偏移表越界".into());
            }
            u64::from_be_bytes(buf[at..at + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    Ok(ParsedIdx {
        fanout,
        entries,
        pack_sha1,
        self_ok,
    })
}

/// 供引擎判断 kind 字符串是否为 delta。
pub fn entry_is_delta(kind: &str) -> bool {
    is_delta_kind(kind)
}
