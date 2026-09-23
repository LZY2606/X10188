//! Git pack file parser: header, object type/size varints, ofs-delta / ref-delta
//! base references, zlib stream boundary detection, per-entry CRC32 and the
//! pack trailer checksum. Pure Rust, no system git.

use crc32fast::Hasher as Crc32;
use flate2::{Decompress, FlushDecompress, Status};

use crate::gitutil;

/// Hard cap for a single inflated entry, to contain zip-bomb style input.
pub const INFLATE_HARD_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RawEntry {
    pub offset: u64,
    pub type_id: u8,
    pub declared_size: u64,
    /// Bytes from entry start to the start of the zlib stream.
    pub hdr_len: u64,
    /// Absolute offset of the ofs-delta base (offset - distance).
    pub base_offset: Option<u64>,
    /// Raw ofs distance as encoded (for bounds diagnostics).
    pub ofs_distance: Option<u64>,
    pub base_oid: Option<String>,
    /// Compressed zlib stream length in bytes.
    pub comp_len: u64,
    pub crc32: u32,
    /// Inflated payload (delta instructions for delta entries). None on error.
    pub inflated: Option<Vec<u8>>,
    pub parse_error: Option<String>,
}

#[derive(Debug)]
pub struct PackParse {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<RawEntry>,
    pub trailer_ok: Option<bool>,
    pub errors: Vec<String>,
}

/// Inflate a zlib stream starting at `input[0]`, returning (output, consumed
/// input bytes). Stops with `SpoofExceeded` as soon as output exceeds `cap`,
/// i.e. mid-stream, so a lying size header is caught before full expansion.
pub fn zlib_inflate_bounded(input: &[u8], cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= input.len() {
            return Err("zlib 流被截断: 输入耗尽但流未结束".into());
        }
        let status = d
            .decompress(&input[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压错误: {e}"))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > cap {
            return Err(format!(
                "大小欺骗: 解压到一半输出已超过声明上限 ({} > {})",
                out.len(),
                cap
            ));
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if produced == 0 && d.total_in() as usize == in_before {
                    return Err("zlib 流无进展 (数据损坏)".into());
                }
            }
        }
    }
}

fn parse_entry_header(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= data.len() {
        return Err("对象头越界".into());
    }
    let mut c = data[pos];
    pos += 1;
    let type_id = (c >> 4) & 0x7;
    let mut size: u64 = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        if pos >= data.len() || shift > 63 {
            return Err("对象大小 varint 损坏".into());
        }
        c = data[pos];
        pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((type_id, size, pos))
}

fn parse_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= data.len() {
        return Err("ofs-delta 偏移越界".into());
    }
    let mut c = data[pos];
    pos += 1;
    let mut ofs: u64 = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if pos >= data.len() {
            return Err("ofs-delta 偏移 varint 损坏".into());
        }
        c = data[pos];
        pos += 1;
        ofs = ((ofs + 1) << 7) | (c & 0x7f) as u64;
    }
    Ok((ofs, pos))
}

pub fn parse_pack(data: &[u8]) -> Result<PackParse, String> {
    if data.len() < 12 + 20 {
        return Err("文件太小, 不是合法 pack".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK magic".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let num_objects = u32::from_be_bytes(data[8..12].try_into().unwrap());

    // Trailer: sha1 of everything before it.
    let body = &data[..data.len() - 20];
    let trailer = &data[data.len() - 20..];
    let trailer_ok = Some(gitutil::sha1_hex(body) == hex::encode(trailer));

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    let limit = data.len() - 20;

    for idx in 0..num_objects {
        if pos >= limit {
            errors.push(format!(
                "pack 在第 {idx} 个对象处提前结束 (声明 {num_objects} 个)"
            ));
            break;
        }
        let entry_start = pos;
        let mut entry = RawEntry {
            offset: entry_start as u64,
            type_id: 0,
            declared_size: 0,
            hdr_len: 0,
            base_offset: None,
            ofs_distance: None,
            base_oid: None,
            comp_len: 0,
            crc32: 0,
            inflated: None,
            parse_error: None,
        };
        let parsed = (|| -> Result<(), String> {
            let (type_id, size, p) = parse_entry_header(data, pos)?;
            pos = p;
            entry.type_id = type_id;
            entry.declared_size = size;
            match type_id {
                1 | 2 | 3 | 4 => {}
                6 => {
                    let (ofs, p) = parse_ofs_distance(data, pos)?;
                    pos = p;
                    entry.ofs_distance = Some(ofs);
                    if ofs == 0 || ofs > entry_start as u64 {
                        // Out-of-range distance: record, base_offset stays None.
                        entry.parse_error =
                            Some(format!("ofs 距离越界: distance={ofs} 于 offset={entry_start}"));
                    } else {
                        entry.base_offset = Some(entry_start as u64 - ofs);
                    }
                }
                7 => {
                    if pos + 20 > data.len() {
                        return Err("ref-delta base oid 越界".into());
                    }
                    entry.base_oid = Some(hex::encode(&data[pos..pos + 20]));
                    pos += 20;
                }
                _ => return Err(format!("未知对象类型 {type_id}")),
            }
            entry.hdr_len = (pos - entry_start) as u64;
            // Inflate with cap = declared size; catching overflow mid-stream
            // proves a spoofed size header.
            let cap = entry.declared_size.min(INFLATE_HARD_CAP);
            match zlib_inflate_bounded(&data[pos..], cap) {
                Ok((out, consumed)) => {
                    entry.comp_len = consumed as u64;
                    if out.len() as u64 != entry.declared_size {
                        entry.parse_error = Some(format!(
                            "大小欺骗: 声明 {} 字节, 实际解压 {} 字节",
                            entry.declared_size,
                            out.len()
                        ));
                    } else {
                        entry.inflated = Some(out);
                    }
                    pos += consumed;
                }
                Err(e) => {
                    entry.parse_error = Some(e);
                    // Cannot locate the next entry reliably; stop the walk.
                    return Err("流边界丢失, 后续对象不可信".into());
                }
            }
            let mut c = Crc32::new();
            c.update(&data[entry_start..pos]);
            entry.crc32 = c.finalize();
            Ok(())
        })();
        if let Err(e) = parsed {
            if entry.parse_error.is_none() {
                entry.parse_error = Some(e.clone());
            }
            errors.push(format!("offset {entry_start}: {e}"));
            entries.push(entry);
            break;
        }
        entries.push(entry);
    }

    Ok(PackParse {
        version,
        num_objects,
        entries,
        trailer_ok,
        errors,
    })
}
