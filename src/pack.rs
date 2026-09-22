//! Pack file, pack index (.idx) and loose object parsing. Pure Rust, no system git.

use crate::git::{hex_encode, object_id, zlib_inflate_bounded, ObjType};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct RawEntry {
    pub offset: u64,
    pub obj_type: ObjType,
    /// Declared (header) uncompressed size.
    pub size_hdr: u64,
    /// Absolute offset where the zlib stream (or delta base header) starts.
    pub data_start: u64,
    /// For ofs-delta: absolute offset of the base object in the same pack.
    pub base_offset: Option<u64>,
    /// For ref-delta: base object id.
    pub base_oid: Option<String>,
    /// Compressed zlib stream length in bytes.
    pub comp_len: u64,
    /// CRC-32 of the raw region [offset, data_start + comp_len).
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<RawEntry>,
    /// SHA-1 trailer of the pack (last 20 bytes).
    pub trailer: String,
    /// True when the trailer matches the hash of all preceding bytes.
    pub trailer_ok: bool,
    /// Non-fatal problems discovered while parsing.
    pub warnings: Vec<String>,
}

fn read_be32(data: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *data.get(pos)?,
        *data.get(pos + 1)?,
        *data.get(pos + 2)?,
        *data.get(pos + 3)?,
    ]))
}

/// Parse a PACK file. Tolerant: a truncated/corrupt object aborts the scan but
/// keeps everything parsed so far (bad-object isolation happens downstream).
pub fn parse_pack(data: &[u8]) -> Result<PackInfo, String> {
    if data.len() < 12 + 20 {
        return Err("文件太小, 不是有效的 PACK".to_string());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".to_string());
    }
    let version = read_be32(data, 4).ok_or("无法读取版本")?;
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let count = read_be32(data, 8).ok_or("无法读取对象数量")?;
    let mut pos = 12usize;
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let body_end = data.len() - 20;

    for idx in 0..count {
        if pos >= body_end {
            warnings.push(format!(
                "对象 {idx}/{count}: 数据提前结束, 后续对象缺失"
            ));
            break;
        }
        let offset = pos as u64;
        // object header: type + size varint
        let mut byte = data[pos];
        pos += 1;
        let type_code = (byte >> 4) & 0x7;
        let obj_type = match ObjType::from_pack_code(type_code) {
            Some(t) => t,
            None => {
                warnings.push(format!("对象 {idx}: 非法类型码 {type_code}, 停止扫描"));
                break;
            }
        };
        let mut size: u64 = (byte & 0x0f) as u64;
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            byte = match data.get(pos) {
                Some(b) => *b,
                None => {
                    warnings.push(format!("对象 {idx}: 头部 varint 截断"));
                    break;
                }
            };
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if shift > 63 {
                warnings.push(format!("对象 {idx}: 声明大小溢出"));
                break;
            }
        }

        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            ObjType::OfsDelta => {
                let mut b = match data.get(pos) {
                    Some(b) => *b,
                    None => {
                        warnings.push(format!("对象 {idx}: ofs-delta 偏移截断"));
                        break;
                    }
                };
                pos += 1;
                let mut dist: u64 = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    b = match data.get(pos) {
                        Some(x) => *x,
                        None => {
                            warnings.push(format!("对象 {idx}: ofs-delta 偏移截断"));
                            break;
                        }
                    };
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
                }
                // base = self - dist; dist == 0 or dist > offset means corrupt/cyclic.
                base_offset = Some(offset.wrapping_sub(dist));
                if dist == 0 || dist > offset {
                    warnings.push(format!(
                        "对象 {idx}: ofs 距离 {dist} 越界 (对象偏移 {offset})"
                    ));
                }
            }
            ObjType::RefDelta => {
                if pos + 20 > data.len() {
                    warnings.push(format!("对象 {idx}: ref-delta base oid 截断"));
                    break;
                }
                base_oid = Some(hex_encode(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {}
        }

        let data_start = pos as u64;
        // Find the zlib boundary. Cap output at a generous ceiling; the engine
        // re-checks against the declared size and its own budget.
        let cap = size_hdr_sane_cap(size);
        match zlib_inflate_bounded(&data[pos..body_end], cap) {
            Ok(res) => {
                let comp_len = res.consumed as u64;
                let raw = &data[offset as usize..pos + res.consumed];
                let crc32 = crc32fast::hash(raw);
                entries.push(RawEntry {
                    offset,
                    obj_type,
                    size_hdr: size,
                    data_start,
                    base_offset,
                    base_oid,
                    comp_len,
                    crc32,
                });
                pos += res.consumed;
            }
            Err(e) => {
                warnings.push(format!("对象 {idx} (偏移 {offset}): {e}; 停止扫描后续对象"));
                break;
            }
        }
    }

    let trailer = hex_encode(&data[data.len() - 20..]);
    let mut h = Sha1::new();
    h.update(&data[..data.len() - 20]);
    let expect = hex_encode(&h.finalize());
    let trailer_ok = trailer == expect;
    if !trailer_ok {
        warnings.push(format!("pack 校验和不匹配: 文件记录 {trailer}, 实际计算 {expect}"));
    }

    Ok(PackInfo {
        version,
        count,
        entries,
        trailer,
        trailer_ok,
        warnings,
    })
}

/// Sanity cap used while locating the zlib boundary. The declared size is
/// untrusted, so allow generous headroom; the engine enforces real budgets.
fn size_hdr_sane_cap(size_hdr: u64) -> u64 {
    size_hdr.saturating_mul(4).saturating_add(1 << 20).min(1 << 32)
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub version: u32,
    pub entries: Vec<IdxEntry>,
    /// Pack checksum recorded at the tail of the index.
    pub pack_checksum: String,
    pub fanout: [u32; 256],
}

/// Parse a .idx file (v1 and v2).
pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 4 * 256 {
        return Err("idx 文件太小".to_string());
    }
    let (version, fanout_start) = if data[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        let v = read_be32(data, 4).ok_or("idx 版本缺失")?;
        if v != 2 {
            return Err(format!("不支持的 idx 版本 {v}"));
        }
        (2, 8usize)
    } else {
        (1, 0usize)
    };
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_be32(data, fanout_start + 4 * i).ok_or("fanout 表截断")?;
    }
    let n = fanout[255] as usize;
    let mut entries = Vec::with_capacity(n);
    if version == 2 {
        let sha_start = fanout_start + 4 * 256;
        let crc_start = sha_start + 20 * n;
        let off_start = crc_start + 4 * n;
        let big_start = off_start + 4 * n;
        if data.len() < big_start {
            return Err("idx v2 表截断".to_string());
        }
        for i in 0..n {
            let oid = hex_encode(&data[sha_start + 20 * i..sha_start + 20 * i + 20]);
            let crc32 = read_be32(data, crc_start + 4 * i).ok_or("crc 表截断")?;
            let raw_off = read_be32(data, off_start + 4 * i).ok_or("offset 表截断")?;
            let offset = if raw_off & 0x8000_0000 != 0 {
                let idx64 = (raw_off & 0x7fff_ffff) as usize;
                let p = big_start + 8 * idx64;
                let hi = read_be32(data, p).ok_or("64 位 offset 表截断")? as u64;
                let lo = read_be32(data, p + 4).ok_or("64 位 offset 表截断")? as u64;
                (hi << 32) | lo
            } else {
                raw_off as u64
            };
            entries.push(IdxEntry { oid, offset, crc32 });
        }
        if data.len() < big_start + 40 {
            return Err("idx v2 校验和截断".to_string());
        }
        let pack_checksum = hex_encode(&data[data.len() - 40..data.len() - 20]);
        Ok(IdxInfo { version: 2, entries, pack_checksum, fanout })
    } else {
        let entry_start = fanout_start + 4 * 256;
        if data.len() < entry_start + 24 * n {
            return Err("idx v1 表截断".to_string());
        }
        for i in 0..n {
            let p = entry_start + 24 * i;
            let offset = read_be32(data, p)? as u64;
            let oid = hex_encode(&data[p + 4..p + 24]);
            entries.push(IdxEntry { oid, offset, crc32: 0 });
        }
        Ok(IdxInfo {
            version: 1,
            entries,
            pack_checksum: String::new(),
            fanout,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub obj_type: ObjType,
    pub content: Vec<u8>,
    pub oid: String,
}

/// Parse a loose object file (zlib of "<type> <size>\0<content>").
pub fn parse_loose(data: &[u8]) -> Result<LooseObject, String> {
    let res = zlib_inflate_bounded(data, 1 << 32)?;
    let nul = res
        .out
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose 对象缺少头部 NUL")?;
    let header = std::str::from_utf8(&res.out[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().ok_or("loose 头部缺少类型")?;
    let size: u64 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or("loose 头部缺少大小")?;
    let obj_type = ObjType::parse(type_name).ok_or(format!("未知 loose 类型 {type_name}"))?;
    if obj_type.is_delta() {
        return Err("loose 对象不应是 delta 类型".to_string());
    }
    let content = res.out[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose 大小欺骗: 头部声明 {} 实际 {}",
            size,
            content.len()
        ));
    }
    let oid = object_id(obj_type, &content);
    Ok(LooseObject { obj_type, content, oid })
}
