//! 纯 Rust 实现的 Git pack / index / loose object 解析。
//! 不调用系统 git；zlib 边界通过 miniz_oxide 流式 inflate 精确定位。

use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn type_from_name(s: &str) -> Option<u8> {
    Some(match s {
        "commit" => OBJ_COMMIT,
        "tree" => OBJ_TREE,
        "blob" => OBJ_BLOB,
        "tag" => OBJ_TAG,
        _ => return None,
    })
}

pub fn is_full_type(t: u8) -> bool {
    matches!(t, OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG)
}

/// 计算 Git 对象 id：sha1("type size\0" + content)。
pub fn git_oid(obj_type: u8, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(type_name(obj_type).as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

/// pack entry header varint：最高位续位；首字节 bit6..4 为类型，bit3..0 为 size 低 4 位。
pub fn parse_entry_header(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize)> {
    if pos >= data.len() {
        bail!("entry header 越界");
    }
    let first = data[pos];
    pos += 1;
    let obj_type = (first >> 4) & 0b111;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4u32;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            bail!("entry header 截断");
        }
        byte = data[pos];
        pos += 1;
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if shift > 70 {
            bail!("size varint 过长");
        }
    }
    Ok((obj_type, size, pos))
}

/// ofs-delta 的负向偏移编码。
pub fn parse_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    if pos >= data.len() {
        bail!("ofs-delta 偏移截断");
    }
    let mut byte = data[pos];
    pos += 1;
    let mut distance = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            bail!("ofs-delta 偏移截断");
        }
        byte = data[pos];
        pos += 1;
        distance = distance.wrapping_add(1).wrapping_shl(7) | u64::from(byte & 0x7f);
    }
    Ok((distance, pos))
}

/// delta 头部使用的小端变长 size（base size / result size）。
pub fn parse_size_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            bail!("delta size varint 截断");
        }
        let byte = data[pos];
        pos += 1;
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if shift > 70 {
            bail!("delta size varint 过长");
        }
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((size, pos))
}

pub struct InflateOutcome {
    pub output: Vec<u8>,
    /// zlib 流实际消费的压缩字节数（流边界）。
    pub consumed: usize,
    /// 是否到达 zlib stream end（adler32 由 miniz_oxide 校验）。
    pub complete: bool,
    /// 解压输出超过 max_out 时提前停止，输出不可作为完整对象使用。
    pub budget_exceeded: bool,
}

/// 从 `start` 开始流式解压 zlib 数据，精确返回流边界。
pub fn inflate_zlib(data: &[u8], start: usize, max_out: Option<u64>) -> Result<InflateOutcome> {
    use miniz_oxide::inflate::stream::{inflate, InflateState};
    use miniz_oxide::{DataFormat, MZFlush, MZStatus};

    if start > data.len() {
        bail!("zlib 起点越界");
    }
    let mut state = InflateState::new_boxed(DataFormat::Zlib);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut buf = [0u8; 64 * 1024];

    loop {
        let input = data.get(pos..).unwrap_or(&[]);
        let res = inflate(&mut state, input, &mut buf, MZFlush::None)
            .map_err(|e| anyhow::anyhow!("zlib 解压失败: {e:?}"))?;
        pos += res.bytes_consumed;
        out.extend_from_slice(&buf[..res.bytes_written]);

        if let Some(max) = max_out {
            if out.len() as u64 > max {
                return Ok(InflateOutcome {
                    output: out,
                    consumed: pos - start,
                    complete: false,
                    budget_exceeded: true,
                });
            }
        }

        match res.status {
            MZStatus::StreamEnd => {
                return Ok(InflateOutcome {
                    output: out,
                    consumed: pos - start,
                    complete: true,
                    budget_exceeded: false,
                });
            }
            MZStatus::Ok | MZStatus::NeedDict => {
                if res.bytes_consumed == 0 && res.bytes_written == 0 {
                    if pos >= data.len() {
                        // 输入耗尽仍未结束 -> 截断；部分输出不能当完整对象。
                        return Ok(InflateOutcome {
                            output: out,
                            consumed: pos - start,
                            complete: false,
                            budget_exceeded: false,
                        });
                    }
                    bail!("zlib 流无法继续推进（数据损坏）");
                }
            }
            other => bail!("zlib 状态异常: {other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeltaInfo {
    pub base_size: u64,
    pub declared_out_size: u64,
    pub instr_offset: usize,
    pub instr_len: usize,
    pub copy_count: u32,
    pub insert_count: u32,
}

/// 应用 Git delta 指令流。校验 base 大小、输出声明大小与所有 copy/insert 边界。
pub fn apply_delta(base: &[u8], delta: &[u8], max_out: Option<u64>) -> Result<(Vec<u8>, DeltaInfo)> {
    let (base_size, out_size, instr_start) = parse_delta_header(delta)?;
    if base_size != base.len() as u64 {
        bail!("delta base 大小不匹配：声明 {base_size}，实际 {}", base.len());
    }
    let mut out: Vec<u8> = Vec::with_capacity(out_size.min(1 << 24) as usize);
    let mut pos = instr_start;
    let mut copy_count = 0u32;
    let mut insert_count = 0u32;

    while pos < delta.len() {
        let read = |pos: &mut usize| -> Result<u8> {
            let b = *delta.get(*pos).context("copy 操作数截断")?;
            *pos += 1;
            Ok(b)
        };
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            let mut nb = || read(&mut pos);
            if cmd & 0x01 != 0 { cp_off |= u64::from(nb()?); }
            if cmd & 0x02 != 0 { cp_off |= u64::from(nb()?) << 8; }
            if cmd & 0x04 != 0 { cp_off |= u64::from(nb()?) << 16; }
            if cmd & 0x08 != 0 { cp_off |= u64::from(nb()?) << 24; }
            if cmd & 0x10 != 0 { cp_size |= u64::from(nb()?); }
            if cmd & 0x20 != 0 { cp_size |= u64::from(nb()?) << 8; }
            if cmd & 0x40 != 0 { cp_size |= u64::from(nb()?) << 16; }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off.checked_add(cp_size).context("copy offset 溢出")?;
            if end > base.len() as u64 {
                bail!("copy 指令越界：offset={cp_off} size={cp_size}，base 长度 {}", base.len());
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            copy_count += 1;
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                bail!("insert 指令越界：需要 {n} 字节，剩余 {}", delta.len() - pos);
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            insert_count += 1;
        } else {
            bail!("非法 delta 指令 0x00");
        }
        if let Some(max) = max_out {
            if out.len() as u64 > max {
                bail!("delta 展开超过预算（{max} 字节）");
            }
        }
        if out.len() as u64 > out_size {
            bail!("delta 输出超过声明大小 {out_size}");
        }
    }

    if out.len() as u64 != out_size {
        bail!("delta 输出大小不符：声明 {out_size}，实际 {}", out.len());
    }
    Ok((
        out,
        DeltaInfo {
            base_size,
            declared_out_size: out_size,
            instr_offset: instr_start,
            instr_len: delta.len() - instr_start,
            copy_count,
            insert_count,
        },
    ))
}

pub fn parse_delta_header(delta: &[u8]) -> Result<(u64, u64, usize)> {
    let (base_size, p1) = parse_size_varint(delta, 0)?;
    let (out_size, p2) = parse_size_varint(delta, p1)?;
    Ok((base_size, out_size, p2))
}

#[derive(Debug, Clone)]
pub enum DeltaBase {
    Ofs { distance: u64, base_offset: u64 },
    Ref { oid: [u8; 20] },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub ordinal: u32,
    pub offset: u64,
    pub obj_type: u8,
    pub declared_size: u64,
    pub base: Option<DeltaBase>,
    pub data_offset: u64,
    pub data_len: u64,
    pub end_offset: u64,
    /// [offset, end_offset) 原始字节的 crc32，供 index 核对。
    pub crc32: u32,
    /// 解析期解压发现的问题（边界仍记录，对象交由引擎隔离）。
    pub inflate_note: Option<String>,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub object_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: [u8; 20],
    pub trailer_ok: bool,
    pub trailing_bytes: usize,
}

/// 解析 pack：header、entry header、ofs/ref delta、zlib 边界、trailer 校验。
pub fn parse_pack(data: &[u8]) -> Result<ParsedPack> {
    if data.len() < 32 {
        bail!("pack 文件过短（{} 字节）", data.len());
    }
    if &data[0..4] != b"PACK" {
        bail!("缺少 PACK 魔数");
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        bail!("不支持的 pack 版本 {version}");
    }
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());

    let mut pos = 12usize;
    let mut entries = Vec::with_capacity(object_count as usize);
    for ordinal in 0..object_count {
        let offset = pos as u64;
        let (obj_type, size, p2) = parse_entry_header(data, pos)
            .with_context(|| format!("entry #{ordinal}（offset {offset}）header 解析失败"))?;
        pos = p2;

        let base = match obj_type {
            OBJ_OFS_DELTA => {
                let (distance, p3) = parse_ofs_distance(data, pos)
                    .with_context(|| format!("entry #{ordinal} ofs-delta 偏移解析失败"))?;
                pos = p3;
                let base_offset = offset.saturating_sub(distance);
                Some(DeltaBase::Ofs { distance, base_offset })
            }
            OBJ_REF_DELTA => {
                if pos + 20 > data.len() {
                    bail!("entry #{ordinal} ref-delta base oid 截断");
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&data[pos..pos + 20]);
                pos += 20;
                Some(DeltaBase::Ref { oid })
            }
            other if is_full_type(other) => None,
            other => bail!("entry #{ordinal} 非法对象类型 {other}"),
        };

        let data_offset = pos as u64;
        let outcome = inflate_zlib(data, pos, None)
            .with_context(|| format!("entry #{ordinal}（offset {offset}）zlib 解析失败"))?;
        pos += outcome.consumed;
        let end_offset = pos as u64;
        let crc = crc32fast::hash(&data[offset as usize..pos]);
        let inflate_note = if !outcome.complete {
            Some("zlib 流提前结束（截断）".to_string())
        } else if outcome.output.len() as u64 != size {
            Some(format!("大小欺骗：header 声明 {size}，实际解压 {}", outcome.output.len()))
        } else {
            None
        };
        entries.push(PackEntry {
            ordinal,
            offset,
            obj_type,
            declared_size: size,
            base,
            data_offset,
            data_len: end_offset - data_offset,
            end_offset,
            crc32: crc,
            inflate_note,
        });
    }

    if pos + 20 > data.len() {
        bail!("pack trailer 缺失（entry 数据可能超长）");
    }
    let mut trailer = [0u8; 20];
    trailer.copy_from_slice(&data[pos..pos + 20]);
    let digest = Sha1::digest(&data[..pos]);
    let trailer_ok = digest.as_slice() == trailer;
    let trailing_bytes = data.len() - pos - 20;

    Ok(ParsedPack {
        version,
        object_count,
        entries,
        trailer,
        trailer_ok,
        trailing_bytes,
    })
}

#[derive(Debug)]
pub struct IndexEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedIndex {
    pub fanout: [u32; 256],
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: [u8; 20],
    pub index_checksum: [u8; 20],
    pub fanout_ok: bool,
    pub checksum_ok: bool,
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

fn be64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
}

/// 解析 index v2：fanout、oid、crc32、offset（含 64 位大偏移表）、两级 checksum。
pub fn parse_index(data: &[u8]) -> Result<ParsedIndex> {
    if data.len() < 8 + 1024 + 40 {
        bail!("index 文件过短");
    }
    if &data[0..4] != b"\xfftOc" {
        bail!("仅支持 index v2（缺少 \\xfftOc 魔数）");
    }
    let version = be32(data, 4);
    if version != 2 {
        bail!("不支持的 index 版本 {version}");
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = be32(data, 8 + 4 * i);
    }
    let fanout_ok = fanout.windows(2).all(|w| w[0] <= w[1]);
    let count = fanout[255] as usize;
    let oid_base = 8 + 1024;
    let crc_base = oid_base + count * 20;
    let off_base = crc_base + count * 4;
    let large_base = off_base + count * 4;
    let needed = large_base + 40;
    if data.len() < needed {
        bail!("index 截断：需要至少 {needed} 字节，实际 {}", data.len());
    }

    let mut oids = Vec::with_capacity(count);
    for i in 0..count {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_base + 20 * i..oid_base + 20 * i + 20]);
        oids.push(oid);
    }
    let mut crc32s = Vec::with_capacity(count);
    for i in 0..count {
        crc32s.push(be32(data, crc_base + 4 * i));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let raw = be32(data, off_base + 4 * i);
        let offset = if raw & 0x8000_0000 != 0 {
            let large_idx = (raw & 0x7fff_ffff) as usize;
            let at = large_base + 8 * large_idx;
            if at + 8 > data.len() - 40 {
                bail!("index 大偏移表越界");
            }
            be64(data, at)
        } else {
            u64::from(raw)
        };
        entries.push(IndexEntry { oid: oids[i], crc32: crc32s[i], offset });
    }

    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[data.len() - 40..data.len() - 20]);
    let mut index_checksum = [0u8; 20];
    index_checksum.copy_from_slice(&data[data.len() - 20..]);
    let digest = Sha1::digest(&data[..data.len() - 20]);
    let checksum_ok = digest.as_slice() == index_checksum;

    Ok(ParsedIndex {
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        fanout_ok,
        checksum_ok,
    })
}

#[derive(Debug)]
pub struct ParsedLoose {
    pub obj_type: u8,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: [u8; 20],
    pub header_ok: bool,
}

/// 解析 loose object：zlib("type size\0" + content)。
pub fn parse_loose(data: &[u8]) -> Result<ParsedLoose> {
    let outcome = inflate_zlib(data, 0, None)?;
    if !outcome.complete {
        bail!("loose object zlib 流截断");
    }
    let buf = outcome.output;
    let nul = buf.iter().position(|&b| b == 0).context("loose object 缺少 NUL header")?;
    let header = std::str::from_utf8(&buf[..nul]).context("loose object header 非 UTF-8")?;
    let (tname, size_s) = header.split_once(' ').context("loose object header 缺少空格")?;
    let obj_type = type_from_name(tname).with_context(|| format!("loose object 未知类型 {tname}"))?;
    let declared_size: u64 = size_s.parse().context("loose object size 非数字")?;
    let content = buf[nul + 1..].to_vec();
    let header_ok = declared_size == content.len() as u64;
    let oid = git_oid(obj_type, &content);
    Ok(ParsedLoose {
        obj_type,
        declared_size,
        content,
        oid,
        header_ok,
    })
}

/// 内容摘要：sha1 十六进制与长度（与原始偏移分开留存）。
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn oid_hex(oid: &[u8]) -> String {
    hex::encode(oid)
}
