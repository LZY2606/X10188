//! Git pack 与 pack index (v2) 的纯 Rust 解析，不调用系统 git。

use sha1::Digest;
use std::io::Read;

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

#[derive(Debug, Clone)]
pub struct PackEntryInfo {
    pub offset: u64,
    pub header_len: u64,
    pub obj_type: u8,
    pub size: u64,
    pub data_off: u64,
    pub data_len: u64,
    pub base_distance: Option<u64>,
    pub base_oid: Option<String>,
    pub crc32: u32,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub trailer_ok: bool,
    pub entries: Vec<PackEntryInfo>,
    pub error: Option<String>,
}

/// pack 尾部 20 字节校验和（对前面全部字节的 sha1）。
pub fn pack_trailer(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 20 {
        return None;
    }
    Some(hex::encode(&bytes[bytes.len() - 20..]))
}

fn parse_obj_header(b: &[u8], mut i: usize, limit: usize) -> Result<(u8, u64, usize), String> {
    let start = i;
    if i >= limit {
        return Err("对象头越界".into());
    }
    let mut c = b[i];
    i += 1;
    let typ = (c >> 4) & 0x7;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        if i >= limit {
            return Err("对象头截断".into());
        }
        c = b[i];
        i += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("对象头大小字段过长".into());
        }
    }
    Ok((typ, size, i - start))
}

fn decode_ofs_distance(b: &[u8], mut i: usize, limit: usize) -> Result<(u64, usize), String> {
    let start = i;
    if i >= limit {
        return Err("ofs-delta 距离字段越界".into());
    }
    let mut c = b[i];
    i += 1;
    let mut n = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if i >= limit {
            return Err("ofs-delta 距离字段截断".into());
        }
        c = b[i];
        i += 1;
        n = ((n + 1) << 7) | (c & 0x7f) as u64;
    }
    Ok((n, i - start))
}

/// 在 `off` 处探测 zlib 流边界，返回 (解压内容, 消费的压缩字节数)。
pub fn inflate_at(b: &[u8], off: usize) -> Result<(Vec<u8>, usize), String> {
    if off >= b.len() {
        return Err("zlib 起点越界".into());
    }
    let mut dec = flate2::read::ZlibDecoder::new(&b[off..]);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| format!("zlib 解压失败: {e}"))?;
    Ok((out, dec.total_in() as usize))
}

fn parse_one(b: &[u8], start: usize, limit: usize) -> Result<(PackEntryInfo, usize), String> {
    let (typ, size, hlen) = parse_obj_header(b, start, limit)?;
    let mut off = start + hlen;
    let mut base_distance = None;
    let mut base_oid = None;
    match typ {
        OBJ_OFS_DELTA => {
            let (dist, used) = decode_ofs_distance(b, off, limit)?;
            base_distance = Some(dist);
            off += used;
        }
        OBJ_REF_DELTA => {
            if off + 20 > limit {
                return Err("ref-delta base oid 截断".into());
            }
            base_oid = Some(hex::encode(&b[off..off + 20]));
            off += 20;
        }
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => {}
        other => return Err(format!("未知对象类型 {other}")),
    }
    let data_off = off;
    let (_inflated, consumed) = inflate_at(b, data_off)?;
    let data_len = consumed;
    let end = data_off + data_len;
    if end > limit {
        return Err("zlib 流越过 pack 尾部".into());
    }
    let crc32 = crc32fast::hash(&b[start..end]);
    Ok((
        PackEntryInfo {
            offset: start as u64,
            header_len: (data_off - start) as u64,
            obj_type: typ,
            size,
            data_off: data_off as u64,
            data_len: data_len as u64,
            base_distance,
            base_oid,
            crc32,
        },
        end,
    ))
}

pub fn parse_pack(b: &[u8]) -> Result<ParsedPack, String> {
    if b.len() < 12 + 20 {
        return Err("文件太小，不是合法 pack".into());
    }
    if &b[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(b[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(b[8..12].try_into().unwrap());
    let body_end = b.len() - 20;
    let mut h = sha1::Sha1::new();
    h.update(&b[..body_end]);
    let expect = h.finalize();
    let trailer_ok = &b[body_end..] == expect.as_slice();
    let mut entries = Vec::new();
    let mut off = 12usize;
    let mut error = None;
    for _ in 0..count {
        match parse_one(b, off, body_end) {
            Ok((info, next)) => {
                entries.push(info);
                off = next;
            }
            Err(e) => {
                error = Some(format!("第 {} 个对象（偏移 {}）解析失败: {}", entries.len(), off, e));
                break;
            }
        }
    }
    Ok(ParsedPack { version, count, trailer_ok, entries, error })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedIdx {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
}

pub fn parse_idx(b: &[u8]) -> Result<ParsedIdx, String> {
    if b.len() < 8 + 1024 + 40 {
        return Err("文件太小，不是合法 idx".into());
    }
    if b[0..4] != [0xff, 0x74, 0x4f, 0x63] {
        return Err("缺少 idx 魔数".into());
    }
    let version = u32::from_be_bytes(b[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("仅支持 idx v2，实际版本 {version}"));
    }
    let mut fanout = Vec::with_capacity(256);
    for k in 0..256 {
        let p = 8 + k * 4;
        fanout.push(u32::from_be_bytes(b[p..p + 4].try_into().unwrap()));
    }
    let n = fanout[255] as usize;
    let oid_tab = 8 + 1024;
    let crc_tab = oid_tab + 20 * n;
    let off_tab = crc_tab + 4 * n;
    let big_tab = off_tab + 4 * n;
    if b.len() < big_tab + 40 {
        return Err("idx 表区截断".into());
    }
    let mut entries = Vec::with_capacity(n);
    for k in 0..n {
        let oid = hex::encode(&b[oid_tab + 20 * k..oid_tab + 20 * k + 20]);
        let crc32 = u32::from_be_bytes(b[crc_tab + 4 * k..crc_tab + 4 * k + 4].try_into().unwrap());
        let raw = u32::from_be_bytes(b[off_tab + 4 * k..off_tab + 4 * k + 4].try_into().unwrap());
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let p = big_tab + idx * 8;
            if p + 8 > b.len() - 40 {
                return Err("idx 大偏移表越界".into());
            }
            u64::from_be_bytes(b[p..p + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&b[b.len() - 40..b.len() - 20]);
    Ok(ParsedIdx { fanout, entries, pack_sha1 })
}
