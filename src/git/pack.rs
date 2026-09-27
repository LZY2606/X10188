//! pack 文件解析：header、对象头、ofs/ref-delta 元信息、zlib 边界。

use crc32fast::Hasher as Crc;

use super::zlib::inflate_zlib;
use super::{oid_hex, read_ofs_distance, read_pack_entry_header, Error, ObjType, Result};

/// 单个 pack entry 的结构信息（解压数据已与结构分离存放）。
#[derive(Clone, Debug)]
pub struct PackEntry {
    /// 对象在 pack 内的序号（从 0 开始）。
    pub index: usize,
    pub ty: ObjType,
    /// entry 起始偏移（含对象头）。
    pub offset: u64,
    /// 对象头结束 / zlib 流开始偏移（ofs-delta 的负偏移正是指向该 offset）。
    pub header_end: u64,
    /// 声明的解压后大小。
    pub declared_size: u64,
    /// ofs-delta: 基对象的绝对偏移（已解析负距离）。
    pub base_offset: Option<u64>,
    /// ref-delta: 基对象 20 字节 oid。
    pub base_oid: Option<[u8; 20]>,
    /// zlib 流相对整个 pack 的字节范围 [z_start, z_end)。
    pub z_start: u64,
    pub z_end: Option<u64>,
    /// deflate 体（不含 2 字节 zlib 头）长度。
    pub deflate_len: Option<usize>,
    /// 实际解压字节数（成功时）。
    pub inflated_size: Option<usize>,
    /// 该 entry 解析是否成功；失败时错误信息存在 error 中。
    pub ok: bool,
    pub error: Option<String>,
    /// CRC32 覆盖整个 packed 对象 [offset, entry_end)。
    pub crc32: Option<u32>,
    /// 整个 packed 对象的结束偏移（成功解析时等于 z_end）。
    pub entry_end: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct PackInfo {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<PackEntry>,
    /// 无法继续解析位置之后的致命错误（此后无更多 entry）。
    pub fatal_error: Option<String>,
    /// pack 尾部 20 字节 SHA-1（若存在）。
    pub trailer: Option<[u8; 20]>,
    pub trailer_matches: Option<bool>,
}

const INFLATE_HARD_LIMIT: usize = 512 * 1024 * 1024;

pub fn parse_pack(data: &[u8]) -> Result<PackInfo> {
    if data.len() < 12 {
        return Err(Error::Pack("文件不足 12 字节，缺少 pack header".into()));
    }
    if &data[0..4] != b"PACK" {
        return Err(Error::Pack("魔数不是 'PACK'".into()));
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(Error::Pack(format!("不支持的 pack 版本 {}", version)));
    }
    let num_objects = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut fatal_error = None;

    for index in 0..num_objects as usize {
        if pos >= data.len() {
            fatal_error = Some(format!(
                "entry #{} 起始偏移 {} 超出文件长度 {}，pack 被截断",
                index,
                pos,
                data.len()
            ));
            break;
        }
        let offset = pos as u64;
        let entry = match parse_entry(data, &mut pos, index, offset) {
            Ok(e) => e,
            Err(Error::Zlib(_)) | Err(Error::SizeLie(_)) => {
                // zlib 边界在损坏点之后不可信，无法继续扫描后续对象。
                fatal_error = Some(format!("entry #{} @{}: {}", index, offset,
                    err_str(&entries, index, offset)));
                // 仍登记该坏对象，便于 UI 显示证据。
                entries.push(PackEntry {
                    index, ty: ObjType::Blob, offset,
                    header_end: pos as u64, declared_size: 0,
                    base_offset: None, base_oid: None,
                    z_start: pos as u64, z_end: None, deflate_len: None,
                    inflated_size: None, ok: false,
                    error: Some(fatal_error.as_ref().unwrap().clone()),
                    crc32: None, entry_end: None,
                });
                break;
            }
            Err(e) => {
                fatal_error = Some(format!("entry #{} @{}: {}", index, offset, e));
                break;
            }
        };
        entries.push(entry);
    }

    let (trailer, trailer_matches) = if data.len() >= pos + 20 && fatal_error.is_none() {
        let mut t = [0u8; 20];
        t.copy_from_slice(&data[pos..pos + 20]);
        let actual = super::oid::sha1_bytes(&data[..pos]);
        (Some(t), Some(t == actual))
    } else {
        (None, None)
    };

    Ok(PackInfo {
        version,
        num_objects,
        entries,
        fatal_error,
        trailer,
        trailer_matches,
    })
}

#[allow(clippy::ptr_arg)]
fn err_str(_e: &Vec<PackEntry>, index: usize, offset: u64) -> String {
    format!("entry #{} @{} 的 zlib 流损坏，后续偏移不可恢复", index, offset)
}

fn parse_entry(
    data: &[u8],
    pos: &mut usize,
    index: usize,
    offset: u64,
) -> Result<PackEntry> {
    let (ty, declared) = read_pack_entry_header(data, pos)?;
    let mut base_offset = None;
    let mut base_oid = None;
    match ty {
        ObjType::OfsDelta => {
            let dist = read_ofs_distance(data, pos)?;
            if dist > *pos as u64 {
                return Err(Error::Pack(format!(
                    "ofs-delta 负距离 {} 越过 pack 起点（当前 {}）",
                    dist, *pos
                )));
            }
            base_offset = Some(*pos as u64 - dist);
        }
        ObjType::RefDelta => {
            if *pos + 20 > data.len() {
                return Err(Error::Pack("ref-delta 基 oid 被截断".into()));
            }
            let mut o = [0u8; 20];
            o.copy_from_slice(&data[*pos..*pos + 20]);
            *pos += 20;
            base_oid = Some(o);
        }
        _ => {}
    }
    let header_end = *pos as u64;
    let z_start = header_end;

    let infl = inflate_zlib(&data[*pos..], INFLATE_HARD_LIMIT, Some(declared))?;
    let z_end = z_start + infl.consumed as u64;
    *pos += infl.consumed;
    let entry_end = *pos as u64;

    let mut crc = Crc::new();
    crc.update(&data[offset as usize..entry_end as usize]);

    Ok(PackEntry {
        index,
        ty,
        offset,
        header_end,
        declared_size: declared,
        base_offset,
        base_oid,
        z_start,
        z_end: Some(z_end),
        deflate_len: Some(inflate.deflate_len),
        inflated_size: Some(infl.data.len()),
        ok: true,
        error: None,
        crc32: Some(crc.finalize()),
        entry_end: Some(entry_end),
    })
}

/// 解压指定 entry 的原始数据（loose / delta 指令或完整对象）。
pub fn inflate_entry_at(data: &[u8], entry: &PackEntry) -> Result<Vec<u8>> {
    let start = entry.z_start as usize;
    let infl = inflate_zlib(&data[start..], INFLATE_HARD_LIMIT, Some(entry.declared_size))?;
    Ok(infl.data)
}

pub fn describe_entry(e: &PackEntry) -> String {
    let mut s = format!("#{} {} @{}", e.index, e.ty.code(), e.offset);
    if let Some(bo) = e.base_offset {
        s.push_str(&format!(" -> ofs {}", bo));
    }
    if let Some(oid) = e.base_oid {
        s.push_str(&format!(" -> ref {}", &oid_hex(&oid)[..12]));
    }
    s
}
