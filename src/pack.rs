//! Git pack 解析：header、对象类型、ofs-delta / ref-delta、
//! zlib 边界、条目 CRC 与 pack 尾部 SHA-1 校验。
//!
//! 保留每个对象的原始偏移与字节范围，供布局视图与取证展示。

use sha1::{Digest, Sha1};
use sha2::{Sha256};

use crate::crc::crc32;
use crate::delta::{decode_ofs_distance, decode_pack_object_header};
use crate::oid::{ObjType, Oid};
use crate::zlib::inflate_slice;

/// 单个 pack 条目的解析结果（即使包整体有问题，已解析条目也会保留）。
#[derive(Clone, Debug)]
pub struct PackEntryParsed {
    pub index: usize,
    pub offset: u64,
    /// 对象头（类型+size）在文件中的范围。
    pub header_range: (u64, u64),
    /// delta 基引用头（ofs 距离 / 20 字节 sha）的范围；非 delta 为 None。
    pub base_ref_range: Option<(u64, u64)>,
    /// zlib 压缩数据（含最终边界）在文件中的范围。
    pub zlib_range: (u64, u64),
    /// 整个条目用于 index CRC32 的字节范围。
    pub entry_range: (u64, u64),
    pub obj_type: ObjType,
    pub declared_size: u64,
    /// 解压后的字节数（delta 为 delta 指令数据长度）。
    pub inflated_len: usize,
    /// 解压后的原始负载（delta 指令或 canonical 对象内容）。
    pub payload: Vec<u8>,
    pub ofs_base_offset: Option<u64>,
    pub ref_base_oid: Option<Oid>,
    pub entry_crc32: u32,
    /// 该条目自身解析是否成功。
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PackParsed {
    pub file_name: String,
    pub file_size: u64,
    pub content_sha256: String,
    pub version: u32,
    pub count: u32,
    /// 对 pack 内容（去掉最后 20 字节 trailer）重新计算的 SHA-1。
    pub computed_pack_sha: Oid,
    /// 文件尾部记录的 SHA-1。
    pub trailer_sha: Oid,
    pub trailer_ok: bool,
    pub entries: Vec<PackEntryParsed>,
    /// 致命/尾部解析错误（坏 magic、截断等）；不影响已隔离出的条目。
    pub error: Option<String>,
}

pub const PACK_MAGIC: &[u8; 4] = b"PACK";

/// 解压硬上限（防压缩炸弹）：单条目 1 GiB。
const INFLATE_HARD_LIMIT: usize = 1 << 30;

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    Digest::update(&mut h, data);
    hex::encode(h.finalize())
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解析整个 pack 文件字节。
pub fn parse_pack(file_name: &str, bytes: &[u8]) -> PackParsed {
    let mut pp = PackParsed {
        file_name: file_name.to_string(),
        file_size: bytes.len() as u64,
        content_sha256: sha256_hex(bytes),
        version: 0,
        count: 0,
        computed_pack_sha: Oid::ZERO,
        trailer_sha: Oid::ZERO,
        trailer_ok: false,
        entries: Vec::new(),
        error: None,
    };

    macro_rules! fail {
        ($msg:expr) => {{
            pp.error = Some($msg.to_string());
            return pp;
        }};
    }

    if bytes.len() < 32 {
        fail!("pack 文件短于 32 字节（无 header/trailer）");
    }
    if &bytes[0..4] != PACK_MAGIC {
        fail!("pack magic 不是 'PACK'");
    }
    pp.version = read_u32(&bytes[4..8]);
    if pp.version != 2 {
        fail!(format!("不支持的 pack 版本 {}", pp.version));
    }
    pp.count = read_u32(&bytes[8..12]);

    // 尾部 SHA-1 校验（覆盖前 file_size-20 字节）。
    let content_end = bytes.len() - 20;
    let mut h = Sha1::new();
    Digest::update(&mut h, &bytes[..content_end]);
    let computed: [u8; 20] = h.finalize().into();
    pp.computed_pack_sha = Oid(computed);
    pp.trailer_sha = Oid(bytes[content_end..content_end + 20].try_into().unwrap());
    pp.trailer_ok = computed == pp.trailer_sha.0;

    let mut pos = 12usize;
    let mut idx = 0usize;
    while idx < pp.count as usize {
        let entry_offset = pos as u64;
        if pos >= content_end {
            pp.error = Some(format!(
                "对象条目 {idx} 起始偏移 {pos} 越过 pack 内容边界 {content_end}（截断）"
            ));
            break;
        }
        let hdr = match decode_pack_object_header(bytes, pos) {
            Ok(h) => h,
            Err(e) => {
                pp.error = Some(format!("条目 {idx} 偏移 {pos}: {e}"));
                break;
            }
        };
        let header_end = pos + hdr.header_len;
        let obj_type = match ObjType::from_pack_code(hdr.type_code) {
            Some(t) => t,
            None => {
                pp.error = Some(format!(
                    "条目 {idx} 偏移 {pos}: 非法 pack 类型号 {}",
                    hdr.type_code
                ));
                break;
            }
        };

        let mut base_ref_range: Option<(u64, u64)> = None;
        let mut ofs_base_offset: Option<u64> = None;
        let mut ref_base_oid: Option<Oid> = None;

        match obj_type {
            ObjType::OfsDelta => {
                let (dist, n) = match decode_ofs_distance(bytes, header_end) {
                    Ok(v) => v,
                    Err(e) => {
                        pp.error = Some(format!("条目 {idx} 偏移 {pos}: {e}"));
                        break;
                    }
                };
                let ref_end = header_end + n;
                base_ref_range = Some((header_end as u64, ref_end as u64));
                if dist > entry_offset {
                    // ofs 距离越过本条目（指向 pack 起点之前）——坏对象。
                    pp.entries.push(bad_entry(
                        idx,
                        entry_offset,
                        (pos as u64, header_end as u64),
                        base_ref_range,
                        obj_type,
                        hdr.size,
                        format!("ofs-delta 距离 {dist} 越过本条目偏移 {entry_offset}（越界）"),
                    ));
                    idx += 1;
                    // 无法定位 zlib 边界，停止继续顺序扫描。
                    pp.error = Some(format!(
                        "条目 {idx} ofs-delta 越界，无法继续顺序定位后续对象"
                    ));
                    break;
                }
                ofs_base_offset = Some(entry_offset - dist);
                pos = ref_end;
            }
            ObjType::RefDelta => {
                if header_end + 20 > content_end {
                    pp.error = Some(format!(
                        "条目 {idx} ref-delta 的 20 字节 base oid 越界"
                    ));
                    break;
                }
                let oid = Oid(bytes[header_end..header_end + 20].try_into().unwrap());
                base_ref_range = Some((header_end as u64, (header_end + 20) as u64));
                ref_base_oid = Some(oid);
                pos = header_end + 20;
            }
            _ => pos = header_end,
        }

        let zlib_start = pos;
        let inflated = inflate_slice(bytes, zlib_start, INFLATE_HARD_LIMIT);
        let entry = match inflated {
            Ok(inf) => {
                let zlib_end = zlib_start + inf.consumed;
                if zlib_end > content_end {
                    pp.error = Some(format!(
                        "条目 {idx} zlib 边界 {zlib_end} 越过 pack 内容边界 {content_end}"
                    ));
                }
                let size_ok = inf.data.len() as u64 == hdr.size;
                let err = if size_ok {
                    None
                } else {
                    Some(format!(
                        "条目 {idx} size 欺骗：头部声明 {}，解压得到 {} 字节",
                        hdr.size,
                        inf.data.len()
                    ))
                };
                let entry_crc = crc32(&bytes[entry_offset as usize..zlib_end]);
                PackEntryParsed {
                    index: idx,
                    offset: entry_offset,
                    header_range: (entry_offset, header_end as u64),
                    base_ref_range,
                    zlib_range: (zlib_start as u64, zlib_end as u64),
                    entry_range: (entry_offset, zlib_end as u64),
                    obj_type,
                    declared_size: hdr.size,
                    inflated_len: inf.data.len(),
                    payload: inf.data,
                    ofs_base_offset,
                    ref_base_oid,
                    entry_crc32: entry_crc,
                    ok: size_ok,
                    error: err,
                }
            }
            Err(e) => {
                // 无法确定 zlib 边界：隔离坏对象，且无法继续顺序扫描。
                pp.entries.push(bad_entry(
                    idx,
                    entry_offset,
                    (entry_offset, header_end as u64),
                    base_ref_range,
                    obj_type,
                    hdr.size,
                    format!("zlib 解压失败: {e}"),
                ));
                idx += 1;
                pp.error =
                    Some(format!("条目 {idx} 偏移 {entry_offset} 无法确定 zlib 边界，扫描中止"));
                break;
            }
        };
        pos = entry.zlib_range.1 as usize;
        pp.entries.push(entry);
        idx += 1;
    }

    if idx != pp.count as usize && pp.error.is_none() {
        pp.error = Some(format!(
            "声明对象数 {}，实际顺序解析出 {idx} 个",
            pp.count
        ));
    }
    if !pp.trailer_ok {
        let msg = format!(
            "pack SHA-1 校验失败：计算值 {}，尾部 {}",
            pp.computed_pack_sha.short(),
            pp.trailer_sha.short()
        );
        pp.error = match pp.error.take() {
            Some(old) => Some(format!("{old}; {msg}")),
            None => Some(msg),
        };
    }
    pp
}

#[allow(clippy::too_many_arguments)]
fn bad_entry(
    index: usize,
    offset: u64,
    header_range: (u64, u64),
    base_ref_range: Option<(u64, u64)>,
    obj_type: ObjType,
    declared_size: u64,
    error: String,
) -> PackEntryParsed {
    PackEntryParsed {
        index,
        offset,
        header_range,
        base_ref_range,
        zlib_range: (offset, offset),
        entry_range: header_range,
        obj_type,
        declared_size,
        inflated_len: 0,
        payload: Vec::new(),
        ofs_base_offset: None,
        ref_base_oid: None,
        entry_crc32: 0,
        ok: false,
        error: Some(error),
    }
}
