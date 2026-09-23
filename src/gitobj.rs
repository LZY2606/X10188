//! 纯 Rust 的 Git 对象解析：pack / idx / loose object / zlib 边界。
//! 不调用系统 git。

use sha1::{Digest, Sha1};

pub fn compute_oid(obj_type: &str, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(obj_type.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    hex::encode(hasher.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        use ObjType::*;
        Some(match code {
            1 => Commit,
            2 => Tree,
            3 => Blob,
            4 => Tag,
            6 => OfsDelta,
            7 => RefDelta,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        use ObjType::*;
        match self {
            Commit => "commit",
            Tree => "tree",
            Blob => "blob",
            Tag => "tag",
            OfsDelta => "ofs_delta",
            RefDelta => "ref_delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

pub struct InflateResult {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub stream_end: bool,
    pub overflow: bool,
}

/// 流式 zlib 解压，返回解压内容与实际消耗的输入字节数（用于定位 pack 条目边界）。
/// 输出超过 max_out 时提前停止并标记 overflow。
pub fn inflate_bounded(input: &[u8], max_out: u64) -> Result<InflateResult, String> {
    use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
    use miniz_oxide::MZStatus;
    let mut de = DecompressorOxide::new();
    let mut out: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let mut buf = [0u8; 65536];
    loop {
        let allowed = (max_out.saturating_add(1)).saturating_sub(out.len() as u64) as usize;
        let cap = allowed.min(buf.len());
        let (status, cin, cout) = decompress(
            &mut de,
            &input[consumed..],
            &mut buf[..cap],
            0,
            inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER,
        );
        consumed += cin;
        out.extend_from_slice(&buf[..cout]);
        match status {
            MZStatus::StreamEnd => {
                return Ok(InflateResult { data: out, consumed, stream_end: true, overflow: false })
            }
            MZStatus::Ok => {
                if out.len() as u64 > max_out {
                    return Ok(InflateResult { data: out, consumed, stream_end: false, overflow: true });
                }
                if cin == 0 && cout == 0 {
                    if consumed >= input.len() {
                        return Err("zlib 流截断：输入耗尽但流未结束".into());
                    }
                    return Err("zlib 解压无进展".into());
                }
            }
            MZStatus::Err(e) => return Err(format!("zlib 错误: {e:?}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackEntryInfo {
    pub index: usize,
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub data_offset: u64,
    pub data_len: u64,
    pub inflated_len: u64,
    pub stream_end: bool,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct PackInfo {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntryInfo>,
    pub trailer_ok: bool,
    pub trailer_expected: String,
    pub trailer_actual: String,
    pub errors: Vec<String>,
}

const HARD_CAP: u64 = 512 << 20;

pub fn parse_pack(data: &[u8]) -> Result<PackInfo, String> {
    if data.len() < 12 + 20 {
        return Err("文件太小，不是有效的 pack".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let declared_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let limit = data.len() - 20;
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for index in 0..declared_count as usize {
        if pos >= limit {
            errors.push(format!("pack 截断：仅解析出 {index}/{declared_count} 个条目"));
            break;
        }
        let offset = pos as u64;
        let mut b = data[pos];
        pos += 1;
        let code = (b >> 4) & 0x07;
        let mut size = (b & 0x0f) as u64;
        let mut shift = 4u32;
        while b & 0x80 != 0 && pos < limit {
            b = data[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        let obj_type = match ObjType::from_code(code) {
            Some(t) => t,
            None => {
                entries.push(PackEntryInfo {
                    index, offset, obj_type: ObjType::Blob, declared_size: size,
                    data_offset: pos as u64, data_len: 0, inflated_len: 0, stream_end: false,
                    base_offset: None, base_oid: None,
                    error: Some(format!("未知对象类型码 {code}")),
                });
                errors.push(format!("条目 {index}: 未知类型码 {code}，后续条目无法定位"));
                break;
            }
        };
        let mut base_offset = None;
        let mut base_oid = None;
        let mut hdr_error = None;
        match obj_type {
            ObjType::OfsDelta => {
                if pos >= limit {
                    hdr_error = Some("ofs-delta 头截断".to_string());
                } else {
                    let mut c = data[pos];
                    pos += 1;
                    let mut dist = (c & 0x7f) as u64;
                    while c & 0x80 != 0 && pos < limit {
                        c = data[pos];
                        pos += 1;
                        dist = ((dist + 1) << 7) | ((c & 0x7f) as u64);
                    }
                    if dist > offset {
                        hdr_error = Some(format!("ofs 距离越界：回退 {dist} 字节超出 pack 起点"));
                    } else {
                        base_offset = Some(offset - dist);
                    }
                }
            }
            ObjType::RefDelta => {
                if pos + 20 > limit {
                    hdr_error = Some("ref-delta 头截断".to_string());
                } else {
                    base_oid = Some(hex::encode(&data[pos..pos + 20]));
                    pos += 20;
                }
            }
            _ => {}
        }
        let data_offset = pos as u64;
        if let Some(e) = hdr_error {
            entries.push(PackEntryInfo {
                index, offset, obj_type, declared_size: size, data_offset, data_len: 0,
                inflated_len: 0, stream_end: false, base_offset, base_oid, error: Some(e),
            });
            errors.push(format!("条目 {index} 头损坏，后续条目无法定位"));
            break;
        }
        let cap = size.min(HARD_CAP);
        match inflate_bounded(&data[pos..limit], cap) {
            Ok(res) => {
                let (data_len, inflated_len, stream_end, mut ent_error) =
                    (res.consumed as u64, res.data.len() as u64, res.stream_end, None);
                if res.overflow {
                    // 声明大小可能被伪造：去掉声明上限重新解压，定位真实流边界
                    match inflate_bounded(&data[pos..limit], HARD_CAP) {
                        Ok(full) => {
                            entries.push(PackEntryInfo {
                                index, offset, obj_type, declared_size: size, data_offset,
                                data_len: full.consumed as u64,
                                inflated_len: full.data.len() as u64,
                                stream_end: full.stream_end,
                                base_offset, base_oid, error: None,
                            });
                            pos += full.consumed;
                            continue;
                        }
                        Err(e) => {
                            ent_error = Some(e);
                        }
                    }
                }
                entries.push(PackEntryInfo {
                    index, offset, obj_type, declared_size: size, data_offset, data_len,
                    inflated_len, stream_end, base_offset, base_oid, error: ent_error,
                });
                pos += res.consumed;
            }
            Err(e) => {
                entries.push(PackEntryInfo {
                    index, offset, obj_type, declared_size: size, data_offset, data_len: 0,
                    inflated_len: 0, stream_end: false, base_offset, base_oid,
                    error: Some(e.clone()),
                });
                errors.push(format!("条目 {index} zlib 解压失败：{e}，后续条目无法定位"));
                break;
            }
        }
    }
    let actual = sha1_hex(&data[..data.len() - 20]);
    let expected = hex::encode(&data[data.len() - 20..]);
    let trailer_ok = actual == expected;
    if !trailer_ok {
        errors.push("pack 尾部 SHA-1 校验和不匹配".into());
    }
    Ok(PackInfo {
        version, declared_count, entries, trailer_ok,
        trailer_expected: expected, trailer_actual: actual, errors,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntryInfo {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxInfo {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntryInfo>,
    pub errors: Vec<String>,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 8 + 256 * 4 {
        return Err("idx 文件太小".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 idx 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("仅支持 idx v2，实际版本 v{version}"));
    }
    let mut fanout = Vec::with_capacity(256);
    let mut p = 8usize;
    for _ in 0..256 {
        fanout.push(u32::from_be_bytes(data[p..p + 4].try_into().unwrap()));
        p += 4;
    }
    let mut errors = Vec::new();
    for w in fanout.windows(2) {
        if w[1] < w[0] {
            errors.push("fanout 表非单调递增".into());
            break;
        }
    }
    let n = fanout[255] as usize;
    let need = p + n * 20 + n * 4 + n * 4;
    if data.len() < need {
        return Err(format!("idx 截断：需要至少 {need} 字节，实际 {}", data.len()));
    }
    let oid_base = p;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let large_base = off_base + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc = u32::from_be_bytes(data[crc_base + i * 4..crc_base + i * 4 + 4].try_into().unwrap());
        let raw = u32::from_be_bytes(data[off_base + i * 4..off_base + i * 4 + 4].try_into().unwrap());
        let offset = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let s = large_base + li * 8;
            if s + 8 > data.len() {
                errors.push(format!("条目 {i} 的大偏移表索引越界"));
                0
            } else {
                u64::from_be_bytes(data[s..s + 8].try_into().unwrap())
            }
        } else {
            raw as u64
        };
        entries.push(IdxEntryInfo { oid, crc32: crc, offset });
    }
    Ok(IdxInfo { fanout, entries, errors })
}

/// 解析 loose object：zlib("type size\0content")
pub fn parse_loose(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let res = inflate_bounded(data, HARD_CAP).map_err(|e| format!("loose 解压失败: {e}"))?;
    if !res.stream_end {
        return Err("loose zlib 流未正常结束".into());
    }
    let buf = res.data;
    let nul = buf.iter().position(|&b| b == 0).ok_or("loose 缺少头部分隔符")?;
    let header = std::str::from_utf8(&buf[..nul]).map_err(|_| "loose 头部非 UTF-8")?;
    let (typ, size_s) = header.split_once(' ').ok_or("loose 头部格式错误")?;
    match typ {
        "commit" | "tree" | "blob" | "tag" => {}
        _ => return Err(format!("未知 loose 类型 {typ}")),
    }
    let size: usize = size_s.parse().map_err(|_| "loose 大小字段非法")?;
    let content = buf[nul + 1..].to_vec();
    if content.len() != size {
        return Err(format!("loose 大小不符：声明 {size} 实际 {}", content.len()));
    }
    Ok((typ.to_string(), content))
}

pub fn detect_kind(data: &[u8]) -> &'static str {
    if data.starts_with(b"PACK") {
        "pack"
    } else if data.starts_with(b"\xfftOc") {
        "idx"
    } else if parse_loose(data).is_ok() {
        "loose"
    } else {
        "unknown"
    }
}
