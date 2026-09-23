//! Git pack 解析：header、对象类型、ofs-delta / ref-delta、zlib 边界、trailer 校验。
use crate::gitutil;

pub const T_COMMIT: u8 = 1;
pub const T_TREE: u8 = 2;
pub const T_BLOB: u8 = 3;
pub const T_TAG: u8 = 4;
pub const T_OFS_DELTA: u8 = 6;
pub const T_REF_DELTA: u8 = 7;

pub fn kind_name(code: u8) -> &'static str {
    match code {
        T_COMMIT => "commit",
        T_TREE => "tree",
        T_BLOB => "blob",
        T_TAG => "tag",
        T_OFS_DELTA => "ofs_delta",
        T_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

#[derive(Clone, Debug)]
pub struct EntryParse {
    pub offset: u64,
    pub kind_code: u8,
    pub kind: String,
    pub declared_size: u64,
    /// 对象头（含 delta base 信息）长度：entry 起点到 zlib 流起点
    pub header_len: u64,
    pub data_offset: u64,
    pub compressed_len: u64,
    pub base_offset: Option<u64>,
    pub base_distance: Option<u64>,
    pub base_oid: Option<String>,
    /// 解压后的内容（普通对象为内容，delta 对象为 delta 指令流）
    pub data: Vec<u8>,
    pub error: Option<String>,
    /// 原始字节 [offset, data_offset+compressed_len)，用于 CRC32 复核
    pub raw: Vec<u8>,
}

#[derive(Debug)]
pub struct PackParse {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<EntryParse>,
    pub trailer: String,
    pub trailer_ok: bool,
    pub error: Option<String>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_pack(data: &[u8]) -> PackParse {
    let mut p = PackParse {
        version: 0,
        declared_count: 0,
        entries: Vec::new(),
        trailer: String::new(),
        trailer_ok: false,
        error: None,
    };
    if data.len() < 12 + 20 {
        p.error = Some("pack too small".into());
        return p;
    }
    if &data[0..4] != b"PACK" {
        p.error = Some("bad pack magic".into());
        return p;
    }
    p.version = be32(&data[4..8]);
    p.declared_count = be32(&data[8..12]);
    let body_end = data.len() - 20;
    p.trailer = gitutil::to_hex(&data[body_end..]);
    p.trailer_ok = gitutil::sha1_hex(&data[..body_end]) == p.trailer;

    let mut pos = 12usize;
    for i in 0..p.declared_count {
        if pos >= body_end {
            p.error = Some(format!(
                "truncated pack: parsed {} of {} entries",
                i, p.declared_count
            ));
            break;
        }
        let entry_offset = pos as u64;
        // --- 对象头：continuation varint，type 在第一个字节的 4..6 位 ---
        let b0 = data[pos];
        pos += 1;
        let kind_code = (b0 >> 4) & 7;
        let mut size = (b0 & 0x0f) as u64;
        let mut shift = 4u32;
        let mut b = b0;
        while b & 0x80 != 0 && pos < body_end {
            b = data[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        let mut base_offset = None;
        let mut base_distance = None;
        let mut base_oid = None;
        let mut error: Option<String> = None;
        if kind_code == T_OFS_DELTA {
            // ofs-delta：距离编码，每遇续位先 +1 再左移 7
            let mut c = data[pos];
            pos += 1;
            let mut dist = (c & 0x7f) as u64;
            while c & 0x80 != 0 && pos < body_end {
                c = data[pos];
                pos += 1;
                dist = ((dist + 1) << 7) | (c & 0x7f) as u64;
            }
            base_distance = Some(dist);
            if dist > entry_offset {
                error = Some(format!(
                    "ofs distance {dist} out of bounds at entry offset {entry_offset}"
                ));
            } else {
                base_offset = Some(entry_offset - dist);
            }
        } else if kind_code == T_REF_DELTA {
            if pos + 20 > body_end {
                error = Some("ref-delta base oid truncated".into());
            } else {
                base_oid = Some(gitutil::to_hex(&data[pos..pos + 20]));
                pos += 20;
            }
        }
        let header_len = pos as u64 - entry_offset;
        let data_offset = pos as u64;
        // --- zlib 流：用 declared+1 作为上限，解压到一半即可发现大小欺骗 ---
        let limit = size.saturating_add(1).min(gitutil::MAX_INFLATE) as usize;
        let mut stop = false;
        let (inflated, consumed, derr) = match gitutil::inflate(&data[pos..body_end], Some(limit)) {
            Ok(inf) => {
                let e = if inf.data.len() as u64 != size {
                    Some(format!(
                        "size_mismatch: declared {size}, inflated {}",
                        inf.data.len()
                    ))
                } else {
                    None
                };
                (inf.data, inf.consumed, e)
            }
            Err(gitutil::InflateError::OutputExceeded { .. }) => {
                // 大小欺骗：输出超过声明。继续扫描边界以便后续 entry 可解析。
                let c = gitutil::inflate_consumed_only(&data[pos..body_end]).unwrap_or(0);
                if c == 0 {
                    stop = true;
                }
                (
                    Vec::new(),
                    c,
                    Some(format!("size_mismatch: declared {size}, inflated exceeds declared")),
                )
            }
            Err(e) => {
                stop = true;
                (Vec::new(), 0, Some(format!("inflate error: {e}")))
            }
        };
        if error.is_none() {
            error = derr;
        }
        let compressed_len = consumed as u64;
        let raw = data[entry_offset as usize..pos + consumed].to_vec();
        pos += consumed;
        p.entries.push(EntryParse {
            offset: entry_offset,
            kind_code,
            kind: gitutil::kind_name(kind_code).to_string(),
            declared_size: size,
            header_len,
            data_offset,
            compressed_len,
            base_offset,
            base_distance,
            base_oid,
            data: inflated,
            error: error.clone(),
            raw,
        });
        if stop {
            p.error = Some(format!(
                "stopped at entry {i}: cannot locate next entry boundary"
            ));
            break;
        }
    }
    p
}
