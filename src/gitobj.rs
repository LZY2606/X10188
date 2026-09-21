// 纯 Rust 实现的 Git 对象/pack/index 解析,不调用系统 git。
use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn full_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
}

/// 解压 zlib 数据,返回(解压内容, 压缩流消耗的输入字节数)。
/// 消耗字节数即 zlib 边界,用于在 pack 中定位下一个对象。
pub fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        let status = dec
            .decompress(
                &data[in_before as usize..],
                &mut buf,
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = (dec.total_out() - out_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        if status == Status::StreamEnd {
            return Ok((out, dec.total_in() as usize));
        }
        if dec.total_in() as usize >= data.len()
            && dec.total_in() == in_before
            && produced == 0
        {
            return Err("zlib 流截断: 输入耗尽但未到达流结尾".to_string());
        }
    }
}

/// Git delta 尺寸使用的 7 位小端 varint。
pub fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("varint 越界".to_string());
        }
        let b = data[*pos];
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("varint 过长".to_string());
        }
    }
    Ok(value)
}

#[derive(Clone, Debug)]
pub struct PackObject {
    pub offset: u64,
    pub otype: ObjType,
    pub hdr_size: u64,
    /// ofs-delta 基对象的绝对偏移(可能为负,表示距离越界)。
    pub base_ofs: Option<i64>,
    pub base_oid: Option<String>,
    pub comp_start: u64,
    pub comp_len: u64,
}

#[derive(Debug)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub objects: Vec<PackObject>,
    pub trailer_ok: bool,
    pub trailer_aligned: bool,
}

fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// 解析 pack:头部、对象类型/size、ofs/ref delta 元数据与 zlib 边界。
pub fn parse_pack(data: &[u8]) -> Result<PackInfo, String> {
    if data.len() < 32 {
        return Err("文件过小,不是合法 pack".to_string());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".to_string());
    }
    let version = be_u32(data, 4);
    let count = be_u32(data, 8);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let mut pos = 12usize;
    let mut objects = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let start = pos;
        if pos >= data.len() {
            return Err(format!("pack 在偏移 {start} 处截断(对象头)"), );
        }
        let mut c = data[pos];
        pos += 1;
        let type_code = (c >> 4) & 0x7;
        let otype = ObjType::from_code(type_code)
            .ok_or_else(|| format!("偏移 {start}: 未知对象类型 {type_code}"))?;
        let mut size = (c & 0x0f) as u64;
        let mut shift = 4u32;
        while c & 0x80 != 0 {
            if pos >= data.len() {
                return Err(format!("偏移 {start}: size varint 截断"));
            }
            c = data[pos];
            pos += 1;
            size |= ((c & 0x7f) as u64) << shift;
            shift += 7;
        }
        let mut base_ofs = None;
        let mut base_oid = None;
        match otype {
            ObjType::OfsDelta => {
                if pos >= data.len() {
                    return Err(format!("偏移 {start}: ofs-delta 距离截断"));
                }
                let mut c = data[pos];
                pos += 1;
                let mut distance = (c & 0x7f) as u64;
                while c & 0x80 != 0 {
                    if pos >= data.len() {
                        return Err(format!("偏移 {start}: ofs-delta 距离截断"));
                    }
                    c = data[pos];
                    pos += 1;
                    distance = ((distance + 1) << 7) | (c & 0x7f) as u64;
                }
                base_ofs = Some(start as i64 - distance as i64);
            }
            ObjType::RefDelta => {
                if pos + 20 > data.len() {
                    return Err(format!("偏移 {start}: ref-delta base oid 截断"));
                }
                base_oid = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {}
        }
        let comp_start = pos;
        let (_plain, consumed) =
            inflate(&data[comp_start..]).map_err(|e| format!("偏移 {start}: {e}"))?;
        let comp_len = consumed as u64;
        pos = comp_start + consumed;
        objects.push(PackObject {
            offset: start as u64,
            otype,
            hdr_size: size,
            base_ofs,
            base_oid,
            comp_start: comp_start as u64,
            comp_len,
        });
    }
    let trailer_aligned = pos + 20 == data.len();
    let trailer_ok =
        trailer_aligned && Sha1::digest(&data[..pos]).as_slice() == &data[pos..pos + 20];
    Ok(PackInfo {
        version,
        count,
        objects,
        trailer_ok,
        trailer_aligned,
    })
}

pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

pub struct IdxInfo {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub fanout_ok: bool,
}

/// 解析 idx v2:魔数、fanout[256]、oid/crc/offset 表与 large-offset 表。
pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 8 + 256 * 4 {
        return Err("idx 文件过小".to_string());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("仅支持 idx v2(缺少 \\xfftOc 魔数,可能是 v1)".to_string());
    }
    let version = be_u32(data, 4);
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version}"));
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        fanout.push(be_u32(data, 8 + i * 4));
    }
    let n = fanout[255] as usize;
    let mut fanout_ok = fanout[0] as usize <= n;
    for w in fanout.windows(2) {
        if w[0] > w[1] {
            fanout_ok = false;
        }
    }
    let mut p = 8 + 256 * 4;
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        if p + 20 > data.len() {
            return Err("idx oid 表截断".to_string());
        }
        oids.push(hex::encode(&data[p..p + 20]));
        p += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        if p + 4 > data.len() {
            return Err("idx crc 表截断".to_string());
        }
        crcs.push(be_u32(data, p));
        p += 4;
    }
    let mut offsets32 = Vec::with_capacity(n);
    for _ in 0..n {
        if p + 4 > data.len() {
            return Err("idx offset 表截断".to_string());
        }
        offsets32.push(be_u32(data, p));
        p += 4;
    }
    let large_count = offsets32.iter().filter(|&&o| o & 0x8000_0000 != 0).count();
    let mut large = Vec::with_capacity(large_count);
    for _ in 0..large_count {
        if p + 8 > data.len() {
            return Err("idx large-offset 表截断".to_string());
        }
        let hi = be_u32(data, p) as u64;
        let lo = be_u32(data, p + 4) as u64;
        large.push((hi << 32) | lo);
        p += 8;
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let raw = offsets32[i];
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            if idx >= large.len() {
                return Err("idx large-offset 索引越界".to_string());
            }
            large[idx]
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset,
        });
    }
    Ok(IdxInfo {
        fanout,
        entries,
        fanout_ok,
    })
}

/// 解析 loose object:zlib("type size\0" + content)。
/// 返回 (类型, 内容, 压缩流字节数)。
pub fn parse_loose(data: &[u8]) -> Result<(String, Vec<u8>, usize), String> {
    let (plain, consumed) = inflate(data)?;
    let nul = plain
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 对象缺少 NUL 头分隔".to_string())?;
    let header = std::str::from_utf8(&plain[..nul]).map_err(|e| format!("loose 头非 UTF-8: {e}"))?;
    let (otype, size_str) = header
        .split_once(' ')
        .ok_or_else(|| "loose 头格式应为 'type size'".to_string())?;
    let declared: u64 = size_str
        .parse()
        .map_err(|e| format!("loose 尺寸无法解析: {e}"))?;
    let content = plain[nul + 1..].to_vec();
    if content.len() as u64 != declared {
        return Err(format!(
            "loose 大小欺骗: 声明 {declared} 实际 {}",
            content.len()
        ));
    }
    match otype {
        "commit" | "tree" | "blob" | "tag" => {}
        other => return Err(format!("loose 对象类型非法: {other}")),
    }
    Ok((otype.to_string(), content, consumed))
}

pub struct DeltaOutcome {
    pub result: Vec<u8>,
    pub base_size: u64,
    pub result_size: u64,
    /// 指令区在 delta 解压流中的字节范围 [instr_start, instr_end)。
    pub instr_start: usize,
    pub instr_end: usize,
}

/// 应用 Git delta 指令流,带完整边界校验。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let base_size = read_varint(delta, &mut pos)?;
    let result_size = read_varint(delta, &mut pos)?;
    let instr_start = pos;
    if base_size != base.len() as u64 {
        return Err(format!(
            "delta 基大小不符: 声明 {base_size}, 实际 base {} 字节",
            base.len()
        ));
    }
    let mut out = Vec::with_capacity(result_size.min(1 << 28) as usize);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut offset = 0u64;
            for i in 0..4u32 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 offset 截断".to_string());
                    }
                    offset |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            let mut size = 0u64;
            for i in 0..3u32 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令 size 截断".to_string());
                    }
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or("copy 长度整数溢出")? as usize;
            if end > base.len() {
                return Err(format!(
                    "copy 越界: base[{}..{}] 超出 base 长度 {}",
                    offset, end, base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令数据截断".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("delta 指令 0 为保留操作码".to_string());
        }
    }
    let instr_end = pos;
    if out.len() as u64 != result_size {
        return Err(format!(
            "delta 结果大小不符: 声明 {result_size}, 实际 {}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        result: out,
        base_size,
        result_size,
        instr_start,
        instr_end,
    })
}

/// 计算 Git 对象 id:sha1("type len\0" + content)。
pub fn git_oid(otype: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{otype} {}\0", content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

pub fn digest_hex(data: &[u8]) -> String {
    hex::encode(Sha1::digest(data))
}
