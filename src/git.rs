//! 底层 Git 格式解析：pack header、对象头、ofs/ref-delta、zlib 边界、idx fanout。
//! 不调用系统 git，全部自行实现。

use flate2::Decompress;
use flate2::FlushDecompress;
use sha1::{Digest, Sha1};
use std::fmt;

pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";
pub const IDX_SIGNATURE: [u8; 4] = [255, 116, 79, 99];
pub const HEADER_LEN: usize = 12;
pub const TRAILER_LEN: usize = 20;
pub const IDX_V2: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjectType {
    pub fn from_u8(v: u8) -> Option<ObjectType> {
        match v {
            1 => Some(ObjectType::Commit),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Blob),
            4 => Some(ObjectType::Tag),
            6 => Some(ObjectType::OfsDelta),
            7 => Some(ObjectType::RefDelta),
            _ => None,
        }
    }
    pub fn base_type(self) -> Option<ObjectType> {
        match self {
            ObjectType::Commit
            | ObjectType::Tree
            | ObjectType::Blob
            | ObjectType::Tag => Some(self),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
            ObjectType::OfsDelta => "ofs-delta",
            ObjectType::RefDelta => "ref-delta",
        }
    }
    pub fn type_name(self) -> Option<&'static str> {
        self.base_type().map(|t| t.name())
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn parse_oid(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// pack/loose 对象头使用的小端 7-bit size 编码。
pub fn read_size_encoding(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut shift: u32 = 0;
    let mut size: u64 = 0;
    let mut pos = start;
    loop {
        if pos >= data.len() {
            return Err("size 编码被截断".into());
        }
        let b = data[pos];
        pos += 1;
        size |= u64::from(b & 0x7f).checked_shl(shift).ok_or("size 溢出")?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size 编码过长".into());
        }
    }
    Ok((size, pos))
}

/// ofs-delta 的负偏移编码。
pub fn read_ofs_distance(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    if start >= data.len() {
        return Err("ofs-delta 偏移被截断".into());
    }
    let mut pos = start;
    let mut b = data[pos];
    pos += 1;
    let mut distance: u64 = u64::from(b & 0x7f);
    while b & 0x80 != 0 {
        if pos >= data.len() {
            return Err("ofs-delta 偏移被截断".into());
        }
        b = data[pos];
        pos += 1;
        distance = distance
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .and_then(|v| v.checked_add(u64::from(b & 0x7f)))
            .ok_or("ofs-delta 偏移溢出")?;
    }
    Ok((distance, pos))
}

#[derive(Debug, Clone)]
pub struct EntryHeader {
    pub kind: ObjectType,
    pub declared_size: u64,
    pub header_end: usize,
    pub ofs_distance: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
}

pub fn read_entry_header(data: &[u8], start: usize) -> Result<EntryHeader, String> {
    if start >= data.len() {
        return Err("对象起始位置越界".into());
    }
    let first = data[start];
    let raw_kind = (first >> 4) & 0x07;
    let kind = ObjectType::from_u8(raw_kind).ok_or_else(|| format!("未知对象类型 {raw_kind}"))?;
    let mut size: u64 = u64::from(first & 0x0f);
    let mut pos = start + 1;
    if first & 0x80 != 0 {
        let (rest, next) = read_size_encoding(data, pos)?;
        size |= rest.checked_shl(4).ok_or("对象大小溢出")?;
        pos = next;
    }
    let mut ofs_distance = None;
    let mut base_oid = None;
    if kind == ObjectType::OfsDelta {
        let (distance, next) = read_ofs_distance(data, pos)?;
        ofs_distance = Some(distance);
        pos = next;
    } else if kind == ObjectType::RefDelta {
        if pos + 20 > data.len() {
            return Err("ref-delta base oid 被截断".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[pos..pos + 20]);
        base_oid = Some(oid);
        pos += 20;
    }
    Ok(EntryHeader {
        kind,
        declared_size: size,
        header_end: pos,
        ofs_distance,
        base_oid,
    })
}

#[derive(Debug, Clone)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    pub compressed_start: usize,
    pub compressed_end: usize,
    /// 声明大小与实际解压大小不一致（大小欺骗）。
    pub size_mismatch: bool,
    /// 解压流在声明上限后仍输出额外字节。
    pub output_overflow: bool,
}

/// 从指定 zlib 流起点解压，通过 Decompress::total_in 精确定位压缩边界。
/// `declared_size` 用于识别大小欺骗；`hard_limit` 是防止内存耗尽的绝对上限。
pub fn inflate_at(
    data: &[u8],
    start: usize,
    declared_size: u64,
    hard_limit: usize,
) -> Result<InflateOutcome, String> {
    if start >= data.len() {
        return Err("zlib 起点越界".into());
    }
    let mut dec = Decompress::new(true);
    let mut input_pos = start;
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let limit = (declared_size as usize).saturating_add(1).min(hard_limit.saturating_add(1));
    let mut output_overflow = false;
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let status = dec
            .decompress(
                &data[input_pos..],
                &mut chunk,
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let consumed = (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        input_pos += consumed;
        out.extend_from_slice(&chunk[..produced]);
        if dec.total_out() as usize > limit && !output_overflow {
            output_overflow = true;
        }
        if out.len() > hard_limit.saturating_add(1) {
            return Err("解压输出超过安全上限，疑似大小欺骗攻击".into());
        }
        if status == flate2::Status::StreamEnd {
            break;
        }
        if status == flate2::Status::Ok && produced == 0 && consumed == 0 {
            return Err("zlib 流无法继续推进".into());
        }
        let _ = before_in;
    }
    let compressed_end = start + dec.total_in() as usize;
    let actual = out.len() as u64;
    Ok(InflateOutcome {
        data: out,
        compressed_start: start,
        compressed_end,
        size_mismatch: actual != declared_size,
        output_overflow,
    })
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub offset: u64,
    pub header_end: u64,
    pub compressed_start: u64,
    pub compressed_end: u64,
    pub kind: ObjectType,
    pub declared_size: u64,
    pub inflated_size: Option<u64>,
    pub inflated: Option<Vec<u8>>,
    pub ofs_distance: Option<u64>,
    pub base_offset: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
    pub crc32: u32,
    pub parse_error: Option<String>,
    pub size_mismatch: bool,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub pack_checksum: [u8; 20],
    pub computed_checksum: [u8; 20],
    pub checksum_ok: bool,
    pub trailer_offset: u64,
    pub parse_errors: Vec<String>,
}

fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc: u32 = 0xffff_ffff;
    for b in bytes {
        crc = table[((crc ^ u32::from(*b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// 顺序解析整个 pack。某个对象解压失败时隔离该对象，
/// 只有在无法确定下一个对象起点时才停止（此时 idx 可用来按偏移重解析）。
pub fn parse_pack(data: &[u8], hard_limit: usize) -> Result<PackInfo, String> {
    if data.len() < HEADER_LEN + TRAILER_LEN {
        return Err("pack 文件过短".into());
    }
    if &data[0..4] != PACK_SIGNATURE {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if version != 2 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let trailer_offset = (data.len() - TRAILER_LEN) as u64;
    let mut entries = Vec::new();
    let mut parse_errors = Vec::new();
    let mut pos = HEADER_LEN;
    let mut idx = 0usize;
    while (pos as u64) < trailer_offset {
        if idx >= count as usize {
            parse_errors.push(format!("偏移 {pos}: 对象数超过 header 声明的 {count}"));
            break;
        }
        let entry_start = pos;
        let header = match read_entry_header(data, pos) {
            Ok(h) => h,
            Err(e) => {
                parse_errors.push(format!("偏移 {pos}: 对象头解析失败: {e}"));
                break;
            }
        };
        let mut entry = PackEntry {
            index: idx,
            offset: pos as u64,
            header_end: header.header_end as u64,
            compressed_start: header.header_end as u64,
            compressed_end: 0,
            kind: header.kind,
            declared_size: header.declared_size,
            inflated_size: None,
            inflated: None,
            ofs_distance: header.ofs_distance,
            base_offset: None,
            base_oid: header.base_oid,
            crc32: 0,
            parse_error: None,
            size_mismatch: false,
        };
        if header.kind == ObjectType::OfsDelta {
            let distance = header.ofs_distance.unwrap();
            if distance > pos as u64 {
                entry.parse_error = Some(format!(
                    "ofs-delta 距离 {distance} 越界（当前偏移 {pos}）"
                ));
            } else {
                entry.base_offset = Some(pos as u64 - distance);
            }
        }
        match inflate_at(data, header.header_end, header.declared_size, hard_limit) {
            Ok(out) => {
                entry.crc32 = crc32(&data[entry_start..out.compressed_end]);
                entry.compressed_end = out.compressed_end as u64;
                entry.inflated_size = Some(out.data.len() as u64);
                entry.size_mismatch = out.size_mismatch || out.output_overflow;
                if entry.size_mismatch {
                    entry.parse_error = Some(format!(
                        "大小欺骗：header 声明 {}，实际解压 {}",
                        header.declared_size,
                        out.data.len()
                    ));
                }
                entry.inflated = Some(out.data);
                pos = out.compressed_end;
            }
            Err(e) => {
                entry.parse_error = Some(e);
                parse_errors.push(format!("偏移 {pos}: 解压失败，顺序扫描终止"));
                entries.push(entry);
                break;
            }
        }
        entries.push(entry);
        idx += 1;
    }
    if entries.len() != count as usize {
        parse_errors.push(format!(
            "实际解析对象 {} 与 header 声明 {} 不符",
            entries.len(),
            count
        ));
    }
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[data.len() - 20..]);
    let mut hasher = Sha1::new();
    hasher.update(&data[..data.len() - 20]);
    let computed: [u8; 20] = hasher.finalize().into();
    Ok(PackInfo {
        version,
        count,
        entries,
        pack_checksum,
        computed_checksum: computed,
        checksum_ok: pack_checksum == computed,
        trailer_offset,
        parse_errors,
    })
}

/// 按 idx 给出的偏移单独解析一个对象，用于顺序扫描中断后恢复或校验 idx 条目。
pub fn parse_entry_at(
    data: &[u8],
    offset: u64,
    index: usize,
    hard_limit: usize,
) -> PackEntry {
    let start = offset as usize;
    let mut entry = PackEntry {
        index,
        offset,
        header_end: 0,
        compressed_start: 0,
        compressed_end: 0,
        kind: ObjectType::Blob,
        declared_size: 0,
        inflated_size: None,
        inflated: None,
        ofs_distance: None,
        base_offset: None,
        base_oid: None,
        crc32: 0,
        parse_error: None,
        size_mismatch: false,
    };
    if start >= data.len() {
        entry.parse_error = Some("对象偏移越界".into());
        return entry;
    }
    let header = match read_entry_header(data, start) {
        Ok(h) => h,
        Err(e) => {
            entry.parse_error = Some(e);
            return entry;
        }
    };
    entry.header_end = header.header_end as u64;
    entry.compressed_start = header.header_end as u64;
    entry.kind = header.kind;
    entry.declared_size = header.declared_size;
    entry.ofs_distance = header.ofs_distance;
    entry.base_oid = header.base_oid;
    if header.kind == ObjectType::OfsDelta {
        if let Some(distance) = header.ofs_distance {
            if distance > offset {
                entry.parse_error =
                    Some(format!("ofs-delta 距离 {distance} 越界（当前偏移 {offset}）"));
            } else {
                entry.base_offset = Some(offset - distance);
            }
        }
    }
    match inflate_at(data, header.header_end, header.declared_size, hard_limit) {
        Ok(out) => {
            entry.crc32 = crc32(&data[start..out.compressed_end]);
            entry.compressed_end = out.compressed_end as u64;
            entry.inflated_size = Some(out.data.len() as u64);
            entry.size_mismatch = out.size_mismatch || out.output_overflow;
            if entry.size_mismatch {
                entry.parse_error = Some(format!(
                    "大小欺骗：header 声明 {}，实际解压 {}",
                    header.declared_size,
                    out.data.len()
                ));
            }
            entry.inflated = Some(out.data);
        }
        Err(e) => entry.parse_error = Some(e),
    }
    entry
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub computed_pack_checksum: [u8; 20],
    pub computed_idx_checksum: [u8; 20],
    pub pack_checksum_ok: bool,
    pub idx_checksum_ok: bool,
    pub fanout_ok: bool,
}

fn read_u32_at(data: &[u8], p: usize) -> Result<u32, String> {
    data.get(p..p + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "idx 读取 u32 越界".into())
}

fn read_u64_at(data: &[u8], p: usize) -> Result<u64, String> {
    data.get(p..p + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or_else(|| "idx 读取 u64 越界".into())
}

pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 8 + 256 * 4 + 40 {
        return Err("idx 文件过短".into());
    }
    if &data[0..4] != IDX_SIGNATURE {
        return Err("仅支持 idx v2（缺少 \\377tOc 魔数）".into());
    }
    let version = read_u32_at(data, 4)?;
    if version != IDX_V2 {
        return Err(format!("仅支持 idx v2，得到 v{version}"));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_u32_at(data, 8 + i * 4)?;
    }
    let count = fanout[255] as usize;
    if count == 0 {
        return Err("idx 中没有对象".into());
    }
    let mut fanout_ok = true;
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            fanout_ok = false;
        }
    }
    let mut prev: Option<[u8; 20]> = None;
    for i in 0..count {
        let p = 8 + 256 * 4 + i * 20;
        if p + 20 > data.len() {
            return Err("idx oid 表越界".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        if let Some(prev_oid) = prev {
            if oid <= prev_oid {
                fanout_ok = false;
            }
        }
        prev = Some(oid);
    }
    let crc_start = 8 + 256 * 4 + count * 20;
    let off_start = crc_start + count * 4;
    let large_start = off_start + count * 4;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let oid_p = 8 + 256 * 4 + i * 20;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_p..oid_p + 20]);
        let crc = read_u32_at(data, crc_start + i * 4)?;
        let raw_offset = read_u32_at(data, off_start + i * 4)?;
        let offset = if raw_offset & 0x8000_0000 != 0 {
            let large_index = (raw_offset & 0x7fff_ffff) as usize;
            let p = large_start + large_index * 8;
            read_u64_at(data, p)?
        } else {
            u64::from(raw_offset)
        };
        entries.push(IdxEntry { oid, crc32: crc, offset });
    }
    let needed = large_start
        + entries.iter().filter(|e| e.offset & (1 << 63) != 0).count() * 8
        + 40;
    if data.len() < needed {
        return Err("idx 大偏移表或尾部校验越界".into());
    }
    let pack_p = data.len() - 40;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[pack_p..pack_p + 20]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&data[pack_p + 20..pack_p + 40]);
    let mut pack_hasher = Sha1::new();
    pack_hasher.update(&data[..pack_p]);
    let computed_pack_checksum: [u8; 20] = pack_hasher.finalize().into();
    let mut idx_hasher = Sha1::new();
    idx_hasher.update(&data[..pack_p + 20]);
    let computed_idx_checksum: [u8; 20] = idx_hasher.finalize().into();
    Ok(IdxInfo {
        fanout,
        entries,
        pack_checksum,
        idx_checksum,
        computed_pack_checksum,
        computed_idx_checksum,
        pack_checksum_ok: pack_checksum == computed_pack_checksum,
        idx_checksum_ok: idx_checksum == computed_idx_checksum,
        fanout_ok,
    })
}

/// 解析 loose object：zlib(<type> SP <size> NUL <content>)。
pub fn parse_loose(data: &[u8], hard_limit: usize) -> Result<(ObjectType, Vec<u8>), String> {
    let out = inflate_at(data, 0, u64::MAX, hard_limit)?;
    let nul = out
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or("loose 对象缺少 NUL 头")?;
    let header = std::str::from_utf8(&out.data[..nul]).map_err(|e| e.to_string())?;
    let (type_str, size_str) = header
        .split_once(' ')
        .ok_or("loose 对象头格式错误")?;
    let kind = match type_str {
        "commit" => ObjectType::Commit,
        "tree" => ObjectType::Tree,
        "blob" => ObjectType::Blob,
        "tag" => ObjectType::Tag,
        other => return Err(format!("loose 未知类型 {other}")),
    };
    let declared: u64 = size_str.parse().map_err(|_| "loose 大小不是数字")?;
    let content = out.data[nul + 1..].to_vec();
    if declared as usize != content.len() {
        return Err(format!(
            "loose 大小欺骗：header 声明 {}，实际 {}",
            declared,
            content.len()
        ));
    }
    Ok((kind, content))
}

/// 计算重新 hash 后的 Git object id。
pub fn git_object_id(kind: ObjectType, content: &[u8]) -> [u8; 20] {
    let type_name = kind.type_name().expect("delta 不能直接计算 oid");
    let mut hasher = Sha1::new();
    hasher.update(type_name.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update(&[0]);
    hasher.update(content);
    hasher.finalize().into()
}

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub opcode_offset: usize,
    pub opcode_len: usize,
    pub kind: &'static str,
    pub copy_offset: Option<u64>,
    pub copy_size: Option<u64>,
    pub insert_len: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    pub base_size: u64,
    pub result_size: u64,
    pub data: Vec<u8>,
    pub instructions: Vec<DeltaInstruction>,
}

fn read_delta_size(data: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut pos = start;
    let mut size: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if pos >= data.len() {
            return Err("delta size varint 被截断".into());
        }
        let b = data[pos];
        pos += 1;
        size |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 56 {
            return Err("delta size 编码过长".into());
        }
    }
    Ok((size, pos))
}

/// 应用 Git delta 指令，逐条记录操作码范围、copy/insert 范围。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let (base_size, p1) = read_delta_size(delta, 0)?;
    let (result_size, p2) = read_delta_size(delta, p1)?;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta base 大小不匹配：声明 {base_size}，实际 {}",
            base.len()
        ));
    }
    if result_size > MAX_EXPANSION as u64 {
        return Err("delta 结果超过最大展开字节".into());
    }
    let mut result = Vec::with_capacity(result_size.min(1 << 20) as usize);
    let mut pos = p2;
    let mut instructions = Vec::new();
    while pos < delta.len() {
        let opcode_offset = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode == 0 {
            return Err("delta opcode 0 保留且非法".into());
        }
        if opcode & 0x80 != 0 {
            let mut copy_offset: u64 = 0;
            let mut copy_size: u64 = 0;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 偏移字节被截断".into());
                    }
                    copy_offset |= u64::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 长度字节被截断".into());
                    }
                    copy_size |= u64::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = copy_offset.checked_add(copy_size).ok_or("copy 范围溢出")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy 越界：offset={copy_offset} size={copy_size} base_len={}",
                    base.len()
                ));
            }
            result.extend_from_slice(
                &base[copy_offset as usize..(copy_offset + copy_size) as usize],
            );
            instructions.push(DeltaInstruction {
                opcode_offset,
                opcode_len: pos - opcode_offset,
                kind: "copy",
                copy_offset: Some(copy_offset),
                copy_size: Some(copy_size),
                insert_len: None,
            });
        } else {
            let insert_len = u64::from(opcode);
            if pos + opcode as usize > delta.len() {
                return Err("insert 数据被截断".into());
            }
            result.extend_from_slice(&delta[pos..pos + opcode as usize]);
            pos += opcode as usize;
            instructions.push(DeltaInstruction {
                opcode_offset,
                opcode_len: (pos - opcode_offset),
                kind: "insert",
                copy_offset: None,
                copy_size: None,
                insert_len: Some(insert_len),
            });
        }
        if result.len() > result_size as usize {
            return Err("delta 输出超过声明结果大小".into());
        }
    }
    if result.len() as u64 != result_size {
        return Err(format!(
            "delta 结果大小欺骗：声明 {result_size}，实际 {}",
            result.len()
        ));
    }
    Ok(DeltaOutcome {
        base_size,
        result_size,
        data: result,
        instructions,
    })
}

pub const MAX_EXPANSION: usize = 256 * 1024 * 1024;
