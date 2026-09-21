use crate::git::{
    bounded_inflate, git_object_id, parse_entry_header, read_ofs_distance, InflateError, ObjType,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ParsedEntry {
    pub offset: u64,
    pub header_end: u64,
    pub obj_type: &'static str,
    pub type_code: u8,
    pub declared_size: u64,
    pub data: Option<Vec<u8>>,
    pub data_len: u64,
    pub compressed_len: u64,
    pub next_offset: Option<u64>,
    pub ofs_distance: Option<u64>,
    pub ref_base: Option<[u8; 20]>,
    pub error: Option<String>,
    pub sha1: Option<[u8; 20]>,
    pub trailing_bytes: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<ParsedEntry>,
    pub pack_sha: Option<[u8; 20]>,
    pub computed_pack_sha: Option<[u8; 20]>,
    pub checksum_ok: Option<bool>,
    pub trailing_after_entries: u64,
    pub header_issue: Option<String>,
    pub errors: Vec<String>,
}

const DEFAULT_INFLATE_HARD_LIMIT: u64 = 64 * 1024 * 1024;

pub fn parse_pack(bytes: &[u8], hard_limit: Option<u64>) -> ParsedPack {
    parse_pack_with_offsets(bytes, None, hard_limit)
}

pub fn parse_pack_with_offsets(
    bytes: &[u8],
    known_offsets: Option<&[u64]>,
    hard_limit: Option<u64>,
) -> ParsedPack {
    use sha1::{Digest, Sha1};
    let mut pack = ParsedPack::default();
    let hard = hard_limit.unwrap_or(DEFAULT_INFLATE_HARD_LIMIT);
    if bytes.len() < 12 {
        pack.header_issue = Some("pack 文件不足 12 字节".to_string());
        return pack;
    }
    if &bytes[0..4] != b"PACK" {
        pack.header_issue = Some("缺少 PACK 魔数".to_string());
        return pack;
    }
    pack.version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    pack.count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    if pack.version != 2 {
        pack.header_issue = Some(format!("不支持的 pack 版本 {}", pack.version));
        return pack;
    }
    if bytes.len() < 32 {
        pack.header_issue = Some("pack 缺少 20 字节尾部校验".to_string());
        return pack;
    }
    let data_end = bytes.len() - 20;
    let stored = bytes[data_end..].try_into().unwrap();
    pack.pack_sha = Some(stored);
    let mut hasher = Sha1::new();
    hasher.update(&bytes[..data_end]);
    let computed: [u8; 20] = hasher.finalize().into();
    pack.computed_pack_sha = Some(computed);
    pack.checksum_ok = Some(stored == computed);

    let mut off: usize = 12;
    let mut idx: u32 = 0;
    while off < data_end {
        if idx >= pack.count {
            pack.trailing_after_entries = (data_end - off) as u64;
            break;
        }
        let entry = parse_one(bytes, off, data_end, hard);
        let advance = match (&entry.data, &entry.error, entry.next_offset) {
            (_, _, Some(next)) if next > off as u64 => (next - off as u64) as usize,
            (Some(_), _, None) => entry.compressed_len as usize
                + (entry.header_end as usize - off)
                + (if entry.ref_base.is_some() { 20 } else { 0 }),
            _ => 0,
        };
        let broken = entry.data.is_none() || entry.error.is_some();
        off += advance;
        pack.entries.push(entry);
        idx += 1;
        if broken {
            match resync_offset(bytes, off, data_end, known_offsets, idx, pack.count) {
                Some(new_off) => {
                    if new_off > off {
                        pack.errors
                            .push(format!("offset {} 处损坏，跳过 {} 字节后重新同步", off, new_off - off));
                    }
                    off = new_off;
                }
                None => {
                    pack.errors
                        .push(format!("offset {} 处损坏且无法重新同步，终止解析", off));
                    break;
                }
            }
        }
    }
    if pack.entries.len() as u32 != pack.count && pack.errors.is_empty() {
        pack.errors.push(format!(
            "对象数量不匹配：header 声明 {}，实际解析 {}",
            pack.count,
            pack.entries.len()
        ));
    }
    pack
}

fn parse_one(bytes: &[u8], start: usize, data_end: usize, hard: u64) -> ParsedEntry {
    let mut e = ParsedEntry {
        offset: start as u64,
        header_end: 0,
        obj_type: "unknown",
        type_code: 0,
        declared_size: 0,
        data: None,
        data_len: 0,
        compressed_len: 0,
        next_offset: None,
        ofs_distance: None,
        ref_base: None,
        error: None,
        sha1: None,
        trailing_bytes: false,
    };
    let (typ, size, header_end) = match parse_entry_header(bytes, start) {
        Ok(v) => v,
        Err(err) => {
            e.error = Some(format!("对象头解析失败: {:?}", err));
            return e;
        }
    };
    e.obj_type = typ.type_name();
    e.type_code = typ as u8;
    e.declared_size = size;
    e.header_end = header_end as u64;
    let mut zstart = header_end;
    if typ == ObjType::RefDelta {
        if header_end + 20 > data_end {
            e.error = Some("ref-delta 的 20 字节 base oid 越界".to_string());
            return e;
        }
        let oid: [u8; 20] = bytes[header_end..header_end + 20].try_into().unwrap();
        e.ref_base = Some(oid);
        zstart = header_end + 20;
    } else if typ == ObjType::OfsDelta {
        match read_ofs_distance(bytes, header_end) {
            Ok((dist, next)) => {
                e.ofs_distance = Some(dist);
                zstart = next;
                let base = start as i64 - dist as i64;
                if base < 12 || base as usize >= data_end {
                    e.error = Some(format!(
                        "ofs-delta 距离 {} 越界（base 落在 offset {}）",
                        dist, base
                    ));
                    return e;
                }
            }
            Err(err) => {
                e.error = Some(format!("ofs-delta 距离解析失败: {:?}", err));
                return e;
            }
        }
    }
    if zstart >= data_end {
        e.error = Some("压缩数据起始位置越界".to_string());
        return e;
    }
    let outcome = match bounded_inflate(&bytes[zstart..data_end], Some(size), hard) {
        Ok(o) => o,
        Err(err) => {
            e.error = Some(inflate_error_text(&err, size));
            return e;
        }
    };
    e.compressed_len = outcome.consumed as u64;
    e.trailing_bytes = outcome.trailing;
    e.next_offset = Some((zstart + outcome.consumed) as u64);
    e.data_len = outcome.data.len() as u64;
    e.data = Some(outcome.data);
    if let Some(name) = typ.base_type() {
        e.sha1 = Some(git_object_id(name, e.data.as_ref().unwrap()));
    }
    e
}

fn inflate_error_text(err: &InflateError, declared: u64) -> String {
    match err {
        InflateError::Truncated => "zlib 流提前结束".to_string(),
        InflateError::Corrupt(msg) => format!("zlib 数据损坏: {}", msg),
        InflateError::SizeSpoof { declared: _, actual } => format!(
            "大小欺骗：header 声明 {} 字节，解压至少得到 {} 字节",
            declared, actual
        ),
        InflateError::TooLarge { declared: _, limit } => {
            format!("解压超出安全硬上限 {} 字节", limit)
        }
    }
}

fn resync_offset(
    bytes: &[u8],
    after: usize,
    data_end: usize,
    known_offsets: Option<&[u64]>,
    idx: u32,
    count: u32,
) -> Option<usize> {
    if let Some(offs) = known_offsets {
        for o in offs {
            if (*o as usize) > after && (*o as usize) < data_end {
                return Some(*o as usize);
            }
        }
    }
    let scan_limit = after.saturating_add(4096).min(data_end);
    let mut probe = after + 1;
    while probe < scan_limit {
        if let Ok((typ, size, header_end)) = parse_entry_header(bytes, probe) {
            let mut zstart = header_end;
            if typ == ObjType::RefDelta {
                zstart += 20;
            } else if typ == ObjType::OfsDelta {
                if read_ofs_distance(bytes, header_end).is_err() {
                    probe += 1;
                    continue;
                }
                if let Ok((_, next)) = read_ofs_distance(bytes, header_end) {
                    zstart = next;
                }
            }
            if zstart < data_end {
                if let Ok(out) = bounded_inflate(&bytes[zstart..data_end], Some(size), 1 << 20) {
                    let end = zstart + out.consumed;
                    if out.data.len() as u64 == size && end <= data_end {
                        let remaining_entries = count.saturating_sub(idx) as usize;
                        if plausible_tail(bytes, end, data_end, known_offsets, remaining_entries) {
                            return Some(probe);
                        }
                    }
                }
            }
        }
        probe += 1;
    }
    None
}

fn plausible_tail(
    bytes: &[u8],
    mut off: usize,
    data_end: usize,
    known_offsets: Option<&[u64]>,
    remaining: usize,
) -> bool {
    if let Some(offs) = known_offsets {
        return offs.iter().any(|o| *o as usize == off);
    }
    for _ in 0..remaining.min(4) {
        if off >= data_end {
            return true;
        }
        let entry = parse_one(bytes, off, data_end, 1 << 20);
        match entry.next_offset {
            Some(next) if (next as usize) > off => off = next as usize,
            _ => return false,
        }
    }
    true
}
