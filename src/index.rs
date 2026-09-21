use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedIndex {
    pub fanout: [u32; 256],
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: String,
    pub self_checksum_ok: bool,
    pub errors: Vec<String>,
}

pub fn parse_index(data: &[u8]) -> Result<ParsedIndex, String> {
    let header_len = 8 + 256 * 4;
    if data.len() < header_len + 40 {
        return Err("index 太小，缺少 fanout 或校验和".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 index 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("仅支持 index v2，实际版本 {}", version));
    }
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let p = 8 + i * 4;
        fanout[i] = u32::from_be_bytes(data[p..p + 4].try_into().unwrap());
        if i > 0 && fanout[i] < fanout[i - 1] {
            errors.push(format!("fanout 表在 {:#04x} 处非单调递增", i));
        }
    }
    let n = fanout[255] as usize;
    let oid_start = header_len;
    let crc_start = oid_start + n * 20;
    let off_start = crc_start + n * 4;
    let big_off_start = off_start + n * 4;
    if data.len() < big_off_start + 40 {
        return Err("index 被截断，条目区不完整".into());
    }
    let trailer_start = data.len() - 40;
    if big_off_start > trailer_start {
        return Err("index 条目区与校验和重叠".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_start + i * 20..oid_start + i * 20 + 20]);
        let crc32 = u32::from_be_bytes(data[crc_start + i * 4..crc_start + i * 4 + 4].try_into().unwrap());
        let raw_off =
            u32::from_be_bytes(data[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap());
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx64 = (raw_off & 0x7fff_ffff) as usize;
            let p = big_off_start + idx64 * 8;
            if p + 8 > trailer_start {
                errors.push(format!("oid {} 的 64 位偏移表索引越界", oid));
                continue;
            }
            u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IndexEntry { oid, crc32, offset });
    }
    let pack_checksum = hex::encode(&data[trailer_start..trailer_start + 20]);
    let mut h = Sha1::new();
    h.update(&data[..trailer_start + 20]);
    let calc = h.finalize();
    let self_checksum_ok = calc.as_slice() == &data[trailer_start + 20..];
    if !self_checksum_ok {
        errors.push("index 自身校验和不匹配".into());
    }
    Ok(ParsedIndex {
        fanout,
        entries,
        pack_checksum,
        self_checksum_ok,
        errors,
    })
}
