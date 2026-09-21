use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
    pub large_offset: bool,
    pub crc_ok: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ParsedIdx {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_sha: Option<[u8; 20]>,
    pub idx_sha: Option<[u8; 20]>,
    pub computed_idx_sha: Option<[u8; 20]>,
    pub checksum_ok: Option<bool>,
    pub errors: Vec<String>,
}

pub fn parse_idx(bytes: &[u8]) -> ParsedIdx {
    let mut idx = ParsedIdx {
        fanout: vec![],
        entries: vec![],
        pack_sha: None,
        idx_sha: None,
        computed_idx_sha: None,
        checksum_ok: None,
        errors: vec![],
    };
    let magic = [0xff, 0x74, 0x4f, 0x63];
    if bytes.len() < 8 || bytes[0..4] != magic {
        idx.errors.push("不是 idx v2 文件（缺少 \\377tOc 魔数）".to_string());
        return idx;
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if version != 2 {
        idx.errors.push(format!("不支持的 idx 版本 {}", version));
        return idx;
    }
    let fanout_start = 8usize;
    let fanout: Vec<u32> = (0..256)
        .map(|i| u32::from_be_bytes(bytes[fanout_start + i * 4..fanout_start + i * 4 + 4].try_into().unwrap()))
        .collect();
    idx.fanout = fanout.clone();
    let count = fanout[255] as usize;
    let names_start = fanout_start + 256 * 4;
    let crc_start = names_start + count * 20;
    let off_start = crc_start + count * 4;
    let loff_start = off_start + count * 4;
    let need = loff_start + 40;
    if bytes.len() < need {
        idx.errors
            .push(format!("idx 长度不足：需要至少 {} 字节，实际 {}", need, bytes.len()));
        return idx;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&bytes[names_start + i * 20..names_start + (i + 1) * 20]);
        let crc = u32::from_be_bytes(bytes[crc_start + i * 4..crc_start + i * 4 + 4].try_into().unwrap());
        let raw = u32::from_be_bytes(bytes[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap());
        let (offset, large) = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let p = loff_start + li * 8;
            if p + 8 > bytes.len() - 40 {
                idx.errors.push(format!("条目 {} 的 64 位偏移越界", i));
                return idx;
            }
            (u64::from_be_bytes(bytes[p..p + 8].try_into().unwrap()), true)
        } else {
            (raw as u64, false)
        };
        entries.push(IdxEntry {
            oid,
            offset,
            crc32: crc,
            large_offset: large,
            crc_ok: None,
        });
    }
    let pack_sha: [u8; 20] = bytes[loff_start..loff_start + 20].try_into().unwrap();
    let idx_sha: [u8; 20] = bytes[loff_start + 20..loff_start + 40].try_into().unwrap();
    idx.pack_sha = Some(pack_sha);
    idx.idx_sha = Some(idx_sha);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&bytes[..loff_start + 20]);
    let computed: [u8; 20] = h.finalize().into();
    idx.computed_idx_sha = Some(computed);
    idx.checksum_ok = Some(computed == idx_sha);

    let mut prev: u32 = 0;
    for (i, v) in fanout.iter().enumerate() {
        if *v < prev {
            idx.errors
                .push(format!("fanout[{}]={} 小于前值 {}（fanout 必须单调不减）", i, v, prev));
        }
        prev = *v;
    }
    if prev as usize != count {
        idx.errors
            .push(format!("fanout[255]={} 与对象计数不一致", prev));
    }
    let mut prev_oid = [0u8; 20];
    for (i, e) in entries.iter().enumerate() {
        if i > 0 && e.oid <= prev_oid {
            idx.errors.push(format!("oid 表在第 {} 项未严格递增", i));
        }
        prev_oid = e.oid;
    }
    let expected = |byte: u8| -> usize {
        if byte == 0 { 0 } else { fanout[(byte - 1) as usize] as usize }
    };
    for (i, e) in entries.iter().enumerate() {
        let lo = expected(e.oid[0]);
        let hi = fanout[e.oid[0] as usize] as usize;
        if i < lo || i >= hi {
            idx.errors
                .push(format!("oid {} 的 fanout 槽位不匹配", hex::encode(e.oid)));
            break;
        }
    }
    idx.entries = entries;
    idx
}

pub fn verify_entry_crc(pack_bytes: &[u8], offset: u64, compressed_end: u64, crc: u32) -> bool {
    let s = offset as usize;
    let e = compressed_end as usize;
    if s >= e || e > pack_bytes.len() {
        return false;
    }
    crc32fast::hash(&pack_bytes[s..e]) == crc
}
