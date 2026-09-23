use crate::gitobj::sha1_hex;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxInfo {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub self_checksum_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 8 + 256 * 4 + 40 {
        return Err("idx 文件太短".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 idx v2 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version} (仅支持 v2)"));
    }
    let mut fanout = [0u32; 256];
    for (i, f) in fanout.iter_mut().enumerate() {
        let p = 8 + 4 * i;
        *f = u32::from_be_bytes(data[p..p + 4].try_into().unwrap());
    }
    let n = fanout[255] as usize;
    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + 20 * n;
    let off_start = crc_start + 4 * n;
    let large_start = off_start + 4 * n;
    if data.len() < large_start + 40 {
        return Err("idx 文件截断".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_start + 20 * i..oid_start + 20 * (i + 1)]);
        let crc32 = u32::from_be_bytes(data[crc_start + 4 * i..crc_start + 4 * i + 4].try_into().unwrap());
        let raw_off =
            u32::from_be_bytes(data[off_start + 4 * i..off_start + 4 * i + 4].try_into().unwrap());
        let offset = if raw_off & 0x8000_0000 != 0 {
            let li = (raw_off & 0x7fff_ffff) as usize;
            let p = large_start + 8 * li;
            if p + 8 > data.len() - 40 {
                return Err("idx 大偏移表越界".into());
            }
            u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_checksum = hex::encode(&data[data.len() - 40..data.len() - 20]);
    let self_checksum_ok = sha1_hex(&data[..data.len() - 20]) == hex::encode(&data[data.len() - 20..]);
    Ok(IdxInfo { fanout, entries, pack_checksum, self_checksum_ok })
}
