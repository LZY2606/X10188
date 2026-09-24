/// Git pack index (v2) 解析: fanout、oid 表、CRC 表、偏移表。
#[derive(Clone, Debug, serde::Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct IdxScan {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub idx_sha1_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxScan, String> {
    if data.len() < 8 + 256 * 4 + 40 {
        return Err("index 文件过短".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("不是 v2 index(缺少 \\xfftOc 魔数)".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(format!("不支持的 index 版本 {version}"));
    }
    let mut fanout = [0u32; 256];
    for (i, slot) in fanout.iter_mut().enumerate() {
        let b = 8 + i * 4;
        *slot = u32::from_be_bytes([data[b], data[b + 1], data[b + 2], data[b + 3]]);
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            return Err("fanout 表非单调递增".into());
        }
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    if big_base > data.len() {
        return Err("index 表区截断".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let c = crc_base + i * 4;
        let crc32 = u32::from_be_bytes([data[c], data[c + 1], data[c + 2], data[c + 3]]);
        let o = off_base + i * 4;
        let raw = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let b = big_base + idx * 8;
            if b + 8 > data.len() {
                return Err("64 位偏移表越界".into());
            }
            u64::from_be_bytes([
                data[b], data[b + 1], data[b + 2], data[b + 3],
                data[b + 4], data[b + 5], data[b + 6], data[b + 7],
            ])
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let trailer = data.len() - 40;
    if big_base > trailer {
        return Err("index 尾部校验区与数据区重叠".into());
    }
    let pack_sha1 = hex::encode(&data[trailer..trailer + 20]);
    let idx_sha1 = hex::encode(&data[trailer + 20..]);
    let idx_sha1_ok = crate::gitutil::sha1_hex(&data[..trailer + 20]) == idx_sha1;
    Ok(IdxScan {
        fanout,
        entries,
        pack_sha1,
        idx_sha1,
        idx_sha1_ok,
    })
}
