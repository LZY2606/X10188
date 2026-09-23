//! Git pack index (.idx) parser: v2 (magic \xfftOc) and v1, exposing the
//! 256-bucket fanout table, oid list, CRC32 table and 32/64-bit offsets.

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxParse {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
}

fn read_fanout(data: &[u8]) -> Result<[u32; 256], String> {
    if data.len() < 256 * 4 {
        return Err("idx 太小, 无法读取 fanout".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
    }
    Ok(fanout)
}

pub fn parse_idx(data: &[u8]) -> Result<IdxParse, String> {
    if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if version != 2 {
            return Err(format!("不支持的 idx 版本 {version}"));
        }
        let fanout = read_fanout(&data[8..])?;
        let n = fanout[255] as usize;
        let base = 8 + 256 * 4;
        let need = base + n * 20 + n * 4 + n * 4;
        if data.len() < need {
            return Err("idx 被截断".into());
        }
        let oid_base = base;
        let crc_base = oid_base + n * 20;
        let off_base = crc_base + n * 4;
        let big_base = off_base + n * 4;
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
            let crc32 = u32::from_be_bytes(data[crc_base + i * 4..crc_base + i * 4 + 4].try_into().unwrap());
            let raw = u32::from_be_bytes(data[off_base + i * 4..off_base + i * 4 + 4].try_into().unwrap());
            let offset = if raw & 0x8000_0000 != 0 {
                let idx64 = (raw & 0x7fff_ffff) as usize;
                let p = big_base + idx64 * 8;
                if p + 8 > data.len() {
                    return Err("idx 64 位偏移表越界".into());
                }
                u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
            } else {
                raw as u64
            };
            entries.push(IdxEntry { oid, crc32, offset });
        }
        Ok(IdxParse { version, fanout, entries })
    } else {
        // v1: fanout at offset 0, then (offset, sha1) records.
        let fanout = read_fanout(data)?;
        let n = fanout[255] as usize;
        let base = 256 * 4;
        if data.len() < base + n * 24 {
            return Err("idx v1 被截断".into());
        }
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let p = base + i * 24;
            let offset = u32::from_be_bytes(data[p..p + 4].try_into().unwrap()) as u64;
            let oid = hex::encode(&data[p + 4..p + 24]);
            entries.push(IdxEntry { oid, crc32: 0, offset });
        }
        Ok(IdxParse { version: 1, fanout, entries })
    }
}
