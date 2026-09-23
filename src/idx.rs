use crate::oid::Oid;
use serde::Serialize;

pub const IDX_MAGIC: &[u8; 4] = &[0xff, 0x74, 0x4f, 0x63];

#[derive(Clone, Debug, Serialize)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdxParse {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub fanout_ok: bool,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub idx_checksum: String,
    pub checksum_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxParse, String> {
    if data.len() < 8 + 256 * 4 + 40 {
        return Err(format!("文件太小 ({} 字节)，不是有效 index", data.len()));
    }
    if &data[0..4] != IDX_MAGIC {
        return Err("缺少 index 魔数 (\\xfftOc)，不支持 v1 index".to_string());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("不支持的 index 版本 {version}"));
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let o = 8 + i * 4;
        fanout.push(u32::from_be_bytes(data[o..o + 4].try_into().unwrap()));
    }
    let n = fanout[255] as usize;
    let names_start = 8 + 256 * 4;
    let crc_start = names_start + 20 * n;
    let off_start = crc_start + 4 * n;
    let big_start = off_start + 4 * n;
    if big_start + 40 > data.len() {
        return Err("index 被截断".to_string());
    }
    let trailer_start = data.len() - 40;
    if big_start > trailer_start {
        return Err("index 长度与 fanout 计数不符".to_string());
    }

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = Oid::from_bytes(&data[names_start + i * 20..names_start + i * 20 + 20])
            .ok_or("oid 长度错误")?;
        let crc32 = u32::from_be_bytes(data[crc_start + i * 4..crc_start + i * 4 + 4].try_into().unwrap());
        let raw_off =
            u32::from_be_bytes(data[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap());
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let p = big_start + idx * 8;
            if p + 8 > trailer_start {
                return Err("大偏移表越界".to_string());
            }
            u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }

    // fanout 校验：单调、总数一致、各桶首字节匹配
    let mut fanout_ok = fanout.windows(2).all(|w| w[0] <= w[1]);
    if fanout_ok {
        let mut prev = 0u32;
        for (byte, &count) in fanout.iter().enumerate() {
            for e in &entries[prev as usize..count as usize] {
                if e.oid.0[0] as usize != byte {
                    fanout_ok = false;
                    break;
                }
            }
            if !fanout_ok {
                break;
            }
            prev = count;
        }
    }

    let pack_checksum = hex::encode(&data[trailer_start..trailer_start + 20]);
    let idx_checksum = hex::encode(&data[trailer_start + 20..trailer_start + 40]);
    let checksum_ok =
        crate::hash::sha1_bytes(&data[..trailer_start + 20]) == data[trailer_start + 20..trailer_start + 40];

    Ok(IdxParse {
        version,
        fanout,
        fanout_ok,
        entries,
        pack_checksum,
        idx_checksum,
        checksum_ok,
    })
}
