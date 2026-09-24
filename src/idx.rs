//! Git pack index (v2) 解析：fanout、oid 表、crc32、偏移表。

use anyhow::{bail, Result};

pub const IDX_MAGIC: [u8; 4] = [0xff, 0x74, 0x4f, 0x63];

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Idx {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_idx(data: &[u8]) -> Result<Idx> {
    if data.len() < 8 + 256 * 4 || data[0..4] != IDX_MAGIC {
        bail!("不是 index v2 文件（缺少魔数）");
    }
    let version = be32(&data[4..8]);
    if version != 2 {
        bail!("不支持的 index 版本 {version}（仅支持 v2）");
    }
    let mut fanout = [0u32; 256];
    let mut pos = 8;
    for slot in fanout.iter_mut() {
        *slot = be32(&data[pos..pos + 4]);
        pos += 4;
    }
    let n = fanout[255] as usize;
    let need = pos + n * 20 + n * 4 + n * 4 + 40;
    if data.len() < need {
        bail!("index 文件截断");
    }
    let oid_base = pos;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let large_base = off_base + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 = be32(&data[crc_base + i * 4..crc_base + i * 4 + 4]);
        let raw = be32(&data[off_base + i * 4..off_base + i * 4 + 4]);
        let offset = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let p = large_base + li * 8;
            if p + 8 > data.len() {
                bail!("大偏移表越界");
            }
            u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&data[data.len() - 40..data.len() - 20]);
    Ok(Idx { fanout, entries, pack_sha1 })
}
