//! Git pack index v2 解析：fanout、oid 表、CRC32 表、offset 表与双层校验和。

use serde::{Deserialize, Serialize};

use crate::Oid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdxObject {
    pub oid: Oid,
    pub crc32: u32,
    /// pack 内绝对偏移（自动解析 8 字节长偏移表）。
    pub offset: u64,
    pub is_long_offset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdxFanout {
    /// 256 项累计计数（fanout[i] = 首字节 <= i 的对象数）。
    pub table: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdxFile {
    pub count: u32,
    pub fanout: IdxFanout,
    pub objects: Vec<IdxObject>,
    /// idx 记录的 pack 文件 SHA-1。
    pub pack_checksum: Oid,
    /// idx 自身 SHA-1。
    pub idx_checksum: Oid,
    /// 与传入 pack trailer 是否一致。
    pub pack_checksum_ok: bool,
    pub idx_checksum_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdxError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated { at: usize },
    FanoutCount(u32),
    LongOffsetOutOfRange { index: u64, table_len: usize },
}

impl std::fmt::Display for IdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for IdxError {}

fn rd<const N: usize>(data: &[u8], p: usize) -> Result<[u8; N], IdxError> {
    if p + N > data.len() {
        return Err(IdxError::Truncated { at: p });
    }
    let mut b = [0u8; N];
    b.copy_from_slice(&data[p..p + N]);
    Ok(b)
}

pub fn parse_idx(data: &[u8], pack_trailer: Option<&Oid>) -> Result<IdxFile, IdxError> {
    use sha1::{Digest, Sha1};
    if data.len() < 8 || &data[..4] != b"\xfftOc" {
        return Err(IdxError::BadMagic);
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(IdxError::UnsupportedVersion(version));
    }

    let mut p = 8usize;
    let mut table = Vec::with_capacity(256);
    for _ in 0..256 {
        table.push(u32::from_be_bytes(rd::<4>(data, p)?));
        p += 4;
    }
    let count = table[255];

    let mut oids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        oids.push(Oid::from_slice(&rd::<20>(data, p)?));
        p += 20;
    }
    let mut crcs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        crcs.push(u32::from_be_bytes(rd::<4>(data, p)?));
        p += 4;
    }
    let mut raw_offsets = Vec::with_capacity(count as usize);
    for _ in 0..count {
        raw_offsets.push(u32::from_be_bytes(rd::<4>(data, p)?));
        p += 4;
    }

    // 尾部固定 40 字节：pack 校验和(20) + idx 校验和(20)。中间为 8 字节长偏移表。
    if data.len() < p + 40 {
        return Err(IdxError::Truncated { at: p });
    }
    let trailer_at = data.len() - 40;
    let long_table_len = trailer_at - p;
    if long_table_len % 8 != 0 {
        return Err(IdxError::Truncated { at: p });
    }
    let long_table: &[u8] = &data[p..trailer_at];

    let mut objects = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let r = raw_offsets[i];
        let (offset, is_long) = if r & 0x8000_0000 != 0 {
            let idx = (r & 0x7fff_ffff) as usize;
            if idx * 8 + 8 > long_table.len() {
                return Err(IdxError::LongOffsetOutOfRange {
                    index: idx as u64,
                    table_len: long_table.len() / 8,
                });
            }
            (u64::from_be_bytes(long_table[idx * 8..idx * 8 + 8].try_into().unwrap()), true)
        } else {
            (r as u64, false)
        };
        objects.push(IdxObject { oid: oids[i], crc32: crcs[i], offset, is_long_offset: is_long });
    }

    let pack_checksum_stored = Oid::from_slice(&data[trailer_at..trailer_at + 20]);
    let idx_checksum = Oid::from_slice(&data[trailer_at + 20..trailer_at + 40]);

    // idx 校验范围：magic 起，到 pack 校验和（含）为止。
    let mut h = Sha1::new();
    h.update(&data[..trailer_at + 20]);
    let idx_want = Oid(h.finalize().into());

    Ok(IdxFile {
        count,
        fanout: IdxFanout { table },
        objects,
        pack_checksum: pack_checksum_stored,
        idx_checksum,
        pack_checksum_ok: pack_trailer.map_or(true, |pc| *pc == pack_checksum_stored),
        idx_checksum_ok: idx_want == idx_checksum,
    })
}
