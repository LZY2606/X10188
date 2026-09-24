//! pack index (v2) 解析：fanout、oid 表、CRC32、偏移表。

#[derive(Debug, Clone)]
pub struct IdxRecord {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub records: Vec<IdxRecord>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub idx_sha1_ok: bool,
}

#[derive(Debug)]
pub enum IdxError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
}

impl std::fmt::Display for IdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdxError::TooShort => write!(f, "文件太短，不是合法 index"),
            IdxError::BadMagic => write!(f, "缺少 index 魔数"),
            IdxError::UnsupportedVersion(v) => write!(f, "不支持的 index 版本 {v}"),
            IdxError::Truncated => write!(f, "index 数据截断"),
        }
    }
}

pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx, IdxError> {
    if data.len() < 8 + 256 * 4 + 40 {
        return Err(IdxError::TooShort);
    }
    if &data[0..4] != b"\xfftOc" {
        return Err(IdxError::BadMagic);
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(IdxError::UnsupportedVersion(version));
    }
    let mut fanout = [0u32; 256];
    let mut pos = 8usize;
    for f in fanout.iter_mut() {
        *f = u32::from_be_bytes(data[pos..pos + 4].try_into().map_err(|_| IdxError::Truncated)?);
        pos += 4;
    }
    let n = fanout[255] as usize;
    let need = pos + n * 20 + n * 4 + n * 4 + 40;
    if data.len() < need {
        return Err(IdxError::Truncated);
    }
    let oid_base = pos;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let large_base = off_base + n * 4;
    let mut records = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 = u32::from_be_bytes(
            data[crc_base + i * 4..crc_base + i * 4 + 4]
                .try_into()
                .map_err(|_| IdxError::Truncated)?,
        );
        let raw_off = u32::from_be_bytes(
            data[off_base + i * 4..off_base + i * 4 + 4]
                .try_into()
                .map_err(|_| IdxError::Truncated)?,
        );
        let offset = if raw_off & 0x8000_0000 != 0 {
            let li = (raw_off & 0x7fff_ffff) as usize;
            let p = large_base + li * 8;
            if p + 8 > data.len() {
                return Err(IdxError::Truncated);
            }
            u64::from_be_bytes(data[p..p + 8].try_into().map_err(|_| IdxError::Truncated)?)
        } else {
            raw_off as u64
        };
        records.push(IdxRecord { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&data[data.len() - 40..data.len() - 20]);
    let idx_sha1 = hex::encode(&data[data.len() - 20..]);
    let mut h = sha1::Sha1::new();
    use sha1::Digest;
    h.update(&data[..data.len() - 20]);
    let idx_sha1_ok = hex::encode(h.finalize()) == idx_sha1;
    Ok(ParsedIdx {
        fanout,
        records,
        pack_sha1,
        idx_sha1,
        idx_sha1_ok,
    })
}
