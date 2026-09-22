use crate::oid::Oid;

pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
}

pub struct ParsedIndex {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解析 pack index v2: magic、版本、256 项 fanout、oid/crc/offset 表与 64 位大偏移表。
pub fn parse_index(bytes: &[u8]) -> Result<ParsedIndex, String> {
    if bytes.len() < 8 + 256 * 4 {
        return Err("index shorter than fanout table".to_string());
    }
    if &bytes[0..4] != b"\xfftOc" {
        return Err("bad index magic".to_string());
    }
    let version = be32(&bytes[4..8]);
    if version != 2 {
        return Err(format!("unsupported index version {version}"));
    }

    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = be32(&bytes[8 + i * 4..12 + i * 4]);
    }
    let n = fanout[255] as usize;
    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + n * 20;
    let off_start = crc_start + n * 4;
    let big_start = off_start + n * 4;
    if bytes.len() < big_start {
        return Err("truncated index object tables".to_string());
    }

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&bytes[oid_start + i * 20..oid_start + i * 20 + 20]);
        let crc32 = be32(&bytes[crc_start + i * 4..crc_start + i * 4 + 4]);
        let raw = be32(&bytes[off_start + i * 4..off_start + i * 4 + 4]);
        let offset = if raw & 0x8000_0000 != 0 {
            let bi = (raw & 0x7fff_ffff) as usize;
            let p = big_start + bi * 8;
            if p + 8 > bytes.len() {
                return Err("truncated 64-bit offset table".to_string());
            }
            u64::from_be_bytes(bytes[p..p + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }

    Ok(ParsedIndex {
        version,
        fanout,
        entries,
    })
}
