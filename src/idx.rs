use crate::oid::{self, Oid};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    /// idx 声明的 pack 校验和（用于与 pack 配对）
    pub pack_checksum: Option<String>,
    pub errors: Vec<String>,
}

pub fn parse_idx(bytes: &[u8]) -> Result<IdxFile, String> {
    if bytes.len() < 4 * 256 + 20 {
        return Err("idx 文件过短".to_string());
    }
    if bytes[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        parse_v2(bytes)
    } else {
        parse_v1(bytes)
    }
}

fn read_fanout(bytes: &[u8], at: usize) -> ([u32; 256], u32) {
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes([
            bytes[at + i * 4],
            bytes[at + i * 4 + 1],
            bytes[at + i * 4 + 2],
            bytes[at + i * 4 + 3],
        ]);
    }
    (fanout, fanout[255])
}

fn parse_v2(bytes: &[u8]) -> Result<IdxFile, String> {
    let mut errors = Vec::new();
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version}"));
    }
    let (fanout, n) = read_fanout(bytes, 8);
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push("fanout 表非单调递增".to_string());
            break;
        }
    }
    let n = n as usize;
    let oid_at = 8 + 4 * 256;
    let crc_at = oid_at + n * 20;
    let off_at = crc_at + n * 4;
    let big_at = off_at + n * 4;
    if bytes.len() < big_at + 40 {
        return Err("idx 文件截断".to_string());
    }
    let trailer_at = bytes.len() - 40;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid: Oid = bytes[oid_at + i * 20..oid_at + i * 20 + 20]
            .try_into()
            .map_err(|_| "idx oid 区截断")?;
        let crc32 = u32::from_be_bytes([
            bytes[crc_at + i * 4],
            bytes[crc_at + i * 4 + 1],
            bytes[crc_at + i * 4 + 2],
            bytes[crc_at + i * 4 + 3],
        ]);
        let raw_off = u32::from_be_bytes([
            bytes[off_at + i * 4],
            bytes[off_at + i * 4 + 1],
            bytes[off_at + i * 4 + 2],
            bytes[off_at + i * 4 + 3],
        ]);
        let offset = if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let at = big_at + idx * 8;
            if at + 8 > trailer_at {
                return Err("idx 大偏移表越界".to_string());
            }
            u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap())
        } else {
            raw_off as u64
        };
        entries.push(IdxEntry {
            oid: oid::to_hex(&oid),
            crc32,
            offset,
        });
    }
    let pack_checksum: Oid = bytes[trailer_at..trailer_at + 20].try_into().unwrap();
    let idx_checksum: Oid = bytes[trailer_at + 20..].try_into().unwrap();
    let actual = oid::hash_bytes(&bytes[..trailer_at + 20]);
    if actual != idx_checksum {
        errors.push(format!(
            "idx 自身校验和不匹配: 声明 {}，实际 {}",
            oid::to_hex(&idx_checksum),
            oid::to_hex(&actual)
        ));
    }
    Ok(IdxFile {
        version: 2,
        fanout: fanout.to_vec(),
        entries,
        pack_checksum: Some(oid::to_hex(&pack_checksum)),
        errors,
    })
}

fn parse_v1(bytes: &[u8]) -> Result<IdxFile, String> {
    let (fanout, n) = read_fanout(bytes, 0);
    let n = n as usize;
    let entries_at = 4 * 256;
    if bytes.len() < entries_at + n * 24 {
        return Err("idx v1 文件截断".to_string());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let at = entries_at + i * 24;
        let offset = u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let oid: Oid = bytes[at + 4..at + 24].try_into().unwrap();
        entries.push(IdxEntry {
            oid: oid::to_hex(&oid),
            crc32: 0,
            offset: offset as u64,
        });
    }
    Ok(IdxFile {
        version: 1,
        fanout: fanout.to_vec(),
        entries,
        pack_checksum: None,
        errors: vec!["idx v1 不含 CRC 与 pack 校验和".to_string()],
    })
}
