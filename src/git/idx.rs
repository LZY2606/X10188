//! pack index（.idx v2 为主，兼容 v1）解析：
//! fanout 表、oid→offset、每对象 CRC32 表，以及与 pack 的配套校验。

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc: u32,
    pub ordinal: usize,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub version: u32,
    pub count: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// index 自己声称的 pack 校验和
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub errors: Vec<String>,
}

fn checksum_ok(buf: &[u8], checksum_field: &[u8; 20]) -> bool {
    super::sha1_bytes(&buf[..buf.len() - 20]) == *checksum_field
}

pub fn parse_idx(buf: &[u8]) -> Result<IdxFile, String> {
    if buf.len() < 8 {
        return Err("index 文件过短".into());
    }

    let mut errors = Vec::new();

    // v2: \377tOc 00 00 00 02
    let is_v2 = buf[0..4] == [0xff, b't', b'O', b'c'];
    let version = if is_v2 {
        let v = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if v != 2 {
            return Err(format!("不支持的 idx 版本: {v}"));
        }
        2
    } else {
        1
    };

    let fanout_start = if version == 2 { 8 } else { 0 };
    if buf.len() < fanout_start + 256 * 4 {
        return Err("index fanout 表被截断".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let s = fanout_start + i * 4;
        fanout[i] = u32::from_be_bytes([buf[s], buf[s + 1], buf[s + 2], buf[s + 3]]);
    }
    // fanout 单调不减，末项即对象数
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(format!("fanout 表在 [{i}] 处递减，index 已损坏"));
        }
    }
    let count = fanout[255];

    if version == 2 {
        let need = 8 + 256 * 4 + count as usize * 20
            + count as usize * 4
            + count as usize * 4
            + 40;
        if buf.len() < need {
            return Err(format!(
                "index 数据区被截断：需要至少 {need} 字节，实际 {} 字节",
                buf.len()
            ));
        }
    } else {
        // v1: fanout + count*(4 offset + 20 oid) + 40
        let need = 256 * 4 + count as usize * 24 + 40;
        if buf.len() < need {
            return Err(format!("v1 index 数据区被截断：需要 {need}，实际 {}", buf.len()));
        }
    }

    let mut entries = Vec::with_capacity(count as usize);

    if version == 2 {
        let oid_base = 8 + 256 * 4;
        let crc_base = oid_base + count as usize * 20;
        let off_base = crc_base + count as usize * 4;
        let large_base = off_base + count as usize * 4;
        for i in 0..count as usize {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&buf[oid_base + i * 20..oid_base + (i + 1) * 20]);
            let crc = u32::from_be_bytes([
                buf[crc_base + i * 4],
                buf[crc_base + i * 4 + 1],
                buf[crc_base + i * 4 + 2],
                buf[crc_base + i * 4 + 3],
            ]);
            let off32 = u32::from_be_bytes([
                buf[off_base + i * 4],
                buf[off_base + i * 4 + 1],
                buf[off_base + i * 4 + 2],
                buf[off_base + i * 4 + 3],
            ]);
            let offset = if off32 & 0x8000_0000 != 0 {
                let idx64 = (off32 & 0x7fff_ffff) as usize;
                let s = large_base + idx64 * 8;
                if s + 8 > buf.len() - 40 {
                    return Err("64 位偏移表越界".into());
                }
                u64::from_be_bytes(buf[s..s + 8].try_into().unwrap())
            } else {
                off32 as u64
            };
            entries.push(IdxEntry {
                oid,
                offset,
                crc,
                ordinal: i,
            });
        }
    } else {
        // v1: 每格 4 字节偏移 + 20 字节 oid
        let base = 256 * 4;
        for i in 0..count as usize {
            let s = base + i * 24;
            let offset = u32::from_be_bytes([buf[s], buf[s + 1], buf[s + 2], buf[s + 3]])
                as u64;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&buf[s + 4..s + 24]);
            entries.push(IdxEntry {
                oid,
                offset,
                crc: 0,
                ordinal: i,
            });
        }
    }

    // oid 必须升序（v2），且与 fanout 一致
    for i in 1..entries.len() {
        if entries[i].oid <= entries[i - 1].oid {
            errors.push(format!(
                "oid 表在序号 {i} 处未严格递增，index 已损坏"
            ));
        }
    }
    for e in &entries {
        let bucket = e.oid[0] as usize;
        let lo = if bucket == 0 { 0 } else { fanout[bucket - 1] };
        let hi = fanout[bucket];
        if !((lo as usize)..(hi as usize)).contains(&e.ordinal) {
            errors.push(format!(
                "oid {} 序号 {} 与 fanout[{bucket}] 区间 [{},{}) 不一致",
                hex::encode(e.oid),
                e.ordinal,
                lo,
                hi
            ));
        }
    }

    let mut pack_checksum = [0u8; 20];
    let mut idx_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&buf[buf.len() - 40..buf.len() - 20]);
    idx_checksum.copy_from_slice(&buf[buf.len() - 20..]);
    if !checksum_ok(buf, &idx_checksum) {
        errors.push("index 自身 SHA1 校验失败".into());
    }

    Ok(IdxFile {
        version,
        count,
        fanout,
        entries,
        pack_checksum,
        idx_checksum,
        errors,
    })
}

/// 计算 pack 中单个对象（对象头 + 压缩数据）的 CRC32。
pub fn crc_of_entry(pack: &[u8], header_offset: u64, end_offset: u64) -> u32 {
    let s = header_offset as usize;
    let e = end_offset as usize;
    let e = e.min(pack.len());
    crc32fast::hash(&pack[s..e])
}
