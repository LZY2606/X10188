//! Git pack index (v2) parser: magic, fanout table, oid/crc32/offset tables.

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxParse {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha: String,
    pub errors: Vec<String>,
}

pub fn parse_idx(data: &[u8]) -> IdxParse {
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    let mut entries = Vec::new();
    let mut pack_sha = String::new();

    if data.len() < 8 + 256 * 4 + 40 {
        errors.push("index too short".into());
        return IdxParse { fanout, entries, pack_sha, errors };
    }
    if &data[0..4] != b"\xfftOc" {
        errors.push("bad index magic".into());
        return IdxParse { fanout, entries, pack_sha, errors };
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        errors.push(format!("unsupported index version {}", version));
        return IdxParse { fanout, entries, pack_sha, errors };
    }
    let mut prev = 0u32;
    for i in 0..256 {
        let o = 8 + i * 4;
        fanout[i] = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        if fanout[i] < prev {
            errors.push(format!("fanout table not monotonic at bucket {}", i));
        }
        prev = fanout[i];
    }
    let n = fanout[255] as usize;
    let need = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + 40;
    if data.len() < need {
        errors.push(format!(
            "index truncated: fanout says {} objects, need {} bytes, have {}",
            n,
            need,
            data.len()
        ));
        return IdxParse { fanout, entries, pack_sha, errors };
    }
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let large_base = off_base + n * 4;
    for i in 0..n {
        let oid = hex::encode(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let o = crc_base + i * 4;
        let crc32 = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let o = off_base + i * 4;
        let raw = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let offset = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let lo = large_base + li * 8;
            if lo + 8 > data.len() {
                errors.push(format!("large offset table out of range for entry {}", i));
                0
            } else {
                u64::from_be_bytes(data[lo..lo + 8].try_into().unwrap())
            }
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let ps = data.len() - 40;
    pack_sha = hex::encode(&data[ps..ps + 20]);
    let idx_sha = hex::encode(&data[ps + 20..ps + 40]);
    if crate::gitobj::sha1_hex(&data[..ps]) != idx_sha {
        errors.push("index self checksum mismatch".into());
    }
    IdxParse { fanout, entries, pack_sha, errors }
}
