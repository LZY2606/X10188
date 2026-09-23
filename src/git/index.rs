use crate::git::sha::raw_sha1;
use crate::git::zlib::crc32;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FanoutStat {
    pub bucket: usize,
    pub cumulative: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexSummary {
    pub version: u32, // 1 or 2
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: Option<String>,
    pub idx_sha_ok: bool,
    pub fanout_ok: bool,
    pub errors: Vec<String>,
}

fn u32b(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_index(data: &[u8]) -> IndexSummary {
    let mut errors = Vec::new();
    let mut summary = IndexSummary {
        version: 0,
        fanout: vec![],
        entries: vec![],
        pack_checksum: None,
        idx_sha_ok: false,
        fanout_ok: false,
        errors: vec![],
    };

    if data.len() < 256 * 4 + 40 {
        errors.push("index too short for fanout table and trailer".into());
        summary.errors = errors;
        return summary;
    }

    let (version, fanout_start, table_start) = if &data[0..4] == b"\xfftOc" {
        let v = u32b(&data[4..8]);
        if v != 2 {
            errors.push(format!("unsupported idx v2 version {}", v));
            summary.errors = errors;
            return summary;
        }
        (2u32, 8usize, 8usize + 256 * 4)
    } else {
        (1u32, 0usize, 256 * 4)
    };
    summary.version = version;

    let fanout: Vec<u32> = (0..256)
        .map(|i| u32b(&data[fanout_start + i * 4..][..4]))
        .collect();
    let count = fanout[255] as usize;
    summary.fanout = fanout.clone();

    let expected_len = table_start
        + count * 20
        + if version == 2 { count * 4 } else { 0 }
        + count * 4
        + 20
        + 20;
    if data.len() < expected_len {
        errors.push(format!(
            "index length {} shorter than required {} for {} entries",
            data.len(),
            expected_len,
            count
        ));
        summary.errors = errors;
        return summary;
    }

    let oid_start = table_start;
    let mut pos = oid_start + count * 20;
    let crc_start;
    if version == 2 {
        crc_start = pos;
        pos += count * 4;
    } else {
        crc_start = 0;
    }
    let off_start = pos;
    pos += count * 4;
    let large_start = pos;

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let oid = hex::encode(&data[oid_start + i * 20..][..20]);
        let off_word = u32b(&data[off_start + i * 4..][..4]);
        let offset = if version == 2 && off_word & 0x8000_0000 != 0 {
            let idx = (off_word & 0x7fff_ffff) as usize;
            let p = large_start + idx * 8;
            if p + 8 > data.len() {
                errors.push(format!("large-offset table index {} overruns idx", idx));
                0
            } else {
                u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
            }
        } else {
            off_word as u64
        };
        let crc = if version == 2 {
            u32b(&data[crc_start + i * 4..][..4])
        } else {
            0
        };
        entries.push(IdxEntry { oid, offset, crc32: crc });
    }
    summary.entries = entries;

    // Pack + idx checksum trailer.
    let pack_cs_start = expected_len - 40;
    summary.pack_checksum = Some(hex::encode(&data[pack_cs_start..pack_cs_start + 20]));
    let idx_cs = &data[pack_cs_start + 20..pack_cs_start + 40];
    // idx self-checksum covers everything through the pack checksum field.
    let calc = raw_sha1(&data[..pack_cs_start + 20]);
    let _ = &expected_len;
    if calc.as_slice() == idx_cs {
        summary.idx_sha_ok = true;
    } else {
        errors.push(format!(
            "idx checksum mismatch: want {} got {}",
            hex::encode(idx_cs),
            hex::encode(calc)
        ));
    }

    // Fanout consistency: cumulative count of oids by leading byte must match.
    let mut fanout_ok = true;
    let mut seen = 0usize;
    let mut sorted = true;
    let mut prev: Option<&str> = None;
    for (i, e) in summary.entries.iter().enumerate() {
        let lead = usize::from_str_radix(&e.oid[..2], 16).unwrap_or(256);
        while seen < lead {
            if fanout[seen] as usize != i {
                fanout_ok = false;
            }
            seen += 1;
        }
        if let Some(p) = prev {
            if e.oid.as_str() <= p {
                sorted = false;
            }
        }
        prev = Some(e.oid.as_str());
    }
    while seen < 256 {
        if fanout[seen] as usize != count {
            fanout_ok = false;
        }
        seen += 1;
    }
    if !sorted {
        fanout_ok = false;
        errors.push("index oids are not strictly sorted".into());
    }
    summary.fanout_ok = fanout_ok;
    if !fanout_ok {
        errors.push("fanout table inconsistent with oid leading bytes".into());
    }

    summary.errors = errors;
    summary
}

/// Recompute the CRC for a packed object at `offset` so it can be compared
/// with the value stored in a v2 index.
pub fn crc_for_pack_object(pack: &[u8], offset: u64, end: u64) -> Option<u32> {
    let (o, e) = (offset as usize, end as usize);
    if o > e || e > pack.len() {
        return None;
    }
    Some(crc32(&pack[o..e]))
}
