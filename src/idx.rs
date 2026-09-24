//! Parser for Git pack index files (v1 and v2 formats).

use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub pack_offset: usize,
    /// v2 only: CRC32 of the packed object byte range.
    pub crc: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IdxWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub version: u8,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub computed_idx_checksum: [u8; 20],
    pub idx_checksum_ok: bool,
    pub warnings: Vec<IdxWarning>,
}

#[derive(Debug)]
pub struct IdxFatal(pub String);
impl std::fmt::Display for IdxFatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "idx: {}", self.0)
    }
}
impl std::error::Error for IdxFatal {}

pub fn count_for_prefix(fanout: &[u32; 256], prefix: u8) -> u32 {
    if prefix == 0 {
        fanout[0]
    } else {
        fanout[prefix as usize] - fanout[prefix as usize - 1]
    }
}

pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx, IdxFatal> {
    let v2_magic = [0xff, 0x74, 0x4f, 0x63];
    if data.len() < 8 {
        return Err(IdxFatal("file shorter than 8 bytes".into()));
    }
    let mut warnings = Vec::new();
    let (version, fanout_bytes_start) = if data[..4] == v2_magic {
        let v = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if v != 2 {
            return Err(IdxFatal(format!("unsupported idx version {}", v)));
        }
        (2u8, 8usize)
    } else {
        // v1 starts directly with the fanout table.
        (1u8, 0usize)
    };

    if data.len() < fanout_bytes_start + 1024 + 40 {
        return Err(IdxFatal("truncated fanout/checksum area".into()));
    }

    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let s = fanout_bytes_start + i * 4;
        fanout[i] = u32::from_be_bytes(data[s..s + 4].try_into().unwrap());
    }
    let n = fanout[255] as usize;
    let mut prev = 0u32;
    for (i, f) in fanout.iter().enumerate() {
        if *f < prev {
            warnings.push(IdxWarning {
                code: "fanout_not_monotonic".into(),
                message: format!("fanout[{}] decreased", i),
            });
        }
        prev = *f;
    }

    let mut entries = Vec::with_capacity(n);
    if version == 2 {
        let oid_start = fanout_bytes_start + 1024;
        let crc_start = oid_start + n * 20;
        let off_start = crc_start + n * 4;
        let (eight_start, expected_end) = if n == 0 {
            (off_start, crc_start)
        } else if data.len() < off_start + n * 4 + 40 {
            return Err(IdxFatal("truncated offset table".into()));
        } else {
            (off_start + n * 4, off_start + n * 4)
        };

        let mut big_offsets: Vec<u64> = Vec::new();
        for i in 0..n {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[oid_start + i * 20..oid_start + (i + 1) * 20]);
            let crc = u32::from_be_bytes(
                data[crc_start + i * 4..crc_start + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            let off_word =
                u32::from_be_bytes(data[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap());
            let pack_offset = if off_word & 0x8000_0000 != 0 {
                let tab_idx = (off_word & 0x7fff_ffff) as usize;
                let p = eight_start + tab_idx * 8;
                if data.len() < p + 8 {
                    return Err(IdxFatal("bad 64-bit offset index".into()));
                }
                u64::from_be_bytes(data[p..p + 8].try_into().unwrap()) as usize
            } else {
                off_word as usize
            };
            if off_word & 0x8000_0000 != 0 {
                big_offsets.push(pack_offset as u64);
            }
            entries.push(IdxEntry {
                oid,
                pack_offset,
                crc: Some(crc),
            });
        }
        let _ = expected_end;
        let _ = big_offsets;
    } else {
        // v1: [offset u32][oid 20] x n right after the fanout.
        let mut p = fanout_bytes_start + 1024;
        for _ in 0..n {
            if data.len() < p + 24 + 40 {
                return Err(IdxFatal("truncated v1 entries".into()));
            }
            let off = u32::from_be_bytes(data[p..p + 4].try_into().unwrap()) as usize;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[p + 4..p + 24]);
            p += 24;
            entries.push(IdxEntry {
                oid,
                pack_offset: off,
                crc: None,
            });
        }
    }

    let end = data.len();
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[end - 40..end - 20]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&data[end - 20..end]);

    let mut hasher = Sha1::new();
    let covered_end = end - 20;
    if version == 1 {
        hasher.update(&data[fanout_bytes_start..covered_end]);
    } else {
        hasher.update(&data[..covered_end]);
    }
    let mut computed_idx = [0u8; 20];
    computed_idx.copy_from_slice(&hasher.finalize());
    if computed_idx != idx_checksum {
        warnings.push(IdxWarning {
            code: "idx_checksum_mismatch".into(),
            message: "idx self checksum does not match".into(),
        });
    }

    Ok(ParsedIdx {
        version,
        fanout,
        entries,
        pack_checksum,
        idx_checksum,
        computed_idx_checksum: computed_idx,
        idx_checksum_ok: computed_idx == idx_checksum,
        warnings,
    })
}
