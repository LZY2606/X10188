//! Parser for Git pack index (.idx) files, version 2 (and the legacy
//! version 1 magic-less layout).
//!
//! v2 layout: `\377tOc`, u32 version, 256 fanout u32s, N*20-byte oids,
//! N*4-byte CRC32, N*4-byte offsets (high bit => 8-byte large offset
//! table), 20-byte pack checksum, 20-byte self checksum.

use crate::model::error_code;
use crate::model::Oid;
use crate::parse::pack::ParsedPack;
use crc32fast::Hasher as CrcHasher;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IndexIssue {
    pub code: &'static str,
    pub message: String,
    pub entry_index: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub oid: Oid,
    pub offset: u64,
    /// CRC32 claimed by the index.
    pub crc32: u32,
    pub crc_ok: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub version: u32,
    pub count: usize,
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub issues: Vec<IndexIssue>,
    pub pack_checksum: Option<[u8; 20]>,
    pub self_checksum: Option<[u8; 20]>,
    pub pack_checksum_ok: Option<bool>,
    pub self_checksum_ok: Option<bool>,
}

const V2_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

pub fn parse_index(data: &[u8]) -> ParsedIndex {
    if data.len() < 8 {
        return fail(error_code::TRUNCATED, "index shorter than header".into(), None);
    }
    if data[..4] == V2_MAGIC {
        parse_v2(data)
    } else {
        parse_v1(data)
    }
}

fn fail(code: &'static str, message: String, entry_index: Option<usize>) -> ParsedIndex {
    ParsedIndex {
        version: 0,
        count: 0,
        fanout: Vec::new(),
        entries: Vec::new(),
        issues: vec![IndexIssue { code, message, entry_index }],
        pack_checksum: None,
        self_checksum: None,
        pack_checksum_ok: None,
        self_checksum_ok: None,
    }
}

fn parse_v1(data: &[u8]) -> ParsedIndex {
    // Legacy: 256 fanout u32s, then N records of (4-byte offset, 20-byte oid),
    // then 20-byte pack checksum, 20-byte self checksum. No per-entry CRC.
    let mut issues = Vec::new();
    if data.len() < 256 * 4 + 40 {
        return fail(error_code::TRUNCATED, "v1 index too short".into(), None);
    }
    let fanout: Vec<u32> = (0..256).map(|i| u32_at(data, i * 4).unwrap()).collect();
    let count = fanout[255] as usize;
    let records_start = 256 * 4;
    let records_len = count.checked_mul(24);
    let Some(records_len) = records_len else {
        return fail(error_code::TRUNCATED, "v1 record table overflow".into(), None);
    };
    if records_start + records_len + 40 > data.len() {
        return fail(error_code::TRUNCATED, "v1 records/truncated".into(), None);
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let base = records_start + i * 24;
        let offset = u32_at(data, base).unwrap() as u64;
        let oid = Oid::from_bytes(&data[base + 4..base + 24]).unwrap();
        entries.push(IndexEntry { oid, offset, crc32: 0, crc_ok: None });
    }
    let checksum_start = records_start + records_len;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[checksum_start..checksum_start + 20]);
    let mut self_checksum = [0u8; 20];
    self_checksum.copy_from_slice(&data[checksum_start + 20..checksum_start + 40]);

    let mut hasher = Sha1::new();
    hasher.update(&data[..checksum_start + 20]);
    let self_ok: [u8; 20] = hasher.finalize().into();

    if self_ok != self_checksum {
        issues.push(IndexIssue {
            code: error_code::IDX_SELF_CHECKSUM,
            message: "v1 index self checksum mismatch".into(),
            entry_index: None,
        });
    }

    ParsedIndex {
        version: 1,
        count,
        fanout,
        entries,
        issues,
        pack_checksum: Some(pack_checksum),
        self_checksum: Some(self_checksum),
        pack_checksum_ok: None,
        self_checksum_ok: Some(self_ok == self_checksum),
    }
}

fn parse_v2(data: &[u8]) -> ParsedIndex {
    let mut issues = Vec::new();
    let version = match u32_at(data, 4) {
        Some(v) => v,
        None => return fail(error_code::TRUNCATED, "missing version".into(), None),
    };
    if version != 2 {
        issues.push(IndexIssue {
            code: error_code::IDX_VERSION,
            message: format!("unsupported idx version {version}"),
            entry_index: None,
        });
    }
    let fanout: Vec<u32> = (0..256).map(|i| u32_at(data, 8 + i * 4).unwrap_or(0)).collect();
    let count = fanout[255] as usize;

    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + count * 20;
    let off_start = crc_start + count * 4;
    let large_off_start = off_start + count * 4;
    let trailer_start = large_off_start; // adjusted below
    if oid_start + count * 20 > data.len() {
        issues.push(IndexIssue { code: error_code::TRUNCATED, message: "oid table truncated".into(), entry_index: None });
        return build_partial(version, count, fanout, Vec::new(), issues, data, None);
    }

    let mut raw_offsets: Vec<u64> = Vec::with_capacity(count);
    let mut large_needed = 0usize;
    for i in 0..count {
        let v = match u32_at(data, off_start + i * 4) {
            Some(v) => v,
            None => {
                issues.push(IndexIssue { code: error_code::TRUNCATED, message: "offset table truncated".into(), entry_index: Some(i) });
                break;
            }
        };
        if v & 0x8000_0000 != 0 {
            large_needed += 1;
        }
        raw_offsets.push(u64::from(v));
    }

    // Large offset table and checksums: walk through to find trailer.
    let mut large_pos = large_off_start;
    let mut offsets: Vec<u64> = Vec::with_capacity(count);
    for (i, v) in raw_offsets.iter().enumerate() {
        if v & 0x8000_0000 != 0 {
            let idx = (v & 0x7fff_ffff) as usize;
            let at = large_off_start + idx * 8;
            match data.get(at..at + 8) {
                Some(b) => {
                    let hi = u64::from_be_bytes(b[..8].try_into().unwrap());
                    offsets.push(hi);
                    large_pos = large_pos.max(at + 8);
                }
                None => {
                    issues.push(IndexIssue { code: error_code::TRUNCATED, message: "large offset table truncated".into(), entry_index: Some(i) });
                    offsets.push(u64::from(v));
                }
            }
        } else {
            offsets.push(*v);
        }
    }
    let _ = large_needed;

    let trailer = large_pos.max(off_start + count * 4);
    if trailer + 40 > data.len() {
        issues.push(IndexIssue { code: error_code::TRUNCATED, message: "missing idx checksums".into(), entry_index: None });
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let oid = Oid::from_bytes(&data[oid_start + i * 20..oid_start + i * 20 + 20]).unwrap();
        let crc = u32_at(data, crc_start + i * 4).unwrap_or(0);
        let offset = offsets.get(i).copied().unwrap_or(0);
        entries.push(IndexEntry { oid, offset, crc32: crc, crc_ok: None });
    }

    let mut pack_checksum = None;
    let mut self_checksum = None;
    let mut pack_ok = None;
    let mut self_ok = None;
    if trailer + 40 <= data.len() {
        let mut pc = [0u8; 20];
        pc.copy_from_slice(&data[trailer..trailer + 20]);
        let mut sc = [0u8; 20];
        sc.copy_from_slice(&data[trailer + 20..trailer + 40]);
        pack_checksum = Some(pc);
        self_checksum = Some(sc);

        let mut h = Sha1::new();
        h.update(&data[..trailer + 20]);
        let computed_self: [u8; 20] = h.finalize().into();
        self_ok = Some(computed_self == sc);
        if computed_self != sc {
            issues.push(IndexIssue {
                code: error_code::IDX_SELF_CHECKSUM,
                message: "idx self checksum mismatch".into(),
                entry_index: None,
            });
        }
        pack_ok = Some(false); // compared later against the paired pack
    }

    let mut parsed = ParsedIndex {
        version,
        count,
        fanout,
        entries,
        issues,
        pack_checksum,
        self_checksum,
        pack_checksum_ok: pack_ok,
        self_checksum_ok: self_ok,
    };

    // Fanout monotonicity sanity check.
    for (i, pair) in parsed.fanout.windows(2).enumerate() {
        if pair[0] > pair[1] {
            parsed.issues.push(IndexIssue {
                code: error_code::TRUNCATED,
                message: format!("fanout bucket {} decreases ({} > {})", i + 1, pair[0], pair[1]),
                entry_index: None,
            });
            break;
        }
    }

    parsed
}

fn build_partial(
    version: u32,
    count: usize,
    fanout: Vec<u32>,
    entries: Vec<IndexEntry>,
    issues: Vec<IndexIssue>,
    _data: &[u8],
    _at: Option<usize>,
) -> ParsedIndex {
    ParsedIndex {
        version,
        count,
        fanout,
        entries,
        issues,
        pack_checksum: None,
        self_checksum: None,
        pack_checksum_ok: None,
        self_checksum_ok: None,
    }
}

/// Compare the index's per-entry CRC32 values against the actual pack
/// bytes (entry header through end of zlib stream) and check the pack
/// trailer checksum.
pub fn verify_against_pack(
    idx_data: &[u8],
    pack_data: &[u8],
    pack: &ParsedPack,
) -> ParsedIndex {
    let mut parsed = parse_index(idx_data);
    if let Some(idx_pack_sum) = parsed.pack_checksum {
        parsed.pack_checksum_ok = pack.computed_checksum.map(|c| c == idx_pack_sum);
        if let Some(false) = parsed.pack_checksum_ok {
            parsed.issues.push(IndexIssue {
                code: error_code::IDX_PACK_CHECKSUM,
                message: "idx pack checksum does not match this pack".into(),
                entry_index: None,
            });
        }
    }
    if parsed.version != 2 {
        return parsed;
    }

    let by_offset: std::collections::HashMap<u64, &crate::parse::pack::PackEntry> =
        pack.entries.iter().map(|e| (e.header_offset, e)).collect();

    for (i, entry) in parsed.entries.iter_mut().enumerate() {
        let Some(pack_entry) = by_offset.get(&(entry.offset)) else {
            entry.crc_ok = Some(false);
            parsed.issues.push(IndexIssue {
                code: error_code::IDX_OFFSET_UNKNOWN,
                message: format!("idx offset {} not present in pack scan", entry.offset),
                entry_index: Some(i),
            });
            continue;
        };
        let start = entry.offset as usize;
        let end = pack_entry.zlib_end as usize;
        if end > pack_data.len() || start > end {
            entry.crc_ok = Some(false);
            parsed.issues.push(IndexIssue {
                code: error_code::IDX_OFFSET_UNKNOWN,
                message: format!("idx offset {} maps beyond pack", entry.offset),
                entry_index: Some(i),
            });
            continue;
        }
        let mut hasher = CrcHasher::new();
        hasher.update(&pack_data[start..end]);
        let got = hasher.finalize();
        entry.crc_ok = Some(got == entry.crc32);
        if got != entry.crc32 {
            parsed.issues.push(IndexIssue {
                code: error_code::IDX_CRC,
                message: format!("entry {} ({}) CRC32 {:08x} != idx {:08x}", i, entry.oid.short(), got, entry.crc32),
                entry_index: Some(i),
            });
        }
    }
    parsed
}
