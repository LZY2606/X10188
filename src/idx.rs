//! Parser for Git pack index files (v2 with v1 fallback).

use crate::models::Evidence;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub version: u32,
    pub count: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: [u8; 20],
    pub idx_checksum_declared: [u8; 20],
    pub idx_checksum_ok: bool,
    pub fanout_ok: bool,
    pub sorted_ok: bool,
    pub evidence: Vec<Evidence>,
}

fn u32be(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

pub fn parse_idx(data: &[u8]) -> ParsedIdx {
    let mut evidence = Vec::new();
    let mut empty = ParsedIdx {
        version: 0,
        count: 0,
        fanout: [0u32; 256],
        entries: Vec::new(),
        pack_checksum: [0u8; 20],
        idx_checksum_declared: [0u8; 20],
        idx_checksum_ok: false,
        fanout_ok: false,
        sorted_ok: false,
        evidence: Vec::new(),
    };

    if data.len() < 256 * 4 + 40 {
        evidence.push(Evidence::new("idx_too_short", "index shorter than fanout + checksums"));
        empty.evidence = evidence;
        return empty;
    }

    let is_v2 = data.len() >= 8 && &data[0..4] == b"\xfftOc" && u32be(data, 4) == 2;
    if is_v2 {
        parse_idx_v2(data)
    } else {
        parse_idx_v1(data)
    }
}

fn check_fanout(fanout: &[u32; 256], count: u32) -> bool {
    let mut prev = 0u32;
    for (i, &v) in fanout.iter().enumerate() {
        if v < prev {
            return false;
        }
        if i == 255 && v != count {
            return false;
        }
        prev = v;
    }
    true
}

fn verify_idx_checksum(data: &[u8], declared: &[u8; 20]) -> bool {
    let body_end = data.len() - 20;
    let mut hasher = Sha1::new();
    hasher.update(&data[..body_end]);
    let computed: [u8; 20] = hasher.finalize().into();
    &computed == declared
}

fn parse_idx_v2(data: &[u8]) -> ParsedIdx {
    let mut evidence = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(data, 8 + i * 4);
    }
    let count = fanout[255];
    let n = count as usize;

    let mut p = ParsedIdx {
        version: 2,
        count,
        fanout,
        entries: Vec::new(),
        pack_checksum: [0u8; 20],
        idx_checksum_declared: [0u8; 20],
        idx_checksum_ok: false,
        fanout_ok: false,
        sorted_ok: false,
        evidence: Vec::new(),
    };

    let need = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + 40;
    if data.len() < need {
        evidence.push(Evidence::new(
            "idx_truncated",
            format!("v2 index needs {} bytes for {} entries, has {}", need, n, data.len()),
        ));
        p.evidence = evidence;
        return p;
    }

    let oid_tbl = 8 + 256 * 4;
    let crc_tbl = oid_tbl + n * 20;
    let off32_tbl = crc_tbl + n * 4;
    let mut off64_tbl = off32_tbl + n * 4;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_tbl + i * 20..oid_tbl + (i + 1) * 20]);
        let crc = u32be(data, crc_tbl + i * 4);
        let raw = u32be(data, off32_tbl + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            let slot = (raw & 0x7fff_ffff) as usize;
            let at = off64_tbl + slot * 8;
            if at + 8 > data.len() - 40 {
                evidence.push(Evidence::new(
                    "idx_offset64_oob",
                    format!("entry {} references missing 64-bit offset slot {}", i, slot),
                ));
                0
            } else {
                u64::from_be_bytes([
                    data[at], data[at + 1], data[at + 2], data[at + 3],
                    data[at + 4], data[at + 5], data[at + 6], data[at + 7],
                ])
            }
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, offset, crc32: crc });
    }

    // Count 64-bit slots actually present (they sit before the checksums).
    let pack_sha_at = data.len() - 40;
    off64_tbl = off64_tbl; // keep position documented
    let _ = off64_tbl;

    let sorted_ok = entries.windows(2).all(|w| w[0].oid < w[1].oid);
    if !sorted_ok {
        evidence.push(Evidence::new("idx_not_sorted", "oid table is not strictly sorted"));
    }
    let fanout_ok = check_fanout(&fanout, count);
    if !fanout_ok {
        evidence.push(Evidence::new(
            "bad_fanout",
            "fanout table is not monotonic or final bucket != object count",
        ));
    }

    p.pack_checksum.copy_from_slice(&data[pack_sha_at..pack_sha_at + 20]);
    p.idx_checksum_declared.copy_from_slice(&data[pack_sha_at + 20..]);
    p.idx_checksum_ok = verify_idx_checksum(data, &p.idx_checksum_declared);
    if !p.idx_checksum_ok {
        evidence.push(Evidence::new("idx_checksum_mismatch", "index trailing sha1 does not match body"));
    }

    p.entries = entries;
    p.sorted_ok = sorted_ok;
    p.fanout_ok = fanout_ok;
    p.evidence = evidence;
    p
}

fn parse_idx_v1(data: &[u8]) -> ParsedIdx {
    let mut evidence = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(data, i * 4);
    }
    let count = fanout[255];
    let n = count as usize;

    let mut p = ParsedIdx {
        version: 1,
        count,
        fanout,
        entries: Vec::new(),
        pack_checksum: [0u8; 20],
        idx_checksum_declared: [0u8; 20],
        idx_checksum_ok: false,
        fanout_ok: false,
        sorted_ok: false,
        evidence: Vec::new(),
    };

    let need = 256 * 4 + n * 4 + n * 20 + 40;
    if data.len() < need {
        evidence.push(Evidence::new(
            "idx_truncated",
            format!("v1 index needs {} bytes for {} entries, has {}", need, n, data.len()),
        ));
        p.evidence = evidence;
        return p;
    }

    let off_tbl = 256 * 4;
    let oid_tbl = off_tbl + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let offset = u32be(data, off_tbl + i * 4) as u64;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_tbl + i * 20..oid_tbl + (i + 1) * 20]);
        entries.push(IdxEntry { oid, offset, crc32: 0 });
    }

    let pack_sha_at = oid_tbl + n * 20;
    p.pack_checksum.copy_from_slice(&data[pack_sha_at..pack_sha_at + 20]);
    p.idx_checksum_declared.copy_from_slice(&data[pack_sha_at + 20..]);
    p.idx_checksum_ok = verify_idx_checksum(data, &p.idx_checksum_declared);
    if !p.idx_checksum_ok {
        evidence.push(Evidence::new("idx_checksum_mismatch", "index trailing sha1 does not match body"));
    }

    let sorted_ok = entries.windows(2).all(|w| w[0].oid < w[1].oid);
    if !sorted_ok {
        evidence.push(Evidence::new("idx_not_sorted", "oid table is not strictly sorted"));
    }
    let fanout_ok = check_fanout(&fanout, count);
    if !fanout_ok {
        evidence.push(Evidence::new("bad_fanout", "fanout table is inconsistent with object count"));
    }

    p.entries = entries;
    p.sorted_ok = sorted_ok;
    p.fanout_ok = fanout_ok;
    p.evidence = evidence;
    p
}
