//! Parser for Git pack index files (v1 and v2), including fanout tables,
//! CRC table, 32/64-bit offsets and both trailing SHA1 checksums.

use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub version: u32,
    pub entries: Vec<IdxEntry>,
    /// Raw fanout table (cumulative counts per leading byte).
    pub fanout: [u32; 256],
    /// Object counts per leading byte (derived, non-cumulative).
    pub bucket_counts: [u32; 256],
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub computed_idx_checksum: [u8; 20],
    pub idx_checksum_ok: bool,
    pub errors: Vec<String>,
}

impl ParsedIdx {
    pub fn count(&self) -> u32 {
        self.fanout[255]
    }

    pub fn oid_to_offset(&self, oid: &[u8; 20]) -> Option<u64> {
        self.entries.iter().find(|e| &e.oid == oid).map(|e| e.offset)
    }
}

fn u32b(d: &[u8]) -> u32 {
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

pub fn parse_idx(data: &[u8]) -> ParsedIdx {
    let mut p = ParsedIdx {
        version: 0,
        entries: Vec::new(),
        fanout: [0u32; 256],
        bucket_counts: [0u32; 256],
        pack_checksum: [0u8; 20],
        idx_checksum: [0u8; 20],
        computed_idx_checksum: [0u8; 20],
        idx_checksum_ok: false,
        errors: Vec::new(),
    };
    if data.len() < 2 * 20 + 256 * 4 + 8 {
        p.errors
            .push(format!("idx too small: {} bytes", data.len()));
        return p;
    }

    let is_v2 = &data[0..4] == b"\xff\x74\x4f\x63";
    if is_v2 {
        p.version = u32b(&data[4..8]);
        if p.version != 2 {
            p.errors
                .push(format!("unsupported idx v{} (magic present)", p.version));
            return p;
        }
        let fan_start = 8;
        for i in 0..256 {
            p.fanout[i] = u32b(&data[fan_start + i * 4..][..4]);
        }
        let count = p.fanout[255] as usize;
        let mut prev = 0u32;
        for (i, c) in p.fanout.iter().enumerate() {
            if *c < prev {
                p.errors.push("fanout table is not monotonic".into());
            }
            p.bucket_counts[i] = c - prev;
            prev = *c;
        }
        let sha_off = fan_start + 256 * 4;
        let crc_off = sha_off + count * 20;
        let off32_off = crc_off + count * 4;
        let need = off32_off + count * 4 + 40;
        if data.len() < need {
            p.errors
                .push(format!("idx truncated: need {need}, have {}", data.len()));
            return p;
        }
        let mut large_offsets: Vec<u64> = Vec::new();
        let large_table_off = off32_off + count * 4;
        for i in 0..count {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[sha_off + i * 20..][..20]);
            let crc = u32b(&data[crc_off + i * 4..][..4]);
            let o32 = u32b(&data[off32_off + i * 4..][..4]);
            // NB: large offsets are stored in a shared 64-bit table referenced
            // by index; resolve after collecting.
            let offset = if o32 & 0x8000_0000 != 0 {
                let idx = (o32 & 0x7fff_ffff) as usize;
                let p8 = large_table_off + idx * 8;
                if p8 + 8 + 40 > data.len() {
                    p.errors
                        .push(format!("large-offset ref {idx} out of range"));
                    0
                } else {
                    u64::from_be_bytes(data[p8..p8 + 8].try_into().unwrap())
                }
            } else {
                o32 as u64
            };
            if o32 & 0x8000_0000 != 0 {
                large_offsets.push(offset);
            }
            p.entries.push(IdxEntry { oid, offset, crc });
        }
        let _ = large_offsets;

        let checksums_off = data.len() - 40;
        p.pack_checksum
            .copy_from_slice(&data[checksums_off..checksums_off + 20]);
        p.idx_checksum
            .copy_from_slice(&data[checksums_off + 20..]);
        // idx checksum covers the whole file except its own final 20 bytes
        // (which includes the pack checksum that precedes it).
        let mut h = Sha1::new();
        h.update(&data[..data.len() - 20]);
        p.computed_idx_checksum = h.finalize().into();
        p.idx_checksum_ok = p.idx_checksum == p.computed_idx_checksum;
        if !p.idx_checksum_ok {
            p.errors.push("idx trailing SHA1 mismatch".into());
        }
    } else {
        // v1: 256 fanout then (offset u32, oid 20) records; no CRC table.
        p.version = 1;
        for i in 0..256 {
            p.fanout[i] = u32b(&data[i * 4..][..4]);
        }
        let count = p.fanout[255] as usize;
        let mut prev = 0u32;
        for (i, c) in p.fanout.iter().enumerate() {
            if *c < prev {
                p.errors.push("fanout table is not monotonic".into());
            }
            p.bucket_counts[i] = c - prev;
            prev = *c;
        }
        let base = 256 * 4;
        let need = base + count * 24 + 40;
        if data.len() < need {
            p.errors
                .push(format!("v1 idx truncated: need {need}, have {}", data.len()));
            return p;
        }
        for i in 0..count {
            let rec = base + i * 24;
            let offset = u32b(&data[rec..rec + 4]) as u64;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[rec + 4..rec + 24]);
            p.entries.push(IdxEntry {
                oid,
                offset,
                crc: 0,
            });
        }
        let cs = data.len() - 40;
        p.pack_checksum.copy_from_slice(&data[cs..cs + 20]);
        p.idx_checksum.copy_from_slice(&data[cs + 20..]);
        let mut h = Sha1::new();
        h.update(&data[..data.len() - 20]);
        p.computed_idx_checksum = h.finalize().into();
        p.idx_checksum_ok = p.idx_checksum == p.computed_idx_checksum;
        if !p.idx_checksum_ok {
            p.errors.push("idx trailing SHA1 mismatch".into());
        }
    }
    p
}
