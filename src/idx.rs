//! Parser for git pack index files v2 (`*.idx`).
//!
//! The 256-entry fanout table, sorted oid table, CRC32 table and offset table
//! are all parsed so they can be cross-checked against the pack.

use sha1::{Digest, Sha1};

pub const IDX_V2_MAGIC: [u8; 4] = [0xff, 0x74, 0x4f, 0x63];

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
    /// Set when this index row points at a 64-bit ("large") offset slot.
    pub large_offset: bool,
}

#[derive(Debug, Clone)]
pub struct IdxError {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    /// Exactly 256 cumulative fanout entries.
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// Object count derived from fanout[255].
    pub num_objects: u32,
    pub pack_checksum: [u8; 20],
    pub idx_checksum_stored: [u8; 20],
    pub idx_checksum_computed: [u8; 20],
    pub idx_checksum_ok: bool,
    pub errors: Vec<String>,
}

pub fn parse_idx(data: &[u8]) -> ParsedIdx {
    let mut empty = ParsedIdx {
        fanout: [0u32; 256],
        entries: Vec::new(),
        num_objects: 0,
        pack_checksum: [0u8; 20],
        idx_checksum_stored: [0u8; 20],
        idx_checksum_computed: [0u8; 20],
        idx_checksum_ok: false,
        errors: Vec::new(),
    };

    if data.len() < 8 {
        empty
            .errors
            .push("idx file too small".into());
        return empty;
    }
    if data[..4] != IDX_V2_MAGIC {
        empty
            .errors
            .push("only idx v2 supported (bad magic)".into());
        return empty;
    }
    if &data[4..8] != 2u32.to_be_bytes() {
        empty.errors.push("unsupported idx version".into());
        return empty;
    }

    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let at = 8 + i * 4;
        fanout[i] = u32::from_be_bytes([
            data[at],
            data[at + 1],
            data[at + 2],
            data[at + 3],
        ]);
    }
    let n = fanout[255] as usize;
    let off_oids = 8 + 256 * 4;
    let off_crc = off_oids + n * 20;
    let off_offsets32 = off_crc + n * 4;
    let off_offsets64 = off_offsets32 + n * 4;
    let trailing = 20 + 20;
    if data.len() < off_offsets64 + trailing {
        empty.errors.push(format!(
            "idx truncated: need at least {} bytes for {n} objects, have {}",
            off_offsets64 + trailing,
            data.len()
        ));
        empty.fanout = fanout;
        empty.num_objects = n as u32;
        return empty;
    }

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[off_oids + i * 20..off_oids + (i + 1) * 20]);
        let crc = u32::from_be_bytes([
            data[off_crc + i * 4],
            data[off_crc + i * 4 + 1],
            data[off_crc + i * 4 + 2],
            data[off_crc + i * 4 + 3],
        ]);
        let raw32 = u32::from_be_bytes([
            data[off_offsets32 + i * 4],
            data[off_offsets32 + i * 4 + 1],
            data[off_offsets32 + i * 4 + 2],
            data[off_offsets32 + i * 4 + 3],
        ]);
        let (offset, large) = if raw32 & 0x8000_0000 != 0 {
            let slot = (raw32 & 0x7fff_ffff) as usize;
            let at = off_offsets64 + slot * 8;
            let off64 = u64::from_be_bytes([
                data[at],
                data[at + 1],
                data[at + 2],
                data[at + 3],
                data[at + 4],
                data[at + 5],
                data[at + 6],
                data[at + 7],
            ]);
            (off64, true)
        } else {
            (raw32 as u64, false)
        };
        entries.push(IdxEntry {
            oid,
            offset,
            crc32: crc,
            large_offset: large,
        });
    }

    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[off_offsets64..off_offsets64 + 20]);
    let mut idx_checksum_stored = [0u8; 20];
    idx_checksum_stored.copy_from_slice(&data[off_offsets64 + 20..off_offsets64 + 40]);

    let mut h = Sha1::new();
    h.update(&data[..off_offsets64 + 20]);
    let computed: [u8; 20] = h.finalize().into();
    let ok = computed == idx_checksum_stored;

    // Fanout monotonicity + consistency checks.
    let mut errors = Vec::new();
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(format!("fanout[{i}] decreases"));
            break;
        }
    }
    for i in 0..n.saturating_sub(1) {
        if entries[i].oid >= entries[i + 1].oid {
            errors.push(format!("oid table not strictly sorted at row {i}"));
            break;
        }
    }

    ParsedIdx {
        fanout,
        entries,
        num_objects: n as u32,
        pack_checksum,
        idx_checksum_stored,
        idx_checksum_computed: computed,
        idx_checksum_ok: ok,
        errors,
    }
}

/// Fanout lookup: number of objects whose first byte is <= `b`.
pub fn fanout_le(p: &ParsedIdx, b: u8) -> u32 {
    p.fanout[b as usize]
}
