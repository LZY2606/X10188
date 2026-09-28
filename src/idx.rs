//! Parser for Git pack index files (version 2).
//!
//! Layout:
//!   \xff t O c | 0x00000002
//!   fanout[256] (u32, cumulative)
//!   oids[N]     (20 bytes each, sorted)
//!   crc32[N]    (u32)
//!   offsets[N]  (u32; high bit => 8-byte large-offset table index)
//!   (optional 8-byte offsets)
//!   pack_sha1[20] | idx_sha1[20]

use crate::error::{Error, Result};
use crate::models::Issue;
use crate::oid::Oid;
use crate::pack::IDX_V2_MAGIC;

#[derive(Clone, Debug)]
pub struct IdxRecord {
    pub oid: Oid,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub records: Vec<IdxRecord>,
    /// SHA-1 of the corresponding pack, per the index trailer.
    pub pack_checksum: Option<Oid>,
    pub idx_checksum_ok: bool,
    pub issues: Vec<Issue>,
}

fn u32b(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64b(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes([
        b[at], b[at + 1], b[at + 2], b[at + 3], b[at + 4], b[at + 5], b[at + 6], b[at + 7],
    ])
}

pub fn parse_idx(buf: &[u8]) -> Result<ParsedIdx> {
    let mut issues = Vec::new();
    if buf.len() < 8 {
        return Err(Error::Format("idx shorter than 8-byte preamble".into()));
    }
    if buf[0..4] != IDX_V2_MAGIC {
        return Err(Error::Format(
            "not an idx v2 file (legacy v1 indexes are unsupported)".into(),
        ));
    }
    let version = u32b(buf, 4);
    if version != 2 {
        return Err(Error::Format(format!("unsupported idx version {version}")));
    }

    let fanout_start = 8usize;
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32b(buf, fanout_start + i * 4);
    }
    let n = fanout[255] as usize;

    let mut off = fanout_start + 256 * 4;
    let oid_start = off;
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 20 > buf.len() {
            return Err(Error::Format("idx truncated in oid table".into()));
        }
        oids.push(Oid::from_bytes(&buf[off..off + 20]).unwrap());
        off += 20;
    }

    let crc_start = off;
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 4 > buf.len() {
            return Err(Error::Format("idx truncated in crc table".into()));
        }
        crcs.push(u32b(buf, off));
        off += 4;
    }

    let small_off_start = off;
    let mut small = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 4 > buf.len() {
            return Err(Error::Format("idx truncated in offset table".into()));
        }
        small.push(u32b(buf, off));
        off += 4;
    }

    // Resolve offsets, expanding large-offset table entries as encountered.
    let mut records = Vec::with_capacity(n);
    let mut large_cursor = off;
    for i in 0..n {
        let raw = small[i];
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let at = large_cursor + idx * 8;
            if at + 8 > buf.len() {
                return Err(Error::Format("idx large-offset table out of range".into()));
            }
            u64b(buf, at)
        } else {
            raw as u64
        };
        records.push(IdxRecord { oid: oids[i], offset, crc32: crcs[i] });
    }

    // The large offset table (if any) sits between small offsets and trailers.
    let has_large = small.iter().any(|&v| v & 0x8000_0000 != 0);
    let trailer_base = if has_large {
        let max_idx = small
            .iter()
            .filter(|&&v| v & 0x8000_0000 != 0)
            .map(|&v| (v & 0x7fff_ffff) as usize)
            .max()
            .unwrap_or(0);
        large_cursor + (max_idx + 1) * 8
    } else {
        off
    };

    let pack_checksum = if trailer_base + 40 <= buf.len() {
        Some(Oid::from_bytes(&buf[trailer_base..trailer_base + 20]).unwrap())
    } else {
        issues.push(Issue::error("idx_trailer", "idx missing checksum trailers".into()));
        None
    };

    // idx self-checksum: SHA-1 over everything before the final 20 bytes.
    let idx_checksum_ok = if buf.len() >= 40 {
        use sha1::{Digest, Sha1};
        let body = &buf[..buf.len() - 20];
        let stored = &buf[buf.len() - 20..];
        let mut h = Sha1::new();
        h.update(body);
        h.finalize().as_slice() == stored
    } else {
        false
    };
    if !idx_checksum_ok {
        issues.push(Issue::error("idx_checksum", "idx self-checksum mismatch".into()));
    }

    let _ = (oid_start, crc_start, small_off_start);

    // Validate fanout monotonicity and coverage.
    if fanout[255] as usize != n || fanout.windows(2).any(|w| w[0] > w[1]) {
        issues.push(Issue::error("fanout", "fanout table not monotonic / count mismatch".into()));
    }
    // Validate oids sorted.
    if oids.windows(2).any(|w| w[0] >= w[1]) {
        issues.push(Issue::warn("oid_order", "idx oid table not strictly sorted".into()));
    }

    Ok(ParsedIdx { fanout, records, pack_checksum, idx_checksum_ok, issues })
}
