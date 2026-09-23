//! Parser for Git pack index files (`.idx`), v2 with v1 detection.

use crate::error::{ParseError, ParseResult};
use crate::pack::Cursor;
use crate::types::Oid;
use sha1::{Digest, Sha1};

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: Oid,
    pub idx_checksum: Oid,
    pub idx_checksum_verified: bool,
    pub errors: Vec<crate::types::Evidence>,
}

impl IdxFile {
    pub fn lookup(&self, oid: &Oid) -> Option<&IdxEntry> {
        self.entries
            .binary_search_by(|e| e.oid.cmp(oid))
            .ok()
            .map(|i| &self.entries[i])
    }

    pub fn num_objects(&self) -> u32 {
        self.fanout[255]
    }
}

pub fn parse_idx(buf: &[u8]) -> ParseResult<IdxFile> {
    let mut errors = Vec::new();
    let mut cur = Cursor::new(buf, 0);

    // v2 magic \377tOc, or v1 (starts directly with fanout).
    let first4 = cur.u32_be()?;
    let (version, fanout) = if first4 == 0xff744f63 {
        let v = cur.u32_be()?;
        if v != 2 {
            return Err(ParseError::Unsupported(format!("idx version {v}")));
        }
        let mut fan = [0u32; 256];
        for f in fan.iter_mut() {
            *f = cur.u32_be()?;
        }
        (2u32, fan)
    } else {
        // v1: first4 is fanout[0].
        let mut fan = [0u32; 256];
        fan[0] = first4;
        for f in fan.iter_mut().skip(1) {
            *f = cur.u32_be()?;
        }
        (1u32, fan)
    };

    let count = fanout[255] as usize;
    // Fanout monotonicity check.
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(crate::types::Evidence {
                code: "fanout_nonmonotonic".into(),
                message: format!("fanout[{i}] < fanout[{}]", i - 1),
                offset: None,
                expected: Some(fanout[i - 1].to_string()),
                actual: Some(fanout[i].to_string()),
            });
        }
    }

    let mut entries = Vec::with_capacity(count);
    if version == 2 {
        let oid_start = cur.pos();
        let mut oids = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = cur.take(20)?;
            oids.push(Oid::from_bytes(raw).expect("20 bytes"));
        }
        let mut crcs = Vec::with_capacity(count);
        for _ in 0..count {
            crcs.push(cur.u32_be()?);
        }
        let mut offsets = Vec::with_capacity(count);
        let mut large: Vec<u64> = Vec::new();
        for _ in 0..count {
            offsets.push(cur.u32_be()?);
        }
        for (i, off) in offsets.iter().enumerate() {
            if off & 0x8000_0000 != 0 {
                let idx = (off & 0x7fff_ffff) as usize;
                let raw = cur.take(8)?;
                let v = u64::from_be_bytes(raw.try_into().unwrap());
                large.push(v);
                offsets[i] = (0x8000_0000u32 | (large.len() as u32 - 1)) as u32;
                let _ = idx;
            }
        }
        // Resolve large offsets.
        for (i, off) in offsets.iter().enumerate() {
            let real = if off & 0x8000_0000 != 0 {
                let idx = (off & 0x7fff_ffff) as usize;
                large.get(idx).copied().unwrap_or_else(|| {
                    errors.push(crate::types::Evidence::new(
                        "bad_large_offset",
                        format!("large-offset table index {idx} out of range"),
                    ));
                    0
                })
            } else {
                *off as u64
            };
            entries.push(IdxEntry {
                oid: oids[i],
                crc32: crcs[i],
                offset: real,
            });
        }
        let _ = oid_start;
        let pack_raw = cur.take(20)?;
        let pack_checksum = Oid::from_bytes(pack_raw).expect("20 bytes");
        let idx_raw = cur.take(20)?;
        let idx_checksum = Oid::from_bytes(idx_raw).expect("20 bytes");
        let mut h = Sha1::new();
        h.update(&buf[..buf.len() - 20]);
        let verified = h.finalize().as_slice() == idx_raw;
        if !verified {
            errors.push(crate::types::Evidence {
                code: "idx_checksum".into(),
                message: "idx trailer SHA-1 mismatch".into(),
                offset: Some((buf.len() - 20) as u64),
                expected: Some(Oid::from_bytes(&h.finalize_reset()).unwrap().hex()),
                actual: Some(idx_checksum.hex()),
            });
        }
        Ok(IdxFile {
            version,
            fanout,
            entries,
            pack_checksum,
            idx_checksum,
            idx_checksum_verified: verified,
            errors,
        })
    } else {
        // v1: interleaved (offset u32, oid) pairs, then pack+idx checksums.
        for _ in 0..count {
            let off = cur.u32_be()?;
            let raw = cur.take(20)?;
            entries.push(IdxEntry {
                oid: Oid::from_bytes(raw).expect("20 bytes"),
                crc32: 0,
                offset: off as u64,
            });
        }
        let pack_raw = cur.take(20)?;
        let idx_raw = cur.take(20)?;
        let mut h = Sha1::new();
        h.update(&buf[..buf.len() - 20]);
        let verified = h.finalize().as_slice() == idx_raw;
        Ok(IdxFile {
            version,
            fanout,
            entries,
            pack_checksum: Oid::from_bytes(pack_raw).expect("20 bytes"),
            idx_checksum: Oid::from_bytes(idx_raw).expect("20 bytes"),
            idx_checksum_verified: verified,
            errors,
        })
    }
}

/// Cross-check an idx against a parsed pack: offsets must exist, CRCs must
/// match, and the pack checksum stored in the idx must equal the pack trailer.
pub fn cross_check(idx: &IdxFile, pack: &crate::pack::PackFile, buf: &[u8]) -> Vec<crate::types::Evidence> {
    let mut out = Vec::new();
    if idx.pack_checksum != pack.checksum {
        out.push(crate::types::Evidence {
            code: "idx_pack_mismatch".into(),
            message: "idx references a different pack (checksum mismatch)".into(),
            offset: None,
            expected: Some(idx.pack_checksum.hex()),
            actual: Some(pack.checksum.hex()),
        });
    }
    if idx.num_objects() as usize != pack.entries.len() {
        out.push(crate::types::Evidence {
            code: "idx_count_mismatch".into(),
            message: format!(
                "idx lists {} objects, pack contains {}",
                idx.num_objects(),
                pack.entries.len()
            ),
            offset: None,
            expected: Some(idx.num_objects().to_string()),
            actual: Some(pack.entries.len().to_string()),
        });
    }
    for e in &idx.entries {
        match pack.entry_at_offset(e.offset) {
            None => out.push(crate::types::Evidence {
                code: "idx_offset_missing".into(),
                message: format!("idx offset {} for {} has no pack entry", e.offset, e.oid),
                offset: Some(e.offset),
                expected: None,
                actual: None,
            }),
            Some(entry) => {
                // CRC32 covers header + compressed bytes of the entry.
                let start = entry.entry_offset as usize;
                let end = entry.data_end as usize;
                if end <= buf.len() {
                    let actual = crc32fast::hash(&buf[start..end]);
                    if actual != e.crc32 {
                        out.push(crate::types::Evidence {
                            code: "crc_mismatch".into(),
                            message: format!(
                                "crc32 of entry {} at offset {} does not match idx",
                                e.oid, e.offset
                            ),
                            offset: Some(e.offset),
                            expected: Some(format!("{:08x}", e.crc32)),
                            actual: Some(format!("{actual:08x}")),
                        });
                    }
                }
            }
        }
    }
    out
}
