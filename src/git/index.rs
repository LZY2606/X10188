//! Parser for `.idx` v2 pack index files.

use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub entries: Vec<IdxEntry>,
    pub fanout: [u32; 256],
    pub pack_checksum: [u8; 20],
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdxError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u32),
    FanoutOverflow,
    Truncated,
    BadChecksum,
    DuplicateOid,
}

impl std::fmt::Display for IdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdxError::TooShort => f.write_str("idx shorter than 8-byte header"),
            IdxError::BadMagic => f.write_str("bad idx magic (expected v2 header)"),
            IdxError::UnsupportedVersion(v) => write!(f, "unsupported idx version {v}"),
            IdxError::FanoutOverflow => f.write_str("idx fanout table not monotonic"),
            IdxError::Truncated => f.write_str("idx truncated"),
            IdxError::BadChecksum => f.write_str("idx self-checksum mismatch"),
            IdxError::DuplicateOid => f.write_str("idx contains duplicate oid"),
        }
    }
}

pub fn parse_idx(data: &[u8]) -> Result<IdxFile, IdxError> {
    if data.len() < 8 {
        return Err(IdxError::TooShort);
    }
    if &data[0..4] != b"\xfftOc" {
        // v1 idx files are not supported by this forensic build.
        return Err(IdxError::BadMagic);
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(IdxError::UnsupportedVersion(version));
    }

    let mut pos = 8;
    let mut fanout = [0u32; 256];
    for slot in fanout.iter_mut() {
        if pos + 4 > data.len() {
            return Err(IdxError::Truncated);
        }
        *slot = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
    }
    for w in fanout.windows(2) {
        if w[1] < w[0] {
            return Err(IdxError::FanoutOverflow);
        }
    }
    let n = fanout[255] as usize;
    if fanout[0] > 0 {
        // fanout[0] already counts objects whose first byte is 0, so this is fine;
        // only validate internal monotonic growth.
    }
    let mut prev: Option<[u8; 20]> = None;
    let mut oids: Vec<[u8; 20]> = Vec::with_capacity(n);
    for _ in 0..n {
        if pos + 20 > data.len() {
            return Err(IdxError::Truncated);
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[pos..pos + 20]);
        pos += 20;
        if let Some(p) = prev {
            if oid <= p {
                return Err(IdxError::DuplicateOid);
            }
        }
        prev = Some(oid);
        oids.push(oid);
    }

    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        if pos + 4 > data.len() {
            return Err(IdxError::Truncated);
        }
        crcs.push(u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]));
        pos += 4;
    }

    let mut offsets = Vec::with_capacity(n);
    let mut large_slots = Vec::new();
    for i in 0..n {
        if pos + 4 > data.len() {
            return Err(IdxError::Truncated);
        }
        let raw = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        if raw & 0x8000_0000 != 0 {
            large_slots.push((i, (raw & 0x7fff_ffff) as usize));
            offsets.push(0);
        } else {
            offsets.push(raw as u64);
        }
    }
    for (i, large_index) in large_slots {
        let lp = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + large_index * 8;
        if lp + 8 > data.len() - 40 {
            return Err(IdxError::Truncated);
        }
        offsets[i] = u64::from_be_bytes([
            data[lp], data[lp + 1], data[lp + 2], data[lp + 3], data[lp + 4], data[lp + 5],
            data[lp + 6], data[lp + 7],
        ]);
    }

    // Trailing: 20-byte pack checksum + 20-byte idx checksum.
    if data.len() < pos + 40 {
        return Err(IdxError::Truncated);
    }
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[data.len() - 40..data.len() - 20]);

    let mut h = Sha1::new();
    h.update(&data[..data.len() - 20]);
    let expect = h.finalize();
    if &expect[..] != &data[data.len() - 20..] {
        return Err(IdxError::BadChecksum);
    }

    let entries = oids
        .into_iter()
        .zip(crcs)
        .zip(offsets)
        .map(|((oid, crc32), offset)| IdxEntry { oid, crc32, offset })
        .collect();

    Ok(IdxFile {
        entries,
        fanout,
        pack_checksum,
    })
}

/// Whether the index advertises this exact pack file (compares stored pack checksum).
pub fn idx_matches_pack(idx: &IdxFile, pack: &[u8]) -> bool {
    if pack.len() < 20 {
        return false;
    }
    pack[pack.len() - 20..] == idx.pack_checksum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::builder::{build_index_v2, build_pack, PackObj};
    use crate::git::object::{git_object_id, ObjType};

    #[test]
    fn roundtrip_idx() {
        let blob = b"indexed blob contents";
        let objs = vec![PackObj::base(ObjType::Blob, blob.to_vec())];
        let pack = build_pack(&objs, true);
        let oid = git_object_id(ObjType::Blob, blob);
        let idx = build_index_v2(&[(12, oid)], &pack);
        let parsed = parse_idx(&idx).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].oid, oid);
        assert_eq!(parsed.entries[0].offset, 12);
        assert!(idx_matches_pack(&parsed, &pack));
    }

    #[test]
    fn mismatched_pack_detected() {
        let pack = build_pack(&[PackObj::base(ObjType::Blob, b"a".to_vec())], true);
        let oid = git_object_id(ObjType::Blob, b"a");
        let idx = build_index_v2(&[(12, oid)], &pack);
        let mut other = build_pack(&[PackObj::base(ObjType::Blob, b"different".to_vec())], true);
        other[12] ^= 1; // would corrupt zlib; instead replace trailer comparison:
        let _ = &mut other;
        let parsed = parse_idx(&idx).unwrap();
        // A genuinely different pack has a different trailing checksum.
        let other = build_pack(&[PackObj::base(ObjType::Blob, b"different!!!".to_vec())], true);
        assert!(!idx_matches_pack(&parsed, &other));
    }

    #[test]
    fn tampered_idx_checksum() {
        let pack = build_pack(&[PackObj::base(ObjType::Blob, b"q".to_vec())], true);
        let oid = git_object_id(ObjType::Blob, b"q");
        let mut idx = build_index_v2(&[(12, oid)], &pack);
        let n = idx.len();
        idx[n - 1] ^= 0xff;
        assert_eq!(parse_idx(&idx).unwrap_err(), IdxError::BadChecksum);
    }
}
