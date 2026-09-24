//! Parsers for Git packfiles (`PACK`) and v2 `.idx` files, implemented from
//! scratch. Parsing records raw offsets and compressed (zlib) boundaries.

use crate::error::{Error, Result};
use crate::git::{
    inflate_zlib, read_ofs_distance, read_oid, read_pack_entry_header, ObjType,
};
use serde::Serialize;

pub const PACK_SIG: &[u8; 4] = b"PACK";

#[derive(Debug, Clone, Serialize)]
pub struct PackEntry {
    pub index: usize,
    pub kind: ObjType,
    pub raw_type_code: u8,
    pub offset: u64,
    pub header_end: u64,
    pub data_start: u64,
    pub data_end: u64, // zlib boundary
    pub compressed_len: u64,
    pub declared_size: u64,
    pub actual_size: u64,
    /// inflated payload. For ofs/ref delta this is the *delta* bytes.
    pub payload: Vec<u8>,
    pub crc32: u32,
    // delta linkage
    pub base_offset: Option<u64>,
    pub base_oid_hex: Option<String>,
}

#[derive(Debug)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub data: Vec<u8>,
    pub trailer_sha: [u8; 20],
    pub computed_sha: [u8; 20],
}

pub fn parse_pack(data: Vec<u8>) -> Result<PackFile> {
    if data.len() < 12 + 20 {
        return Err(Error::BadPack("file shorter than pack header+trailer".into()));
    }
    if &data[0..4] != PACK_SIG {
        return Err(Error::BadPack("missing PACK signature".into()));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Unsupported(format!("pack version {version} (only v2)")));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());

    let mut entries = Vec::with_capacity(count as usize);
    let mut pos = 12usize;
    for index in 0..count as usize {
        let offset = pos;
        let (type_code, declared_size, after_header) = read_pack_entry_header(&data, pos)?;
        let kind = ObjType::from_pack_code(type_code)?;
        let mut data_start = after_header;
        let mut base_offset = None;
        let mut base_oid_hex = None;

        match kind {
            ObjType::OfsDelta => {
                let (distance, after) = read_ofs_distance(&data, after_header)?;
                if distance as usize > offset {
                    return Err(Error::OfsOutOfRange {
                        at: offset as u64,
                        negative_offset: distance,
                    });
                }
                base_offset = Some((offset - distance as usize) as u64);
                data_start = after;
            }
            ObjType::RefDelta => {
                let oid = read_oid(&data, after_header)?;
                base_oid_hex = Some(hex::encode(oid));
                data_start = after_header + 20;
            }
            _ => {}
        }

        let (payload, consumed) = inflate_zlib(&data, data_start)?;
        let actual_size = match kind {
            ObjType::OfsDelta | ObjType::RefDelta => payload.len() as u64,
            _ => payload.len() as u64,
        };
        if !matches!(kind, ObjType::OfsDelta | ObjType::RefDelta)
            && actual_size != declared_size
        {
            return Err(Error::SizeMismatch {
                declared: declared_size,
                actual: actual_size,
            });
        }
        let data_end = data_start + consumed;
        let crc = crc32(&data[offset..data_end]);
        entries.push(PackEntry {
            index,
            kind,
            raw_type_code: type_code,
            offset: offset as u64,
            header_end: after_header as u64,
            data_start: data_start as u64,
            data_end: data_end as u64,
            compressed_len: (data_end - offset) as u64,
            declared_size,
            actual_size,
            payload,
            crc32: crc,
            base_offset,
            base_oid_hex,
        });
        pos = data_end;
    }

    if pos + 20 != data.len() {
        return Err(Error::BadPack(format!(
            "entries end at {pos}, but file has {} bytes (trailer misaligned)",
            data.len()
        )));
    }
    let mut trailer_sha = [0u8; 20];
    trailer_sha.copy_from_slice(&data[pos..pos + 20]);
    let computed = sha1_digest(&data[..pos]);
    if computed != trailer_sha {
        return Err(Error::ChecksumMismatch(format!(
            "pack trailer {} != computed {}",
            hex::encode(trailer_sha),
            hex::encode(computed)
        )));
    }

    Ok(PackFile {
        version,
        count,
        entries,
        data,
        trailer_sha,
        computed_sha: computed,
    })
}

// ---------------- .idx v2 ----------------

#[derive(Debug, Clone, Serialize)]
pub struct IndexEntry {
    pub order: usize,
    pub oid_hex: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fanout {
    /// fanout[b] = number of objects whose first byte <= b
    pub table: [u32; 256],
    pub total: u32,
}

#[derive(Debug)]
pub struct IndexFile {
    pub fanout: Fanout,
    pub entries: Vec<IndexEntry>, // sorted by oid
    pub pack_sha: [u8; 20],
    pub idx_sha: [u8; 20],
    pub data: Vec<u8>,
}

pub fn parse_index(data: Vec<u8>) -> Result<IndexFile> {
    if data.len() < 8 {
        return Err(Error::BadIndex("idx too short".into()));
    }
    // v2 magic + version
    if &data[0..4] != b"\xfftOc" {
        return Err(Error::Unsupported("only idx v2 supported".into()));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Unsupported(format!("idx version {version}")));
    }
    let mut table = [0u32; 256];
    for b in 0..256 {
        let p = 8 + b * 4;
        table[b] = u32::from_be_bytes(data[p..p + 4].try_into().unwrap());
    }
    let total = table[255];
    // Validate monotonic fanout.
    for b in 1..256 {
        if table[b] < table[b - 1] {
            return Err(Error::BadIndex(format!(
                "fanout not monotonic at byte {b}"
            )));
        }
    }
    let n = total as usize;
    let mut offsets = Vec::with_capacity(n);
    let mut crcs = Vec::with_capacity(n);
    let mut oids: Vec<[u8; 20]> = Vec::with_capacity(n);

    let sha_table = 8 + 256 * 4;
    let crc_table = sha_table + n * 20;
    let off_table = crc_table + n * 4;
    let large_table_hint = off_table + n * 4;

    for i in 0..n {
        let p = sha_table + i * 20;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        oids.push(oid);
    }
    // oids must be sorted ascending in a valid idx
    for w in oids.windows(2) {
        if w[0] >= w[1] {
            return Err(Error::BadIndex("sha table not strictly sorted".into()));
        }
    }
    for i in 0..n {
        let p = crc_table + i * 4;
        crcs.push(u32::from_be_bytes(data[p..p + 4].try_into().unwrap()));
    }
    let mut large_count = 0usize;
    for i in 0..n {
        let p = off_table + i * 4;
        let raw = u32::from_be_bytes(data[p..p + 4].try_into().unwrap());
        if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let lp = large_table_hint + idx * 8;
            if lp + 8 > data.len() {
                return Err(Error::BadIndex("large offset table overrun".into()));
            }
            offsets.push(u64::from_be_bytes(data[lp..lp + 8].try_into().unwrap()));
            large_count += 1;
        } else {
            offsets.push(raw as u64);
        }
    }
    let trailer_start = large_table_hint + large_count * 8;
    if trailer_start + 40 != data.len() {
        return Err(Error::BadIndex(format!(
            "idx trailer misaligned ({trailer_start} + 40 vs {})",
            data.len()
        )));
    }
    let mut pack_sha = [0u8; 20];
    pack_sha.copy_from_slice(&data[trailer_start..trailer_start + 20]);
    let mut idx_sha = [0u8; 20];
    idx_sha.copy_from_slice(&data[trailer_start + 20..trailer_start + 40]);
    let computed_idx = sha1_digest(&data[..trailer_start + 20]);
    if computed_idx != idx_sha {
        return Err(Error::ChecksumMismatch(format!(
            "idx trailer {} != computed {}",
            hex::encode(idx_sha),
            hex::encode(computed_idx)
        )));
    }

    let entries = (0..n)
        .map(|i| IndexEntry {
            order: i,
            oid_hex: hex::encode(oids[i]),
            offset: offsets[i],
            crc32: crcs[i],
        })
        .collect();

    Ok(IndexFile {
        fanout: Fanout { table, total },
        entries,
        pack_sha,
        idx_sha,
        data,
    })
}

// ---------------- hashing/crc ----------------

use sha1::{Digest, Sha1};

pub fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

// Standard CRC-32 (IEEE), the same polynomial Git uses for idx crc tables.
pub fn crc32(buf: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
