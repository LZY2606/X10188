//! Git pack index (v2) parser: magic, fanout table, oid/crc32/offset entries.

use crate::gitutil::{oid_hex, Oid};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct PackIndex {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("unsupported index version {0}")]
    UnsupportedVersion(u32),
    #[error("index truncated")]
    Truncated,
    #[error("fanout not monotonic")]
    BadFanout,
}

impl PackIndex {
    pub fn total(&self) -> u32 {
        self.fanout[255]
    }

    pub fn parse(data: &[u8]) -> Result<PackIndex, IndexError> {
        if data.len() < 8 {
            return Err(IndexError::Truncated);
        }
        // v2 magic: \xfftOc
        if data[0] != 0xff || &data[1..4] != b"tOc" {
            return Err(IndexError::UnsupportedVersion(1));
        }
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 {
            return Err(IndexError::UnsupportedVersion(version));
        }
        let mut pos = 8usize;
        let mut fanout = [0u32; 256];
        let mut prev = 0u32;
        for slot in fanout.iter_mut() {
            if pos + 4 > data.len() {
                return Err(IndexError::Truncated);
            }
            *slot = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            if *slot < prev {
                return Err(IndexError::BadFanout);
            }
            prev = *slot;
            pos += 4;
        }
        let n = fanout[255] as usize;
        let need = n
            .checked_mul(20)
            .and_then(|v| v.checked_add(n * 4))
            .and_then(|v| v.checked_add(n * 4))
            .and_then(|v| v.checked_add(20 + 20));
        match need {
            Some(v) if pos + v <= data.len() => {}
            _ => return Err(IndexError::Truncated),
        }
        let oid_base = pos;
        let crc_base = oid_base + n * 20;
        let off_base = crc_base + n * 4;
        let large_base = off_base + n * 4;
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
            let crc32 = u32::from_be_bytes([
                data[crc_base + i * 4],
                data[crc_base + i * 4 + 1],
                data[crc_base + i * 4 + 2],
                data[crc_base + i * 4 + 3],
            ]);
            let raw_off = u32::from_be_bytes([
                data[off_base + i * 4],
                data[off_base + i * 4 + 1],
                data[off_base + i * 4 + 2],
                data[off_base + i * 4 + 3],
            ]);
            let offset = if raw_off & 0x8000_0000 != 0 {
                let li = (raw_off & 0x7fff_ffff) as usize;
                let lp = large_base + li * 8;
                if lp + 8 > data.len() {
                    return Err(IndexError::Truncated);
                }
                u64::from_be_bytes(data[lp..lp + 8].try_into().unwrap())
            } else {
                raw_off as u64
            };
            entries.push(IdxEntry { oid, crc32, offset });
        }
        Ok(PackIndex { fanout, entries })
    }

    pub fn lookup(&self, oid: &Oid) -> Option<&IdxEntry> {
        self.entries.iter().find(|e| &e.oid == oid)
    }

    /// Fanout table as hex-bucket -> cumulative count, for display.
    pub fn fanout_display(&self) -> Vec<(String, u32)> {
        self.fanout
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("{:02x}", i), *v))
            .collect()
    }
}

pub fn oid_hex_of(e: &IdxEntry) -> String {
    oid_hex(&e.oid)
}
