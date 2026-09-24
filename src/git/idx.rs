//! Pack index parser (v1 and v2) including the 256-entry fanout table.

use super::types::OID_LEN;
use crate::error::{Error, Result};

const FANOUT_LEN: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct IdxRecord {
    pub offset: u64,
    pub oid: [u8; OID_LEN],
    /// CRC32 as recorded by the index (always present in v2; v1 has none).
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxImage {
    pub version: u32,
    pub fanout: [u32; FANOUT_LEN],
    pub count: u32,
    pub records: Vec<IdxRecord>,
    pub pack_checksum: [u8; OID_LEN],
    pub idx_checksum: [u8; OID_LEN],
    pub has_crc: bool,
    pub parse_error: Option<String>,
}

impl IdxImage {
    pub fn record_at(&self, offset: u64) -> Option<&IdxRecord> {
        self.records.iter().find(|r| r.offset == offset)
    }
    pub fn record_of(&self, oid: &[u8; OID_LEN]) -> Option<&IdxRecord> {
        self.records.iter().find(|r| &r.oid == oid)
    }
}

pub fn parse_idx(data: &[u8]) -> Result<IdxImage> {
    if data.len() < 8 {
        return Err(Error::bad("index too short"));
    }
    if &data[0..4] == b"\xfftOc" {
        parse_v2(data)
    } else {
        parse_v1(data)
    }
}

fn parse_v2(data: &[u8]) -> Result<IdxImage> {
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::parse(format!("unsupported idx version {version}")));
    }
    let fan_start = 8usize;
    let mut fanout = [0u32; FANOUT_LEN];
    for i in 0..FANOUT_LEN {
        fanout[i] = u32::from_be_bytes(
            data[fan_start + i * 4..fan_start + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
    }
    let count = fanout[255];
    let n = count as usize;
    let mut parse_error = None;
    if fan_start + FANOUT_LEN * 4 + n * OID_LEN > data.len() {
        return Err(Error::bad("idx: fanout claims more names than file holds"));
    }
    let names_start = fan_start + FANOUT_LEN * 4;
    let crc_start = names_start + n * OID_LEN;
    let off_start = crc_start + n * 4;
    let need = off_start + n * 4 + 2 * OID_LEN;
    if need > data.len() {
        return Err(Error::bad("idx: truncated crc/offset/checksum tables"));
    }

    let mut records = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; OID_LEN];
        oid.copy_from_slice(&data[names_start + i * OID_LEN..names_start + (i + 1) * OID_LEN]);
        let crc = u32::from_be_bytes(
            data[crc_start + i * 4..crc_start + i * 4 + 4].try_into().unwrap(),
        );
        let off_raw = u32::from_be_bytes(
            data[off_start + i * 4..off_start + i * 4 + 4].try_into().unwrap(),
        );
        let offset = if off_raw & 0x8000_0000 != 0 {
            let large_index = (off_raw & 0x7fff_ffff) as usize;
            let lo = off_start + n * 4 + large_index * 8;
            if lo + 8 > data.len() - 2 * OID_LEN {
                parse_error = Some(format!("idx: 64-bit offset table overrun at {i}"));
                0u64
            } else {
                u64::from_be_bytes(data[lo..lo + 8].try_into().unwrap())
            }
        } else {
            off_raw as u64
        };
        records.push(IdxRecord { offset, oid, crc32: crc });
    }

    let tail = data.len() - 2 * OID_LEN;
    let mut pack_checksum = [0u8; OID_LEN];
    pack_checksum.copy_from_slice(&data[tail..tail + OID_LEN]);
    let mut idx_checksum = [0u8; OID_LEN];
    idx_checksum.copy_from_slice(&data[tail + OID_LEN..]);

    for w in fanout.windows(2) {
        if w[1] < w[0] {
            parse_error = Some("idx: fanout table is not monotone".into());
            break;
        }
    }

    Ok(IdxImage {
        version: 2,
        fanout,
        count,
        records,
        pack_checksum,
        idx_checksum,
        has_crc: true,
        parse_error,
    })
}

/// v1: 256 fanout u32, then that many (offset:u32, oid:20) records sorted by
/// sha1; no CRC table; trailer holds the pack checksum only.
fn parse_v1(data: &[u8]) -> Result<IdxImage> {
    let fan_start = 0usize;
    let mut fanout = [0u32; FANOUT_LEN];
    for i in 0..FANOUT_LEN {
        fanout[i] = u32::from_be_bytes(
            data[fan_start + i * 4..fan_start + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
    }
    let count = fanout[255];
    let n = count as usize;
    let rec_start = fan_start + FANOUT_LEN * 4;
    let need = rec_start + n * 24 + OID_LEN;
    if need > data.len() {
        return Err(Error::bad("idx v1: truncated records"));
    }
    let mut records = Vec::with_capacity(n);
    for i in 0..n {
        let p = rec_start + i * 24;
        let offset = u32::from_be_bytes(data[p..p + 4].try_into().unwrap()) as u64;
        let mut oid = [0u8; OID_LEN];
        oid.copy_from_slice(&data[p + 4..p + 24]);
        records.push(IdxRecord { offset, oid, crc32: 0 });
    }
    let mut pack_checksum = [0u8; OID_LEN];
    pack_checksum.copy_from_slice(&data[rec_start + n * 24..rec_start + n * 24 + OID_LEN]);
    Ok(IdxImage {
        version: 1,
        fanout,
        count,
        records,
        pack_checksum,
        idx_checksum: [0u8; OID_LEN],
        has_crc: false,
        parse_error: None,
    })
}
