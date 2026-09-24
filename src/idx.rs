//! Git pack index (.idx) parsing: v1 and v2 formats, fanout table, CRC32s,
//! 31/63-bit offsets, and the pack checksum used to pair an idx with a pack.

use crate::hexutil;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: Option<u32>,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub version: u32,
    /// Cumulative object counts per first-byte bucket (256 entries).
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    /// sha1 of the pack file this index belongs to.
    pub pack_checksum: String,
    pub self_checksum_ok: bool,
}

pub fn parse_idx(buf: &[u8]) -> Result<IdxFile, String> {
    if buf.len() < 4 * 256 + 20 {
        return Err("file too small for an index".into());
    }
    if buf[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        parse_v2(buf)
    } else {
        parse_v1(buf)
    }
}

fn parse_v2(buf: &[u8]) -> Result<IdxFile, String> {
    if buf.len() < 8 + 4 * 256 + 40 {
        return Err("truncated v2 index".into());
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if version != 2 {
        return Err(format!("unsupported index version {version}"));
    }
    let mut fanout = Vec::with_capacity(256);
    let mut pos = 8;
    for _ in 0..256 {
        fanout.push(u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]));
        pos += 4;
    }
    let n = fanout[255] as usize;
    let need = pos + n * 20 + n * 4 + n * 4 + 20 + 20;
    if buf.len() < need {
        return Err(format!(
            "truncated v2 index: need at least {need} bytes, have {}",
            buf.len()
        ));
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(hexutil::encode(&buf[pos..pos + 20]));
        pos += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]));
        pos += 4;
    }
    let mut offsets = Vec::with_capacity(n);
    let mut large_idx = Vec::new();
    for _ in 0..n {
        let v = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        if v & 0x8000_0000 != 0 {
            large_idx.push((offsets.len(), (v & 0x7fff_ffff) as usize));
            offsets.push(0u64);
        } else {
            offsets.push(v as u64);
        }
    }
    let large_base = pos;
    for (slot, li) in large_idx {
        let p = large_base + li * 8;
        if p + 8 > buf.len() {
            return Err("truncated 64-bit offset table".into());
        }
        offsets[slot] = u64::from_be_bytes([
            buf[p],
            buf[p + 1],
            buf[p + 2],
            buf[p + 3],
            buf[p + 4],
            buf[p + 5],
            buf[p + 6],
            buf[p + 7],
        ]);
    }
    let pack_checksum = hexutil::encode(&buf[buf.len() - 40..buf.len() - 20]);
    let self_sum = hexutil::encode(&Sha1::digest(&buf[..buf.len() - 20]));
    let self_checksum_ok = self_sum == hexutil::encode(&buf[buf.len() - 20..]);
    let entries = oids
        .into_iter()
        .zip(crcs)
        .zip(offsets)
        .map(|((oid, crc), offset)| IdxEntry {
            oid,
            crc32: Some(crc),
            offset,
        })
        .collect();
    Ok(IdxFile {
        version: 2,
        fanout,
        entries,
        pack_checksum,
        self_checksum_ok,
    })
}

fn parse_v1(buf: &[u8]) -> Result<IdxFile, String> {
    let mut fanout = Vec::with_capacity(256);
    let mut pos = 0;
    for _ in 0..256 {
        fanout.push(u32::from_be_bytes([
            buf[pos],
            buf[pos + 1],
            buf[pos + 2],
            buf[pos + 3],
        ]));
        pos += 4;
    }
    let n = fanout[255] as usize;
    if buf.len() < pos + n * 24 {
        return Err("truncated v1 index".into());
    }
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let offset = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as u64;
        let oid = hexutil::encode(&buf[pos + 4..pos + 24]);
        entries.push(IdxEntry {
            oid,
            crc32: None,
            offset,
        });
        pos += 24;
    }
    Ok(IdxFile {
        version: 1,
        fanout,
        entries,
        pack_checksum: String::new(),
        self_checksum_ok: true,
    })
}
