//! Parse a Git pack index (v1 or v2) and expose fanout, oid order,
//! per-entry crc and offset tables.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct IdxEntry {
    pub ordinal: usize,
    pub oid: String,
    pub offset: u64,
    /// Present in v2 indexes.
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RawIdx {
    pub version: u8,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub index_checksum: String,
    pub computed_pack_checksum: String,
    pub computed_index_checksum: String,
    pub fatal: Option<String>,
}

pub fn parse_idx(data: &[u8]) -> Result<RawIdx, String> {
    if data.len() < 8 {
        return Err("idx too small".into());
    }
    let is_v2 = &data[0..4] == b"\xfftOc";
    if is_v2 {
        parse_v2(data)
    } else {
        parse_v1(data)
    }
}

fn checksum20(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn parse_v2(data: &[u8]) -> Result<RawIdx, String> {
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }
    if data.len() < 8 + 256 * 4 {
        return Err("idx truncated in fanout table".into());
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let at = 8 + i * 4;
        fanout.push(u32::from_be_bytes(data[at..at + 4].try_into().unwrap()));
    }
    let count = *fanout.last().unwrap() as usize;

    let mut fatal: Option<String> = None;
    let need = 8 + 1024 + count * 20 + count * 4 + count * 4 + 40;
    if data.len() < need {
        fatal = Some(format!(
            "idx length {} smaller than expected {need} for {count} entries",
            data.len()
        ));
    }

    let mut entries = Vec::with_capacity(count);
    let oid_base = 8 + 1024;
    let crc_base = oid_base + count * 20;
    let off_base = crc_base + count * 4;
    let large_base = off_base + count * 4;
    for ordinal in 0..count {
        let oid = hex::encode(&data[oid_base + ordinal * 20..oid_base + ordinal * 20 + 20]);
        let crc = u32::from_be_bytes(
            data[crc_base + ordinal * 4..crc_base + ordinal * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let raw_off = u32::from_be_bytes(
            data[off_base + ordinal * 4..off_base + ordinal * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let mut offset: u64 = raw_off as u64;
        if raw_off & 0x8000_0000 != 0 {
            let idx = (raw_off & 0x7fff_ffff) as usize;
            let at = large_base + idx * 8;
            if at + 8 > data.len().saturating_sub(40) {
                fatal
                    .get_or_insert(format!("64-bit offset table out of range at ordinal {ordinal}"));
            } else {
                offset = u64::from_be_bytes(data[at..at + 8].try_into().unwrap());
            }
        }
        entries.push(IdxEntry {
            ordinal,
            oid,
            offset,
            crc32: Some(crc),
        });
    }

    let (computed_pack_checksum, computed_index_checksum, pack_checksum, index_checksum) =
        if data.len() >= large_base + 40 {
            (
                checksum20(&data[large_base..large_base + 20]),
                checksum20(&data[..data.len() - 20]),
                hex::encode(&data[large_base..large_base + 20]),
                hex::encode(&data[data.len() - 20..]),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

    Ok(RawIdx {
        version: 2,
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        computed_pack_checksum,
        computed_index_checksum,
        fatal,
    })
}

fn parse_v1(data: &[u8]) -> Result<RawIdx, String> {
    if data.len() < 1024 + 40 {
        return Err("v1 idx truncated".into());
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let at = i * 4;
        fanout.push(u32::from_be_bytes(data[at..at + 4].try_into().unwrap()));
    }
    let count = *fanout.last().unwrap() as usize;
    let mut fatal: Option<String> = None;
    let table_base = 1024;
    let need = table_base + count * 24 + 40;
    if data.len() < need {
        fatal = Some(format!("v1 idx truncated: have {} need {need}", data.len()));
    }
    let mut entries = Vec::with_capacity(count);
    for ordinal in 0..count {
        let at = table_base + ordinal * 24;
        if at + 24 > data.len().saturating_sub(40) {
            break;
        }
        let raw = u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
        let oid = hex::encode(&data[at + 4..at + 24]);
        entries.push(IdxEntry {
            ordinal,
            oid,
            offset: raw as u64,
            crc32: None,
        });
    }
    let trailer = table_base + count * 24;
    let (computed_pack_checksum, computed_index_checksum, pack_checksum, index_checksum) =
        if data.len() >= trailer + 40 {
            (
                checksum20(&data[trailer..trailer + 20]),
                checksum20(&data[..data.len() - 20]),
                hex::encode(&data[trailer..trailer + 20]),
                hex::encode(&data[data.len() - 20..]),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };
    Ok(RawIdx {
        version: 1,
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        computed_pack_checksum,
        computed_index_checksum,
        fatal,
    })
}
