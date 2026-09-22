use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::hash::sha1_hex;

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub oid: String,
    pub offset: u64,
    pub expected_crc: Option<u32>,
    pub large_offset_table_pos: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: String,
    pub checksum_expected: String,
    pub checksum_actual: String,
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

impl ParsedIndex {
    pub fn entry_for_offset(&self, offset: u64) -> Option<&IndexEntry> {
        self.entries.iter().find(|entry| entry.offset == offset)
    }

    pub fn count(&self) -> u32 {
        self.fanout.last().copied().unwrap_or(0)
    }
}

fn u32_at(data: &[u8], pos: usize) -> Result<u32> {
    data.get(pos..pos + 4)
        .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
        .ok_or_else(|| Error::Corrupt("index truncated".into()))
}

pub fn parse_index_path(path: &Path) -> Result<ParsedIndex> {
    parse_index(&std::fs::read(path)?)
}

pub fn parse_index(data: &[u8]) -> Result<ParsedIndex> {
    if data.len() < 8 + 256 * 4 {
        return Err(Error::Corrupt("index too small for fanout".into()));
    }
    let v2 = &data[0..4] == b"\xfftOc";
    let fanout_start = if v2 { 8 } else { 0 };
    let fanout = (0..256)
        .map(|i| u32_at(data, fanout_start + i * 4))
        .collect::<Result<Vec<_>>>()?;
    let count = fanout[255] as usize;
    let mut errors = Vec::new();
    let mut last = 0u32;
    for value in &fanout {
        if *value < last {
            errors.push("fanout values must be nondecreasing".into());
        }
        last = *value;
    }
    if !v2 {
        return Err(Error::Corrupt("only v2 .idx files are supported"));
    }

    let mut pos = fanout_start + 256 * 4;
    let mut oids = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 20 > data.len() {
            return Err(Error::Corrupt("truncated index oid table".into()));
        }
        oids.push(hex::encode(&data[pos..pos + 20]));
        pos += 20;
    }
    let mut expected_crc = Vec::with_capacity(count);
    for _ in 0..count {
        expected_crc.push(Some(u32_at(data, pos)?));
        pos += 4;
    }
    let small_table_start = pos;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        offsets.push(u32_at(data, pos)?);
        pos += 4;
    }
    let large_table_start = pos;
    let mut large_offsets: BTreeMap<usize, u64> = BTreeMap::new();
    let mut large_index = 0usize;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let offset = if offsets[i] & 0x8000_0000 != 0 {
            let table_index = (offsets[i] & 0x7fff_ffff) as usize;
            let p = large_table_start + table_index * 8;
            if p + 8 > data.len() {
                return Err(Error::Corrupt("large offset table points outside index".into()));
            }
            let value = u64::from_be_bytes(data[p..p + 8].try_into().unwrap());
            large_offsets.insert(table_index, value);
            large_index += 1;
            value
        } else {
            offsets[i] as u64
        };
        entries.push(IndexEntry {
            oid: oids[i].clone(),
            offset,
            expected_crc: expected_crc[i],
            large_offset_table_pos: None,
        });
    }
    let _ = small_table_start;
    let _ = large_index;

    if count != entries.len() || entries.windows(2).any(|w| w[0].offset > w[1].offset) {
        errors.push("index offsets are not in ascending order".into());
    }
    let mut unique_oids = oids.clone();
    unique_oids.sort();
    unique_oids.dedup();
    if unique_oids.len() != oids.len() {
        errors.push("index contains duplicate oids".into());
    }
    let after_large = large_table_start + large_offsets.len() * 8;
    if after_large + 40 > data.len() {
        return Err(Error::Corrupt("index missing trailing checksums".into()));
    }
    let pack_checksum = hex::encode(&data[after_large..after_large + 20]);
    let checksum_expected = hex::encode(&data[after_large + 20..after_large + 40]);
    let checksum_actual = sha1_hex(&data[..after_large + 20]);
    if checksum_expected != checksum_actual {
        errors.push("index checksum mismatch".into());
    }
    Ok(ParsedIndex {
        fanout,
        entries,
        pack_checksum,
        checksum_expected,
        checksum_actual,
        checksum_ok: checksum_expected == checksum_actual,
        errors,
    })
}
