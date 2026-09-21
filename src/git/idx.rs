//! `.idx` parser (v1 32-bit offset table and v2 fanout format).

use std::collections::HashMap;

/// One index row for a pack object.
#[derive(Debug, Clone)]
pub struct IdxRow {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

/// Parsed index: fanout table, rows ordered as laid out, and lookup maps.
#[derive(Debug, Clone)]
pub struct ParsedIdx {
    /// Checksum of the pack this index describes (v2 trailer).
    pub pack_checksum: Option<String>,
    pub version: u32,
    pub fanout: [u32; 256],
    pub rows: Vec<IdxRow>,
    pub by_oid: HashMap<String, usize>,
    pub crc_by_offset: HashMap<u64, u32>,
    pub errors: Vec<String>,
}

/// Parse an index file (auto-detects v1/v2 magic).
pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx, String> {
    if data.len() < 8 {
        return Err("index shorter than 8 bytes".to_string());
    }
    let _ = b"\xff\x74\x4f\x63";

    if &data[0..4] == b"\xff\x74\x4f\x63" {
        parse_v2(data)
    } else {
        parse_v1(data)
    }
}

fn read_fanout(data: &[u8], start: usize) -> Result<[u32; 256], String> {
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let pos = start + i * 4;
        fanout[i] = u32::from_be_bytes([
            *data.get(pos).ok_or("truncated fanout")?,
            *data.get(pos + 1).ok_or("truncated fanout")?,
            *data.get(pos + 2).ok_or("truncated fanout")?,
            *data.get(pos + 3).ok_or("truncated fanout")?,
        ]);
    }
    Ok(fanout)
}

fn validate_fanout(fanout: &[u32; 256], count: usize) -> Vec<String> {
    let mut errors = Vec::new();
    for (i, w) in fanout.windows(2).enumerate() {
        if w[1] < w[0] {
            errors.push(format!("fanout decreases between bucket {i} and {}", i + 1));
        }
    }
    if fanout[255] as usize != count {
        errors.push(format!(
            "fanout final value {} disagrees with table length {count}",
            fanout[255]
        ));
    }
    errors
}

fn parse_v2(data: &[u8]) -> Result<ParsedIdx, String> {
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }
    let fanout = read_fanout(data, 8)?;
    let count = fanout[255] as usize;
    let mut errors = validate_fanout(&fanout, count);

    let name_start = 8 + 256 * 4;
    let crc_start = name_start + count * 20;
    let off_start = crc_start + count * 4;
    let need = off_start + count * 4;
    if data.len() < need {
        return Err(format!(
            "idx too small: need {need} bytes through offset table, have {}",
            data.len()
        ));
    }

    let mut rows = Vec::with_capacity(count);
    let mut by_oid = HashMap::new();
    let mut crc_by_offset = HashMap::new();

    for i in 0..count {
        let oid = hex::encode(&data[name_start + i * 20..name_start + (i + 1) * 20]);
        let crc = u32::from_be_bytes([
            data[crc_start + i * 4],
            data[crc_start + i * 4 + 1],
            data[crc_start + i * 4 + 2],
            data[crc_start + i * 4 + 3],
        ]);
        let off_word = u32::from_be_bytes([
            data[off_start + i * 4],
            data[off_start + i * 4 + 1],
            data[off_start + i * 4 + 2],
            data[off_start + i * 4 + 3],
        ]) as u64;

        let offset = if off_word & 0x8000_0000 != 0 {
            let table_idx = (off_word & 0x7fff_ffff) as usize;
            let large_base = need; // optional 8-byte offset table precedes the 40-byte trailer
            let pos = large_base + table_idx * 8;
            if pos + 8 > data.len() - 40 {
                return Err(format!("large offset table entry {table_idx} out of range"));
            }
            u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap())
        } else {
            off_word
        };

        by_oid.entry(oid.clone()).or_insert(i);
        crc_by_offset.insert(offset, crc);
        rows.push(IdxRow { oid, offset, crc32: crc });
    }

    // 20-byte pack checksum + 20-byte idx checksum follow (the large-offset
    // table, if any, sits before them).
    if data.len() < need + 40 {
        errors.push("idx missing trailing checksums".to_string());
    }

    if by_oid.len() != count {
        errors.push(format!(
            "idx contains duplicate object ids ({count} rows, {} unique)",
            by_oid.len()
        ));
    }

    let pack_checksum = if data.len() >= 40 {
        Some(hex::encode(&data[data.len() - 40..data.len() - 20]))
    } else {
        None
    };

    Ok(ParsedIdx {
        pack_checksum,
        version: 2,
        fanout,
        rows,
        by_oid,
        crc_by_offset,
        errors,
    })
}

fn parse_v1(data: &[u8]) -> Result<ParsedIdx, String> {
    let fanout = read_fanout(data, 0)?;
    let count = fanout[255] as usize;
    let errors = validate_fanout(&fanout, count);
    let table_start = 256 * 4;
    let need = table_start + count * 24;
    if data.len() < need {
        return Err(format!(
            "v1 idx too small: need {need} bytes, have {}",
            data.len()
        ));
    }

    let mut rows = Vec::with_capacity(count);
    let mut by_oid = HashMap::new();
    let mut crc_by_offset = HashMap::new();
    for i in 0..count {
        let pos = table_start + i * 24;
        let offset = u32::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as u64;
        let oid = hex::encode(&data[pos + 4..pos + 24]);
        by_oid.entry(oid.clone()).or_insert(i);
        crc_by_offset.insert(offset, 0);
        rows.push(IdxRow {
            oid,
            offset,
            crc32: 0,
        });
    }

    Ok(ParsedIdx {
        pack_checksum: None,
        version: 1,
        fanout,
        rows,
        by_oid,
        crc_by_offset,
        errors,
    })
}
