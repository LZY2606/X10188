//! Pack index (`.idx`) v2 parsing: magic, fanout table, oid / crc32 / offset
//! tables including the 64-bit large-offset table.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdxFile {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxFile, String> {
    if data.len() < 8 {
        return Err("idx too small".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("not an idx v2 file (bad magic)".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }
    let mut pos = 8usize;
    let need = |n: usize| -> Result<(), String> {
        if pos + n > data.len() {
            Err("idx truncated".into())
        } else {
            Ok(())
        }
    };
    let mut fanout = Vec::with_capacity(256);
    need(256 * 4)?;
    for i in 0..256 {
        fanout.push(u32::from_be_bytes(
            data[pos + i * 4..pos + i * 4 + 4].try_into().unwrap(),
        ));
    }
    pos += 256 * 4;
    for w in fanout.windows(2) {
        if w[1] < w[0] {
            return Err("idx fanout not monotonic".into());
        }
    }
    let n = *fanout.last().unwrap() as usize;
    need(n * 20)?;
    let mut oids = Vec::with_capacity(n);
    for i in 0..n {
        oids.push(hex::encode(&data[pos + i * 20..pos + i * 20 + 20]));
    }
    pos += n * 20;
    need(n * 4)?;
    let mut crcs = Vec::with_capacity(n);
    for i in 0..n {
        crcs.push(u32::from_be_bytes(
            data[pos + i * 4..pos + i * 4 + 4].try_into().unwrap(),
        ));
    }
    pos += n * 4;
    need(n * 4)?;
    let mut raw_offsets = Vec::with_capacity(n);
    let mut large_count = 0usize;
    for i in 0..n {
        let v = u32::from_be_bytes(data[pos + i * 4..pos + i * 4 + 4].try_into().unwrap());
        if v & 0x8000_0000 != 0 {
            large_count += 1;
        }
        raw_offsets.push(v);
    }
    pos += n * 4;
    need(large_count * 8)?;
    let mut large = Vec::with_capacity(large_count);
    for i in 0..large_count {
        large.push(u64::from_be_bytes(
            data[pos + i * 8..pos + i * 8 + 8].try_into().unwrap(),
        ));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let v = raw_offsets[i];
        let offset = if v & 0x8000_0000 != 0 {
            large[(v & 0x7fff_ffff) as usize]
        } else {
            v as u64
        };
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset,
        });
    }
    Ok(IdxFile { fanout, entries })
}
