use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::encoding::read_be;

#[derive(Clone, Debug, Serialize)]
pub struct IdxEntry {
    pub oid_hex: String,
    pub offset: u64,
    pub crc32: u32,
    /// True when the offset table points into the 8-byte large-offset table.
    pub large_offset: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdxInfo {
    pub version: u32,
    pub count: u32,
    /// The raw 256 fanout table.
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum_hex: String,
    pub index_checksum_hex: String,
    pub computed_pack_checksum_hex: String,
    pub computed_index_checksum_hex: String,
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

/// Parse a v2 .idx file: magic, version, 256-entry fanout, sorted oids,
/// CRC table, offset table, large-offset table and double SHA-1 trailers.
pub fn parse_idx(data: &[u8]) -> IdxInfo {
    let mut errors = Vec::new();
    let empty = |errors: Vec<String>| IdxInfo {
        version: 0,
        count: 0,
        fanout: vec![],
        entries: vec![],
        pack_checksum_hex: String::new(),
        index_checksum_hex: String::new(),
        computed_pack_checksum_hex: String::new(),
        computed_index_checksum_hex: String::new(),
        checksum_ok: false,
        errors,
    };

    if data.len() < 8 {
        return empty(vec!["idx shorter than 8-byte header".into()]);
    }
    if &data[0..4] != b"\xfftOc" {
        return empty(vec![
            "only idx v2 (\\xfftOc magic) is supported".into()
        ]);
    }
    let version = read_be(&data[4..8], 4) as u32;
    if version != 2 {
        errors.push(format!("unsupported idx version {version}"));
    }

    let fanout_start = 8usize;
    if data.len() < fanout_start + 256 * 4 {
        return empty(vec!["idx fanout table truncated".into()]);
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        fanout.push(read_be(&data[fanout_start + i * 4..], 4) as u32);
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(format!("fanout[{i}] decreases (idx corrupt)"));
        }
    }
    let count = fanout[255];

    let mut p = fanout_start + 256 * 4;
    let need = count as usize * 20 + count as usize * 4 + count as usize * 4;
    if data.len() < p + need + 40 {
        return empty(vec![
            format!("idx tables truncated: need {need} bytes for {count} objects")
        ]);
    }

    let oid_start = p;
    let mut oids = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let s = oid_start + i * 20;
        oids.push(hex::encode(&data[s..s + 20]));
    }
    p = oid_start + count as usize * 20;

    let crc_start = p;
    let mut crcs = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        crcs.push(read_be(&data[crc_start + i * 4..], 4) as u32);
    }
    p = crc_start + count as usize * 4;

    let off_start = p;
    let mut offsets: Vec<(u64, bool)> = Vec::with_capacity(count as usize);
    let mut large_count = 0u32;
    for i in 0..count as usize {
        let raw = read_be(&data[off_start + i * 4..], 4);
        if raw & 0x8000_0000 != 0 {
            offsets.push(((raw & 0x7fff_ffff) as u64, true));
            large_count += 1;
        } else {
            offsets.push((raw, false));
        }
    }
    p = off_start + count as usize * 4;

    let large_start = p;
    if data.len() < large_start + large_count as usize * 8 + 40 {
        return empty(vec!["large-offset table truncated".into()]);
    }
    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let (idx, is_large) = offsets[i];
        let offset = if is_large {
            let s = large_start + idx as usize * 8;
            read_be(&data[s..s + 8], 8)
        } else {
            idx
        };
        entries.push(IdxEntry {
            oid_hex: oids[i].clone(),
            offset,
            crc32: crcs[i],
            large_offset: is_large,
        });
    }
    let trailer_start = large_start + large_count as usize * 8;
    let pack_checksum_hex = hex::encode(&data[trailer_start..trailer_start + 20]);
    let index_checksum_hex = hex::encode(&data[trailer_start + 20..trailer_start + 40]);

    let mut ph = Sha1::new();
    ph.update(&data[..trailer_start]);
    let computed_index = ph.finalize();
    let computed_pack = &data[trailer_start..trailer_start + 20];

    let checksum_ok = computed_index.as_slice() == &data[trailer_start + 20..trailer_start + 40];
    if !checksum_ok {
        errors.push("idx SHA-1 checksum trailer mismatch".into());
    }

    IdxInfo {
        version,
        count,
        fanout,
        entries,
        pack_checksum_hex,
        index_checksum_hex,
        computed_pack_checksum_hex: hex::encode(computed_pack),
        computed_index_checksum_hex: hex::encode(computed_index),
        checksum_ok,
        errors,
    }
}
