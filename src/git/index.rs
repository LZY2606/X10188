//! Pure-Rust PACK index v2 parser with fanout table exposure.

use super::oid::Oid;

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub oid: Oid,
    pub pack_offset: u64,
    pub crc: u32,
}

#[derive(Clone, Debug, Default)]
pub struct IndexParseResult {
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: Option<Oid>,
    pub index_checksum: Option<Oid>,
    pub fatal: Option<String>,
}

pub fn parse_index(buf: &[u8]) -> IndexParseResult {
    let mut res = IndexParseResult::default();
    // v2: 4-byte magic \377tOc, 4-byte version 2, 256*4 fanout, ...
    if buf.len() < 8 + 256 * 4 {
        res.fatal = Some("index too short for v2 header+fanout".into());
        return res;
    }
    if &buf[0..4] != b"\xfftOc" {
        res.fatal = Some("missing index v2 magic \\377tOc".into());
        return res;
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if version != 2 {
        res.fatal = Some(format!("unsupported index version {}", version));
        return res;
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let o = 8 + i * 4;
        fanout.push(u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]));
    }
    let count = fanout[255] as usize;
    let mut p = 8 + 256 * 4;
    let need = p
        .checked_add(count * 20)
        .and_then(|x| x.checked_add(count * 4))
        .and_then(|x| x.checked_add(count * 4))
        .and_then(|x| x.checked_add(40));
    match need {
        Some(n) if n <= buf.len() => {}
        _ => {
            res.fatal = Some(format!(
                "index declares {} objects but the file is too short",
                count
            ));
            res.fanout = fanout;
            return res;
        }
    }

    let mut oids = Vec::with_capacity(count);
    for _ in 0..count {
        let oid = Oid::from_bytes(buf[p..p + 20].try_into().unwrap());
        oids.push(oid);
        p += 20;
    }
    let mut crcs = Vec::with_capacity(count);
    for _ in 0..count {
        crcs.push(u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]));
        p += 4;
    }
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let word = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
        p += 4;
        if word & 0x8000_0000 != 0 {
            // 64-bit offset table: leave a marker, resolve below.
            offsets.push(u64::MAX - (word & 0x7fff_ffff) as u64);
        } else {
            offsets.push(word as u64);
        }
    }
    // Resolve large-offset references against the 64-bit table.
    let markers: Vec<u64> = offsets
        .iter()
        .filter(|x| **x >= u64::MAX - 0x7fff_ffff)
        .copied()
        .collect();
    if !markers.is_empty() {
        for m in &markers {
            let table_idx = (u64::MAX - m) as usize;
            let tp = p + table_idx * 8;
            if tp + 8 > buf.len() {
                res.fatal = Some("64-bit offset table out of range".into());
                return res;
            }
            let v = u64::from_be_bytes(buf[tp..tp + 8].try_into().unwrap());
            for off in offsets.iter_mut() {
                if *off == *m {
                    *off = v;
                }
            }
        }
    }

    for i in 0..count {
        res.entries.push(IndexEntry {
            oid: oids[i],
            pack_offset: offsets[i],
            crc: crcs[i],
        });
    }
    // Trailing checksums: 20 pack sha + 20 index sha.
    let trailer = &buf[p..];
    let mut q = 0usize;
    if let Some(rest) = trailer.get(0..40) {
        // skip optional 8-byte large offset region we did not consume precisely;
        // locate checksums from the end instead.
        let _ = rest;
    }
    if buf.len() >= 40 {
        res.pack_checksum = Some(Oid::from_bytes(buf[buf.len() - 40..buf.len() - 20].try_into().unwrap()));
        res.index_checksum = Some(Oid::from_bytes(buf[buf.len() - 20..].try_into().unwrap()));
    }
    let _ = q;
    res.fanout = fanout;
    res
}
