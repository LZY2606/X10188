//! Pure-Rust parser for git idx v1 and v2 files.

use crate::oid::Oid;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: Option<u32>,
    /// Pack offset; v2 uses the 8-byte table when the high bit is set.
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub version: u8,
    pub fanout: [u32; 256],
    pub count: u32,
    pub entries: Vec<IdxEntry>,
    /// SHA-1 name of the paired pack ("packfile checksum").
    pub pack_checksum: Option<Oid>,
    pub idx_checksum_stored: Option<Oid>,
    pub idx_checksum_computed: Option<Oid>,
    pub issue: Option<String>,
}

fn u32b(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_idx(data: &[u8]) -> IdxInfo {
    let mut info = IdxInfo {
        version: 0,
        fanout: [0u32; 256],
        count: 0,
        entries: Vec::new(),
        pack_checksum: None,
        idx_checksum_stored: None,
        idx_checksum_computed: None,
        issue: None,
    };

    if data.len() < 256 * 4 + 8 {
        info.issue = Some("idx shorter than fanout table".into());
        return info;
    }

    let v2 = &data[0..4] == b"\xfftOc";
    let mut pos = 0usize;
    if v2 {
        let ver = u32b(&data[4..8]);
        if ver != 2 {
            info.issue = Some(format!("unsupported idx version {ver}"));
            return info;
        }
        info.version = 2;
        pos = 8;
    } else {
        info.version = 1;
    }

    for i in 0..256 {
        info.fanout[i] = u32b(&data[pos + i * 4..pos + i * 4 + 4]);
    }
    pos += 256 * 4;
    info.count = info.fanout[255];

    for i in 1..256 {
        if info.fanout[i] < info.fanout[i - 1] {
            info.issue = Some(format!(
                "fanout table not monotonic at bucket {i}: {} < {}",
                info.fanout[i],
                info.fanout[i - 1]
            ));
            return info;
        }
    }

    if v2 {
        let n = info.count as usize;
        if pos + n * 20 > data.len() {
            info.issue = Some("idx truncated in oid table".into());
            return info;
        }
        let mut oids = Vec::with_capacity(n);
        for i in 0..n {
            oids.push(match Oid::from_bytes(&data[pos + i * 20..pos + i * 20 + 20]) {
                Some(o) => o,
                None => {
                    info.issue = Some(format!("oid {i} truncated"));
                    return info;
                }
            });
        }
        pos += n * 20;

        if pos + n * 4 > data.len() {
            info.issue = Some("idx truncated in crc table".into());
            return info;
        }
        let mut crcs = Vec::with_capacity(n);
        for i in 0..n {
            crcs.push(u32b(&data[pos + i * 4..pos + i * 4 + 4]));
        }
        pos += n * 4;

        if pos + n * 4 > data.len() {
            info.issue = Some("idx truncated in offset table".into());
            return info;
        }
        let mut offsets4 = Vec::with_capacity(n);
        for i in 0..n {
            offsets4.push(u32b(&data[pos + i * 4..pos + i * 4 + 4]));
        }
        pos += n * 4;

        let large_base = pos;
        let mut large_count = 0usize;
        let offsets: Vec<u64> = offsets4
            .iter()
            .map(|o4| {
                if o4 & 0x8000_0000 != 0 {
                    let idx = (o4 ^ 0x8000_0000) as usize;
                    let at = large_base + idx * 8;
                    if at + 8 <= data.len() {
                        large_count = large_count.max(idx + 1);
                        u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
                    } else {
                        u64::from(*o4)
                    }
                } else {
                    u64::from(*o4)
                }
            })
            .collect();
        pos = large_base + large_count * 8;

        if pos + 40 > data.len() {
            info.issue = Some("idx missing trailing checksums".into());
            return info;
        }
        info.pack_checksum = Oid::from_bytes(&data[pos..pos + 20]);
        info.idx_checksum_stored = Oid::from_bytes(&data[pos + 20..pos + 40]);
        let computed = sha1_of(&data[..pos + 20]);
        info.idx_checksum_computed = Some(computed);
        if info.idx_checksum_stored != Some(computed) {
            info.issue = Some(format!(
                "idx checksum mismatch: stored {} computed {}",
                info.idx_checksum_stored.map(|o| o.short()).unwrap_or_default(),
                computed.short()
            ));
        }

        for i in 0..n {
            info.entries.push(IdxEntry {
                oid: oids[i],
                crc32: Some(crcs[i]),
                offset: offsets[i],
            });
        }

        check_ordering(&mut info, &oids);
    } else {
        let n = info.count as usize;
        if pos + n * 24 > data.len() {
            info.issue = Some("idx v1 truncated in entry table".into());
            return info;
        }
        let mut oids = Vec::with_capacity(n);
        for _ in 0..n {
            let off = u32b(&data[pos..pos + 4]) as u64;
            let oid = Oid::from_bytes(&data[pos + 4..pos + 24]).unwrap();
            pos += 24;
            oids.push(oid);
            info.entries.push(IdxEntry { oid, crc32: None, offset: off });
        }
        if pos + 40 > data.len() {
            info.issue = Some("idx v1 missing trailing checksums".into());
            return info;
        }
        info.pack_checksum = Oid::from_bytes(&data[pos..pos + 20]);
        info.idx_checksum_stored = Oid::from_bytes(&data[pos + 20..pos + 40]);
        let computed = sha1_of(&data[..pos + 20]);
        info.idx_checksum_computed = Some(computed);
        if info.idx_checksum_stored != Some(computed) {
            info.issue = Some(format!(
                "idx checksum mismatch: stored {} computed {}",
                info.idx_checksum_stored.map(|o| o.short()).unwrap_or_default(),
                computed.short()
            ));
        }
        check_ordering(&mut info, &oids);
    }

    info
}

fn check_ordering(info: &mut IdxInfo, oids: &[Oid]) {
    for w in oids.windows(2) {
        if w[0] >= w[1] {
            info.issue = Some(format!(
                "oid table not strictly sorted: {} >= {}",
                w[0].short(),
                w[1].short()
            ));
            return;
        }
    }
    for (i, o) in oids.iter().enumerate() {
        let bucket = o.as_bytes()[0] as usize;
        let before = if bucket == 0 { 0 } else { info.fanout[bucket - 1] };
        let up_to = info.fanout[bucket];
        if !((before as usize..up_to as usize).contains(&i)) {
            info.issue = Some(format!(
                "oid {} not in fanout bucket {} (indices {}..{})",
                o.short(),
                bucket,
                before,
                up_to
            ));
            return;
        }
    }
}

fn sha1_of(data: &[u8]) -> Oid {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    Oid(h.finalize().into())
}

