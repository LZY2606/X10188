//! Git pack index parser (version 2): fanout table, oid / CRC32 / offset
//! tables, large-offset table and the two trailing checksums.

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub ordinal: usize,
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
    pub large_offset: bool,
}

#[derive(Debug, Clone)]
pub struct IdxIssue {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub num_objects: u32,
    pub entries: Vec<IdxEntry>,
    pub issues: Vec<IdxIssue>,
    pub pack_checksum_expected: [u8; 20],
    pub idx_checksum_expected: [u8; 20],
    pub idx_checksum_actual: [u8; 20],
    pub idx_checksum_ok: bool,
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn u64be(b: &[u8]) -> u64 {
    u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ])
}

pub fn parse_idx(raw: &[u8]) -> Result<ParsedIdx, String> {
    use sha1::Digest;
    if raw.len() < 8 {
        return Err("index shorter than 8 bytes".into());
    }
    let magic = &raw[0..4];
    let version = u32be(&raw[4..8]);
    if magic != b"\xfftOc" {
        return Err(format!("not an idx v2 file (magic {:?})", magic));
    }
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }

    let mut issues = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(&raw[8 + 4 * i..12 + 4 * i]);
    }
    let n = fanout[255] as usize;

    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + n * 20;
    let off_start = crc_start + n * 4;
    let large_start = off_start + n * 4;
    // trailer: pack checksum (20) + idx checksum (20)
    let trailer_at = large_start;
    if raw.len() < trailer_at + 40 {
        return Err("index tables run past end of file".into());
    }

    // fanout monotonicity
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            issues.push(IdxIssue {
                code: "fanout_not_monotonic".into(),
                detail: format!("fanout[{i}] < fanout[{p}]", p = i - 1),
            });
        }
    }

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&raw[oid_start + i * 20..oid_start + (i + 1) * 20]);
        let crc = u32be(&raw[crc_start + i * 4..crc_start + (i + 1) * 4]);
        let off_word = u32be(&raw[off_start + i * 4..off_start + (i + 1) * 4]);
        let (offset, large_offset) = if off_word & 0x8000_0000 != 0 {
            let idx = (off_word & 0x7fff_ffff) as usize;
            let at = large_start + idx * 8;
            if at + 8 > trailer_at {
                issues.push(IdxIssue {
                    code: "large_offset_out_of_range".into(),
                    detail: format!("entry {i} large-offset table index {idx} invalid"),
                });
                (0, true)
            } else {
                (u64be(&raw[at..at + 8]), true)
            }
        } else {
            (off_word as u64, false)
        };
        entries.push(IdxEntry {
            ordinal: i,
            oid,
            crc32: crc,
            offset,
            large_offset,
        });
    }

    // oid ordering / duplicates
    for i in 1..n {
        match entries[i].oid.cmp(&entries[i - 1].oid) {
            std::cmp::Ordering::Less => issues.push(IdxIssue {
                code: "oids_not_sorted".into(),
                detail: format!("oid #{i} is smaller than its predecessor"),
            }),
            std::cmp::Ordering::Equal => issues.push(IdxIssue {
                code: "duplicate_oid_in_index".into(),
                detail: format!("oid {} appears twice", hex::encode(entries[i].oid)),
            }),
            std::cmp::Ordering::Greater => {}
        }
    }

    let mut pack_checksum_expected = [0u8; 20];
    pack_checksum_expected.copy_from_slice(&raw[trailer_at..trailer_at + 20]);
    let mut idx_checksum_expected = [0u8; 20];
    idx_checksum_expected.copy_from_slice(&raw[trailer_at + 20..trailer_at + 40]);
    let mut hasher = sha1::Sha1::new();
    hasher.update(&raw[..trailer_at + 20]);
    let idx_checksum_actual: [u8; 20] = hasher.finalize().into();
    let idx_checksum_ok = idx_checksum_actual == idx_checksum_expected;
    if !idx_checksum_ok {
        issues.push(IdxIssue {
            code: "idx_checksum_mismatch".into(),
            detail: "trailing idx SHA-1 does not match".into(),
        });
    }

    Ok(ParsedIdx {
        fanout,
        num_objects: n as u32,
        entries,
        issues,
        pack_checksum_expected,
        idx_checksum_expected,
        idx_checksum_actual,
        idx_checksum_ok,
    })
}

/// Build an idx v2 file from `(oid, crc32, offset)` rows (test fixture).
/// `pack_checksum` is the pack trailer SHA-1.
pub fn build_idx_v2(rows: &mut [( [u8; 20], u32, u64)], pack_checksum: [u8; 20]) -> Vec<u8> {
    use sha1::Digest;
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let n = rows.len();
    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _, _) in rows.iter() {
        fanout[oid[0] as usize] += 1;
    }
    let mut cum = 0u32;
    for v in fanout.iter_mut() {
        cum += *v;
        *v = cum;
    }
    for v in fanout {
        out.extend_from_slice(&v.to_be_bytes());
    }
    for (oid, _, _) in rows.iter() {
        out.extend_from_slice(oid);
    }
    for (_, crc, _) in rows.iter() {
        out.extend_from_slice(&crc.to_be_bytes());
    }
    let mut large: Vec<u64> = Vec::new();
    for (_, _, off) in rows.iter() {
        if *off > 0x7fff_ffff {
            let idx = large.len() as u32;
            large.push(*off);
            out.extend_from_slice(&(0x8000_0000 | idx).to_be_bytes());
        } else {
            out.extend_from_slice(&(*off as u32).to_be_bytes());
        }
    }
    for off in large {
        out.extend_from_slice(&off.to_be_bytes());
    }
    out.extend_from_slice(&pack_checksum);
    let mut hasher = sha1::Sha1::new();
    hasher.update(&out);
    let checksum: [u8; 20] = hasher.finalize().into();
    out.extend_from_slice(&checksum);
    out
}
