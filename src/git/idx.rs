//! Parse Git pack index files (v2 and legacy v1), keeping the fanout table.

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IdxParse {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// Offset ranges for large (>2^31) objects.
    pub large_offsets: Vec<u64>,
    pub pack_sha: [u8; 20],
    pub idx_trailer_sha_ok: bool,
    pub errors: Vec<String>,
}

fn read_u32(data: &[u8], p: usize) -> Result<u32, String> {
    data.get(p..p + 4)
        .map(|b| Ok(u32::from_be_bytes(b.try_into().unwrap())))
        .ok_or_else(|| "unexpected end of index".to_string())?
}

fn read_u64(data: &[u8], p: usize) -> Result<u64, String> {
    data.get(p..p + 8)
        .map(|b| Ok(u64::from_be_bytes(b.try_into().unwrap())))
        .ok_or_else(|| "unexpected end of index".to_string())?
}

fn check_trailer(data: &[u8], idx_sha_at: usize) -> (bool, [u8; 20]) {
    use sha1_smol::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(&data[..idx_sha_at]);
    let want = hasher.digest().bytes();
    let got = &data[idx_sha_at..idx_sha_at + 20];
    (want == got, want)
}

/// Parse v2 index.
fn parse_v2(data: &[u8]) -> Result<IdxParse, String> {
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_u32(data, 8 + i * 4)?;
    }
    let n = fanout[255] as usize;
    let expected_len = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + 20 + 20;
    if data.len() < expected_len {
        return Err(format!(
            "index too short for {n} objects (need {expected_len}, have {})",
            data.len()
        ));
    }

    let mut oids = Vec::with_capacity(n);
    let mut p = 8 + 256 * 4;
    for _ in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        oids.push(oid);
        p += 20;
    }

    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(read_u32(data, p)?);
        p += 4;
    }

    let mut raw_offsets = Vec::with_capacity(n);
    for _ in 0..n {
        raw_offsets.push(read_u32(data, p)?);
        p += 4;
    }

    let pack_sha = {
        let mut a = [0u8; 20];
        a.copy_from_slice(&data[p..p + 20]);
        a
    };
    let idx_sha_at = p + 20;
    let (trailer_ok, _want) = check_trailer(data, idx_sha_at);
    if !trailer_ok {
        errors.push("index trailer sha1 mismatch".into());
    }

    // Fanout consistency.
    let mut last = 0u32;
    let mut monotonic = true;
    for (i, v) in fanout.iter().enumerate() {
        if *v < last {
            monotonic = false;
            errors.push(format!("fanout[{i}] {v} decreases from previous {last}"));
        }
        last = *v;
    }
    if monotonic && n as u32 != fanout[255] {
        errors.push("fanout total disagrees with object count".into());
    }
    // Verify fanout counts against sorted oids.
    for (bucket, v) in fanout.iter().enumerate() {
        let actual = oids.iter().filter(|o| o[0] as usize <= bucket).count() as u32;
        if actual != *v {
            errors.push(format!(
                "fanout[{bucket}] claims {v} but {actual} oids have first byte <= {bucket}"
            ));
            break;
        }
    }

    // Large-offset table precedes the pack sha; its size is determined by
    // counting the MSB-set 32 bit offsets.
    let large_count = raw_offsets.iter().filter(|o| *o & 0x8000_0000 != 0).count();
    let large_table_start = p - n * 4; // p currently at pack sha
    let large_table_actual_start = idx_sha_at - 20 - large_count * 8;
    let _ = large_table_start;
    let mut large_offsets = Vec::with_capacity(large_count);
    for i in 0..large_count {
        large_offsets.push(read_u64(data, large_table_actual_start + i * 8)?);
    }

    let mut entries = Vec::with_capacity(n);
    let mut large_i = 0usize;
    for i in 0..n {
        let ro = raw_offsets[i];
        let offset = if ro & 0x8000_0000 != 0 {
            let li = (ro & 0x7fff_ffff) as usize;
            let v = large_offsets
                .get(li)
                .copied()
                .ok_or_else(|| format!("large-offset index {li} out of range"))?;
            large_i += 1;
            v
        } else {
            ro as u64
        };
        entries.push(IdxEntry {
            oid: oids[i],
            offset,
            crc: Some(crcs[i]),
        });
    }

    if entries.iter().any(|e| e.offset < 12) {
        errors.push("index lists an offset inside the pack header".into());
    }

    Ok(IdxParse {
        version: 2,
        fanout,
        entries,
        large_offsets,
        pack_sha,
        idx_trailer_sha_ok: trailer_ok,
        errors,
    })
}

/// Parse legacy v1 index (256 fanout, then (offset,oid) records sorted by oid).
fn parse_v1(data: &[u8]) -> Result<IdxParse, String> {
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = read_u32(data, i * 4)?;
    }
    let n = fanout[255] as usize;
    let expected_len = 256 * 4 + n * 24 + 40;
    if data.len() < expected_len {
        return Err(format!(
            "v1 index too short for {n} objects (need {expected_len})"
        ));
    }
    let mut p = 256 * 4;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let offset = read_u32(data, p)? as u64;
        p += 4;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        p += 20;
        entries.push(IdxEntry { oid, offset, crc: None });
    }
    let mut pack_sha = [0u8; 20];
    pack_sha.copy_from_slice(&data[p..p + 20]);
    let idx_sha_at = p + 20;
    let (trailer_ok, _) = check_trailer(data, idx_sha_at);
    if !trailer_ok {
        errors.push("index trailer sha1 mismatch".into());
    }
    Ok(IdxParse {
        version: 1,
        fanout,
        entries,
        large_offsets: Vec::new(),
        pack_sha,
        idx_trailer_sha_ok: trailer_ok,
        errors,
    })
}

pub fn parse_idx(data: &[u8]) -> Result<IdxParse, String> {
    if data.len() < 8 {
        return Err("index shorter than 8 bytes".into());
    }
    if &data[0..4] == b"\xfftOc" {
        let v = read_u32(data, 4)?;
        if v != 2 {
            return Err(format!("unsupported index version {v}"));
        }
        parse_v2(data)
    } else {
        parse_v1(data)
    }
}

/// Build pack parsing hints from an index.
pub fn index_hint(idx: &IdxParse) -> crate::git::pack::IndexHint {
    let mut offsets_oids = idx.entries.iter().map(|e| (e.offset, e.oid)).collect::<Vec<_>>();
    offsets_oids.sort_by_key(|(o, _)| *o);
    let crc_by_offset = idx
        .entries
        .iter()
        .filter_map(|e| e.crc.map(|c| (e.offset, c)))
        .collect();
    crate::git::pack::IndexHint {
        offsets_oids,
        crc_by_offset,
    }
}
