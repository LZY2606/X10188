use crate::util;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Default)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub idx_sha1_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxFile, String> {
    let mut out = IdxFile::default();
    if data.len() < 4 * 256 {
        return Err("idx too small for fanout".into());
    }
    let is_v2 = data.len() >= 8 && data[0] == 0xff && &data[1..4] == b"tOc";
    let mut pos;
    if is_v2 {
        out.version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if out.version != 2 {
            return Err(format!("unsupported idx version {}", out.version));
        }
        pos_after_fanout(data, &mut out, 8)?;
        pos = 8 + 256 * 4;
    } else {
        out.version = 1;
        pos_after_fanout(data, &mut out, 0)?;
        pos = 256 * 4;
    }
    let n = out.fanout[255] as usize;
    if out.version == 2 {
        let need = pos + n * 20 + n * 4 + n * 4 + 40;
        if data.len() < need {
            return Err("idx v2 truncated".into());
        }
        let mut oids = Vec::with_capacity(n);
        for i in 0..n {
            oids.push(util::hex_encode(&data[pos + i * 20..pos + i * 20 + 20]));
        }
        pos += n * 20;
        let mut crcs = Vec::with_capacity(n);
        for i in 0..n {
            crcs.push(u32::from_be_bytes([
                data[pos + i * 4],
                data[pos + i * 4 + 1],
                data[pos + i * 4 + 2],
                data[pos + i * 4 + 3],
            ]));
        }
        pos += n * 4;
        let mut offsets = Vec::with_capacity(n);
        let mut large_idx = Vec::new();
        for i in 0..n {
            let v = u32::from_be_bytes([
                data[pos + i * 4],
                data[pos + i * 4 + 1],
                data[pos + i * 4 + 2],
                data[pos + i * 4 + 3],
            ]);
            if v & 0x8000_0000 != 0 {
                large_idx.push((i, (v & 0x7fff_ffff) as usize));
                offsets.push(0u64);
            } else {
                offsets.push(v as u64);
            }
        }
        pos += n * 4;
        for (i, li) in large_idx {
            let off = pos + li * 8;
            if off + 8 > data.len() {
                return Err("idx v2 large offset table truncated".into());
            }
            offsets[i] = u64::from_be_bytes([
                data[off], data[off + 1], data[off + 2], data[off + 3],
                data[off + 4], data[off + 5], data[off + 6], data[off + 7],
            ]);
        }
        let large_count = data[pos..].len().saturating_sub(40) / 8;
        pos += large_count * 8;
        for i in 0..n {
            out.entries.push(IdxEntry { oid: oids[i].clone(), crc32: crcs[i], offset: offsets[i] });
        }
    } else {
        let need = pos + n * 24;
        if data.len() < need {
            return Err("idx v1 truncated".into());
        }
        for i in 0..n {
            let off = pos + i * 24;
            let offset = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as u64;
            let oid = util::hex_encode(&data[off + 4..off + 24]);
            out.entries.push(IdxEntry { oid, crc32: 0, offset });
        }
        pos += n * 24;
    }
    if data.len() >= pos + 40 {
        out.pack_sha1 = util::hex_encode(&data[data.len() - 40..data.len() - 20]);
        out.idx_sha1 = util::hex_encode(&data[data.len() - 20..]);
        out.idx_sha1_ok = util::sha1_hex(&data[..data.len() - 20]) == out.idx_sha1;
    }
    Ok(out)
}

fn pos_after_fanout(data: &[u8], out: &mut IdxFile, base: usize) -> Result<(), String> {
    if data.len() < base + 256 * 4 {
        return Err("idx truncated in fanout".into());
    }
    let mut prev = 0u32;
    for i in 0..256 {
        let off = base + i * 4;
        let v = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if v < prev {
            return Err("fanout not monotonic".into());
        }
        out.fanout[i] = v;
        prev = v;
    }
    Ok(())
}
