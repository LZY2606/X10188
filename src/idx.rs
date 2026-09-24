use crate::hash;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
    pub order: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum_ok: Option<bool>,
    pub idx_checksum_ok: Option<bool>,
    pub pack_checksum: Option<String>,
    pub fatal: Option<String>,
}

fn u32be(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn u64be(b: &[u8], p: usize) -> u64 {
    u64::from_be_bytes([
        b[p],
        b[p + 1],
        b[p + 2],
        b[p + 3],
        b[p + 4],
        b[p + 5],
        b[p + 6],
        b[p + 7],
    ])
}

pub fn parse_idx(bytes: &[u8]) -> ParsedIdx {
    let mut empty = ParsedIdx {
        fanout: [0; 256],
        entries: Vec::new(),
        pack_checksum_ok: None,
        idx_checksum_ok: None,
        pack_checksum: None,
        fatal: None,
    };
    if bytes.len() < 8 {
        empty.fatal = Some("index 长度不足".to_string());
        return empty;
    }
    if bytes.len() >= 4 && &bytes[0..4] != b"\xfftOc" {
        empty.fatal = Some("缺少 v2 index 魔数（v1 index 不受支持）".to_string());
        return empty;
    }
    let version = u32be(bytes, 4);
    if version != 2 {
        empty.fatal = Some(format!("不支持的 index 版本 {version}"));
        return empty;
    }
    if bytes.len() < 8 + 256 * 4 {
        empty.fatal = Some("fanout 表不完整".to_string());
        return empty;
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(bytes, 8 + i * 4);
    }
    let count = fanout[255] as usize;
    if count == 0 {
        return empty;
    }
    let mut p = 8 + 256 * 4;
    let oid_end = p.checked_add(count * 20);
    let crc_end = oid_end.and_then(|v| v.checked_add(count * 4));
    let off_end = crc_end.and_then(|v| v.checked_add(count * 4));
    let Some((oid_end, crc_end, off_end)) = oid_end.zip(crc_end).zip(off_end).map(|((a, b), c)| (a, b, c)) else {
        empty.fatal = Some("index 表长度溢出".to_string());
        return empty;
    };
    if off_end > bytes.len().saturating_sub(40) {
        empty.fatal = Some(format!("index 对象表不完整: 需要至少 {off_end} 字节"));
        empty.fanout = fanout;
        return empty;
    }

    let mut oids = Vec::with_capacity(count);
    for i in 0..count {
        oids.push(hash::hex(&bytes[p + i * 20..p + i * 20 + 20]));
    }
    p = oid_end;
    let mut crcs = Vec::with_capacity(count);
    for i in 0..count {
        crcs.push(u32be(bytes, p + i * 4));
    }
    p = crc_end;
    let mut offsets4 = Vec::with_capacity(count);
    for i in 0..count {
        offsets4.push(u32be(bytes, p + i * 4));
    }

    let large_table = off_end;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let raw = offsets4[i];
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let lp = large_table + idx * 8;
            if lp + 8 > bytes.len() - 40 {
                empty.fatal = Some(format!("大偏移表条目越界 (entry {i})"));
                return empty;
            }
            u64be(bytes, lp)
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset,
            order: i,
        });
    }

    let mut parsed = ParsedIdx {
        fanout,
        entries,
        pack_checksum_ok: None,
        idx_checksum_ok: None,
        pack_checksum: None,
        fatal: None,
    };
    // trailing 40 bytes: pack sha1 (20) + idx sha1 (20)
    if bytes.len() >= off_end + 40 {
        let pack_sum_at = bytes.len() - 40;
        let idx_sum_at = bytes.len() - 20;
        parsed.pack_checksum = Some(hash::hex(&bytes[pack_sum_at..pack_sum_at + 20]));
        let want_idx_sum = hash::sha1_bytes(&bytes[..idx_sum_at]);
        parsed.idx_checksum_ok = Some(want_idx_sum.as_slice() == &bytes[idx_sum_at..]);
    }
    parsed
}

pub mod encode {
    use crate::hash;

    /// Build a v2 index. Entries: (oid hex, crc32, offset).
    pub fn idx(entries: &[(String, u32, u64)]) -> Vec<u8> {
        let mut sorted: Vec<&(String, u32, u64)> = entries.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let count = sorted.len();

        let mut out = Vec::new();
        out.extend_from_slice(b"\xfftOc");
        out.extend_from_slice(&2u32.to_be_bytes());
        let mut fanout = [0u32; 256];
        let mut seen = 0usize;
        for bucket in 0..256usize {
            while seen < count && usize::from_str_radix(&sorted[seen].0[0..2], 16).unwrap() == bucket {
                seen += 1;
            }
            fanout[bucket] = seen as u32;
        }
        for v in fanout {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for (oid, _, _) in &sorted {
            out.extend_from_slice(&hash::unhex(oid).unwrap());
        }
        for (_, crc, _) in &sorted {
            out.extend_from_slice(&crc.to_be_bytes());
        }
        // offsets: may need 64-bit table; always emit the 64-bit table for simplicity
        let mut big_offsets: Vec<u64> = Vec::new();
        for (_, _, offset) in &sorted {
            if *offset <= u32::MAX as u64 {
                out.extend_from_slice(&(*offset as u32).to_be_bytes());
            } else {
                let idx = big_offsets.len() as u32 | 0x8000_0000;
                out.extend_from_slice(&idx.to_be_bytes());
                big_offsets.push(*offset);
            }
        }
        for off in &big_offsets {
            out.extend_from_slice(&off.to_be_bytes());
        }
        // placeholder pack checksum (20 zero bytes)
        let pack_checksum_at = out.len();
        out.extend_from_slice(&[0u8; 20]);
        let idx_checksum = hash::sha1_bytes(&out);
        out.extend_from_slice(&idx_checksum);
        let _ = pack_checksum_at;
        out
    }
}
