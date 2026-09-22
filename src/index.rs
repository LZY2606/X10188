use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::error::PError;
use crate::oid::Oid;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: Oid,
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FanoutTable {
    pub cumulative: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub version: u32,
    pub entries: Vec<IdxEntry>,
    pub fanout: FanoutTable,
    pub pack_checksum: Oid,
    pub idx_trailer: Oid,
    pub idx_computed: Oid,
    pub idx_checksum_ok: bool,
    pub fatal: Option<PError>,
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn u64be(b: &[u8]) -> u64 {
    let mut o = [0u8; 8];
    o.copy_from_slice(&b[..8]);
    u64::from_be_bytes(o)
}

fn read_fanout(buf: &[u8], start: usize) -> Vec<u32> {
    let mut cumulative = Vec::with_capacity(256);
    for i in 0..256 {
        let o = start + i * 4;
        cumulative.push(u32be(&buf[o..o + 4]));
    }
    cumulative
}

fn check_trailer(buf: &[u8], mut pos: usize) -> Result<(Oid, Oid, Oid), PError> {
    if pos + 40 > buf.len() {
        return Err(PError::Truncated {
            what: "index 尾部".to_string(),
            at: pos,
            need: 40,
        });
    }
    let pack_checksum = Oid::from_slice(&buf[pos..pos+20]).map_err(|e| PError::Io(e))?;
    let idx_trailer = Oid::from_slice(&buf[pos+20..pos+40]).map_err(|e| PError::Io(e))?;
    let mut h = Sha1::new();
    h.update(&buf[..pos + 20]);
    let r = h.finalize();
    let mut c = [0u8; 20];
    c.copy_from_slice(&r);
    let _ = &mut pos;
    Ok((pack_checksum, idx_trailer, Oid(c)))
}

fn parse_v2(buf: &[u8]) -> Result<ParsedIndex, PError> {
    let fanout_start = 8;
    let cumulative = read_fanout(buf, fanout_start);
    let n = cumulative[255] as usize;
    let mut pos = fanout_start + 256 * 4;

    let need = |p: usize, nbytes: usize| -> Result<(), PError> {
        if p + nbytes > buf.len() - 40 {
            Err(PError::Truncated {
                what: "index".to_string(),
                at: p,
                need: nbytes,
            })
        } else {
            Ok(())
        }
    };

    need(pos, n * 20)?;
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(Oid::from_slice(&buf[pos..pos+20]).map_err(|e| PError::Io(e))?);
        pos += 20;
    }

    need(pos, n * 4)?;
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32be(&buf[pos..pos + 4]));
        pos += 4;
    }

    need(pos, n * 4)?;
    let mut offsets: Vec<u64> = Vec::with_capacity(n);
    let mut large_slots: Vec<(usize, usize)> = Vec::new();
    for slot in 0..n {
        let raw = u32be(&buf[pos..pos + 4]);
        pos += 4;
        if raw & 0x8000_0000 != 0 {
            large_slots.push((slot, (raw & 0x7fff_ffff) as usize));
            offsets.push(0);
        } else {
            offsets.push(raw as u64);
        }
    }

    // 64 位大偏移表按 li 升序存放
    let mut large_values: std::collections::BTreeMap<usize, u64> =
        std::collections::BTreeMap::new();
    for &(_slot, li) in &large_slots {
        need(pos, 8)?;
        large_values.insert(li, u64be(&buf[pos..pos + 8]));
        pos += 8;
    }
    for (slot, li) in large_slots {
        offsets[slot] = *large_values
            .get(&li)
            .ok_or_else(|| PError::IndexMismatch(format!("大偏移索引 {} 缺失", li)))?;
    }

    let (pack_checksum, idx_trailer, idx_computed) = check_trailer(buf, pos)?;

    let entries: Vec<IdxEntry> = (0..n)
        .map(|i| IdxEntry {
            oid: oids[i],
            offset: offsets[i],
            crc32: Some(crcs[i]),
        })
        .collect();

    Ok(ParsedIndex {
        version: 2,
        entries,
        fanout: FanoutTable { cumulative },
        pack_checksum,
        idx_trailer,
        idx_computed,
        idx_checksum_ok: idx_computed == idx_trailer,
        fatal: None,
    })
}

fn parse_v1(buf: &[u8]) -> Result<ParsedIndex, PError> {
    let cumulative = read_fanout(buf, 0);
    let n = cumulative[255] as usize;
    let mut pos = 256 * 4;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        if pos + 24 > buf.len() - 40 {
            return Err(PError::Truncated {
                what: "v1 index 记录".to_string(),
                at: pos,
                need: 24,
            });
        }
        let off = u32be(&buf[pos..pos + 4]) as u64;
        let oid = Oid::from_slice(&buf[pos+4..pos+24]).map_err(|e| PError::Io(e))?;
        pos += 24;
        entries.push(IdxEntry {
            oid,
            offset: off,
            crc32: None,
        });
    }
    let (pack_checksum, idx_trailer, idx_computed) = check_trailer(buf, pos)?;
    Ok(ParsedIndex {
        version: 1,
        entries,
        fanout: FanoutTable { cumulative },
        pack_checksum,
        idx_trailer,
        idx_computed,
        idx_checksum_ok: idx_computed == idx_trailer,
        fatal: None,
    })
}

pub fn parse_index(buf: &[u8]) -> ParsedIndex {
    let empty = ParsedIndex {
        version: 0,
        entries: Vec::new(),
        fanout: FanoutTable {
            cumulative: vec![0; 256],
        },
        pack_checksum: Oid::zero(),
        idx_trailer: Oid::zero(),
        idx_computed: Oid::zero(),
        idx_checksum_ok: false,
        fatal: None,
    };
    if buf.len() < 256 * 4 + 40 {
        let mut e = empty;
        e.fatal = Some(PError::Truncated {
            what: "index 整体".to_string(),
            at: buf.len(),
            need: 256 * 4 + 40,
        });
        return e;
    }
    let is_v2 = &buf[0..4] == b"\xfftOc";
    let res = if is_v2 {
        let ver = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if ver != 2 {
            Err(PError::UnsupportedPackVersion(ver))
        } else {
            parse_v2(buf)
        }
    } else {
        parse_v1(buf)
    };
    match res {
        Ok(p) => p,
        Err(e) => {
            let mut x = empty;
            x.fatal = Some(e);
            x
        }
    }
}
