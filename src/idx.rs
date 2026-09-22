//! Pack index (.idx) parsing: v2 fanout/oid/CRC/offset tables and legacy v1.

use crate::oid::Oid;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: Oid,
    pub offset: u64,
    pub crc32: Option<u32>,
    /// Entry lives in this other pack (offset high bit set, 64-bit table).
    pub large_offset_index: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub version: u32,
    pub entries: Vec<IdxEntry>,
    pub fanout: [u32; 256],
    pub pack_checksum: Option<Oid>,
    pub idx_checksum: Option<Oid>,
    pub computed_idx_checksum: Option<Oid>,
    pub idx_checksum_ok: bool,
    pub errors: Vec<String>,
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse a pack index. Accepts v2 (magic `\\377tOc`) and legacy v1.
pub fn parse_idx(buf: &[u8]) -> IdxInfo {
    let mut errors = Vec::new();
    if buf.len() < 8 {
        return fail("index shorter than 8 bytes");
    }

    let is_v2 = &buf[0..4] == b"\xff\x74\x4f\x63";
    if is_v2 {
        parse_v2(buf)
    } else {
        parse_v1(buf)
    }
}

fn fail(msg: &str) -> IdxInfo {
    IdxInfo {
        version: 0,
        entries: Vec::new(),
        fanout: [0u32; 256],
        pack_checksum: None,
        idx_checksum: None,
        computed_idx_checksum: None,
        idx_checksum_ok: false,
        errors: vec![msg.to_string()],
    }
}

fn check_fanout(fan: &[u32; 256], errors: &mut Vec<String>) {
    for w in fan.windows(2) {
        if w[1] < w[0] {
            errors.push("fanout table is not monotonic".into());
            return;
        }
    }
}

fn parse_v2(buf: &[u8]) -> IdxInfo {
    let mut errors = Vec::new();
    let version = u32be(&buf[4..8]);
    if version != 2 {
        errors.push(format!("unknown idx version {version}"));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(&buf[8 + 4 * i..12 + 4 * i]);
    }
    check_fanout(&fanout, &mut errors);
    let n = fanout[255] as usize;
    let mut p = 8 + 256 * 4;

    let need = |p: usize, nbytes: usize| -> Result<(), String> {
        if p + nbytes > buf.len() {
            Err(format!("idx table overruns file at byte {p}"))
        } else {
            Ok(())
        }
    };

    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        if let Err(e) = need(p, 20) {
            errors.push(e);
            return finish_v2(buf, version, fanout, Vec::new(), errors);
        }
        oids.push(Oid::from_bytes(&buf[p..p + 20]).unwrap());
        p += 20;
    }

    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        if let Err(e) = need(p, 4) {
            errors.push(e);
            return finish_v2(buf, version, fanout, Vec::new(), errors);
        }
        crcs.push(u32be(&buf[p..p + 4]));
        p += 4;
    }

    let mut offsets32 = Vec::with_capacity(n);
    for _ in 0..n {
        if let Err(e) = need(p, 4) {
            errors.push(e);
            return finish_v2(buf, version, fanout, Vec::new(), errors);
        }
        offsets32.push(u32be(&buf[p..p + 4]));
        p += 4;
    }

    let entries = offsets32
        .iter()
        .enumerate()
        .map(|(i, &raw)| {
            if raw & 0x8000_0000 != 0 {
                IdxEntry {
                    oid: oids[i],
                    offset: 0,
                    crc32: Some(crcs[i]),
                    large_offset_index: Some(u64::from(raw & 0x7fff_ffff)),
                }
            } else {
                IdxEntry {
                    oid: oids[i],
                    offset: u64::from(raw),
                    crc32: Some(crcs[i]),
                    large_offset_index: None,
                }
            }
        })
        .collect();

    finish_v2(buf, version, fanout, entries, errors)
}

fn finish_v2(
    buf: &[u8],
    version: u32,
    fanout: [u32; 256],
    mut entries: Vec<IdxEntry>,
    mut errors: Vec<String>,
) -> IdxInfo {
    let n = fanout[255] as usize;
    let off64_start = 8 + 256 * 4 + n * (20 + 4 + 4);
    for e in entries.iter_mut() {
        if let Some(idx) = e.large_offset_index {
            let at = off64_start + idx as usize * 8;
            if at + 8 <= buf.len().saturating_sub(40) {
                e.offset = u64::from_be_bytes(buf[at..at + 8].try_into().unwrap());
            } else {
                errors.push(format!("64-bit offset table overrun for {}", e.oid));
            }
        }
    }
    let trailer = buf.len().saturating_sub(40);
    let mut pack_checksum = None;
    let mut idx_checksum = None;
    let mut computed = None;
    let mut ok = false;
    if buf.len() >= 40 + 8 {
        pack_checksum = Oid::from_bytes(&buf[trailer..trailer + 20]).ok();
        idx_checksum = Oid::from_bytes(&buf[trailer + 20..trailer + 40]).ok();
        let mut h = Sha1::new();
        h.update(&buf[..trailer + 20]);
        let c = Oid(h.finalize().into());
        computed = Some(c);
        ok = Some(c) == idx_checksum;
        if !ok {
            errors.push("idx trailing checksum mismatch".into());
        }
    } else {
        errors.push("idx missing trailing checksums".into());
    }
    IdxInfo {
        version,
        entries,
        fanout,
        pack_checksum,
        idx_checksum,
        computed_idx_checksum: computed,
        idx_checksum_ok: ok,
        errors,
    }
}

fn parse_v1(buf: &[u8]) -> IdxInfo {
    let mut errors = Vec::new();
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32be(&buf[i * 4..i * 4 + 4]);
    }
    check_fanout(&fanout, &mut errors);
    let n = fanout[255] as usize;
    let mut p = 256 * 4;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        if p + 24 > buf.len().saturating_sub(40) {
            errors.push(format!("v1 entry table overruns at byte {p}"));
            return IdxInfo {
                version: 1,
                entries,
                fanout,
                pack_checksum: None,
                idx_checksum: None,
                computed_idx_checksum: None,
                idx_checksum_ok: false,
                errors,
            };
        }
        let offset = u32be(&buf[p..p + 4]);
        let oid = Oid::from_bytes(&buf[p + 4..p + 24]).unwrap();
        p += 24;
        entries.push(IdxEntry {
            oid,
            offset: u64::from(offset),
            crc32: None,
            large_offset_index: None,
        });
    }
    let trailer = buf.len().saturating_sub(40);
    let pack_checksum = Oid::from_bytes(&buf[trailer..trailer + 20]).ok();
    let idx_checksum = Oid::from_bytes(&buf[trailer + 20..trailer + 40]).ok();
    let mut h = Sha1::new();
    h.update(&buf[..trailer + 20]);
    let computed = Oid(h.finalize().into());
    let ok = Some(computed) == idx_checksum;
    if !ok {
        errors.push("idx trailing checksum mismatch".into());
    }
    IdxInfo {
        version: 1,
        entries,
        fanout,
        pack_checksum,
        idx_checksum,
        computed_idx_checksum: Some(computed),
        idx_checksum_ok: ok,
        errors,
    }
}

/// Compute the packed-entry CRC32 that an idx stores: zlib stream plus the
/// full entry header, i.e. every byte from the entry offset up to the next
/// entry's offset.
pub fn entry_crc32(pack: &[u8], entry_offset: u64, next_offset: u64) -> u32 {
    let s = entry_offset as usize;
    let e = next_offset as usize;
    crc32fast::hash(&pack[s..e.min(pack.len())])
}
