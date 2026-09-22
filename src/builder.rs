//! Minimal Git pack/index builders used by tests and by this crate's own
//! self-check facilities. No external `git` binary is invoked.

use crate::crc::crc32;
use crate::gitobj::git_oid;
use crate::types::ObjType;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;

pub fn zlib_deflate(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn encode_size_header(type_code: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = (type_code << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        b |= 0x80;
    }
    out.push(b);
    while rest != 0 {
        let mut nb = (rest as u8) & 0x7f;
        rest >>= 7;
        if rest != 0 {
            nb |= 0x80;
        }
        out.push(nb);
    }
    out
}

fn encode_ofs_distance(dist: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut b = (dist & 0x7f) as u8;
    let mut rest = dist >> 7;
    let mut stack = Vec::new();
    while rest != 0 {
        stack.push((rest & 0x7f) as u8);
        rest >>= 7;
    }
    bytes.push(b | if stack.is_empty() { 0 } else { 0x80 });
    while let Some(mut x) = stack.pop() {
        let more = !stack.is_empty();
        if more {
            x |= 0x80;
        }
        bytes.push(x);
    }
    bytes
}

pub enum PackEntrySpec<'a> {
    Base {
        kind: ObjType,
        data: &'a [u8],
        force_spoof_size: Option<u64>,
    },
    OfsDelta {
        base_index: usize,
        delta: &'a [u8],
    },
    RefDelta {
        base_oid: [u8; 20],
        delta: &'a [u8],
    },
}

pub struct BuiltEntry {
    pub offset: u64,
    pub crc_region: Vec<u8>,
    pub declared_oid: String,
}

pub fn build_pack(specs: &[PackEntrySpec]) -> (Vec<u8>, Vec<BuiltEntry>) {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(specs.len() as u32).to_be_bytes());

    let mut built = Vec::new();
    let mut offsets = Vec::new();
    for spec in specs {
        let offset = body.len() as u64;
        offsets.push(offset);
        match spec {
            PackEntrySpec::Base {
                kind,
                data,
                force_spoof_size,
            } => {
                let code = match kind {
                    ObjType::Commit => 1,
                    ObjType::Tree => 2,
                    ObjType::Blob => 3,
                    ObjType::Tag => 4,
                    _ => panic!("bad base kind"),
                };
                let size = force_spoof_size.unwrap_or(data.len() as u64);
                body.extend_from_slice(&encode_size_header(code, size));
                body.extend_from_slice(&zlib_deflate(data));
                built.push(BuiltEntry {
                    offset,
                    crc_region: Vec::new(),
                    declared_oid: git_oid(*kind, data),
                });
            }
            PackEntrySpec::OfsDelta {
                base_index,
                delta,
            } => {
                let base_off = offsets[*base_index];
                let dist = offset - base_off;
                body.extend_from_slice(&encode_size_header(6, delta.len() as u64));
                body.extend_from_slice(&encode_ofs_distance(dist));
                body.extend_from_slice(&zlib_deflate(delta));
                built.push(BuiltEntry {
                    offset,
                    crc_region: Vec::new(),
                    declared_oid: String::new(),
                });
            }
            PackEntrySpec::RefDelta { base_oid, delta } => {
                body.extend_from_slice(&encode_size_header(7, delta.len() as u64));
                body.extend_from_slice(base_oid);
                body.extend_from_slice(&zlib_deflate(delta));
                built.push(BuiltEntry {
                    offset,
                    crc_region: Vec::new(),
                    declared_oid: String::new(),
                });
            }
        }
        let end = body.len();
        built.last_mut().unwrap().crc_region = body[offset as usize..end].to_vec();
    }

    let checksum = {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&body);
        let r = h.finalize();
        r.to_vec()
    };
    body.extend_from_slice(&checksum);
    (body, built)
}

pub struct IdxRow {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

pub fn build_idx(rows: &[IdxRow], pack_checksum: &[u8; 20]) -> Vec<u8> {
    let mut sorted: Vec<IdxRow> = rows
        .iter()
        .map(|r| IdxRow {
            oid: r.oid,
            crc32: r.crc32,
            offset: r.offset,
        })
        .collect();
    sorted.sort_by(|a, b| a.oid.cmp(&b.oid));
    let n = sorted.len();

    let mut out = Vec::new();
    out.extend_from_slice(&0xff744f63u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    let mut count = 0u32;
    let mut bucket = 0usize;
    for row in &sorted {
        while bucket <= row.oid[0] as usize {
            fanout[bucket] = count;
            bucket += 1;
        }
        count += 1;
    }
    while bucket < 256 {
        fanout[bucket] = count;
        bucket += 1;
    }
    for v in fanout {
        out.extend_from_slice(&v.to_be_bytes());
    }

    for row in &sorted {
        out.extend_from_slice(&row.oid);
    }
    for row in &sorted {
        out.extend_from_slice(&row.crc32.to_be_bytes());
    }
    let large_start = 8 + 1024 + n * 20 + n * 4 + n * 4;
    let mut large_offsets: Vec<u64> = Vec::new();
    for row in &sorted {
        if row.offset < 0x8000_0000 {
            out.extend_from_slice(&(row.offset as u32).to_be_bytes());
        } else {
            let idx = large_offsets.len() as u32 | 0x8000_0000;
            out.extend_from_slice(&idx.to_be_bytes());
            large_offsets.push(row.offset);
        }
    }
    for off in &large_offsets {
        out.extend_from_slice(&off.to_be_bytes());
    }
    let _ = large_start;

    out.extend_from_slice(pack_checksum);
    let idx_ck = {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&out);
        let r = h.finalize();
        r.to_vec()
    };
    out.extend_from_slice(&idx_ck);
    out
}

/// Build an idx for a freshly built pack from BuiltEntry metadata + oids.
pub fn build_idx_for(
    pack: &[u8],
    entries: &[BuiltEntry],
    oids: &[[u8; 20]],
) -> Vec<u8> {
    let rows: Vec<IdxRow> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| IdxRow {
            oid: oids[i],
            crc32: crc32(&e.crc_region),
            offset: e.offset,
        })
        .collect();
    let mut pack_ck = [0u8; 20];
    pack_ck.copy_from_slice(&pack[pack.len() - 20..]);
    build_idx(&rows, &pack_ck)
}

pub fn loose_object(kind: ObjType, data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    framed.extend_from_slice(kind.name().as_bytes());
    framed.push(b' ');
    framed.extend_from_slice(data.len().to_string().as_bytes());
    framed.push(0);
    framed.extend_from_slice(data);
    zlib_deflate(&framed)
}

pub fn parse_oid_bytes(hex: &str) -> [u8; 20] {
    let v = crate::hexutil::from_hex(hex).unwrap();
    v.try_into().unwrap()
}

/// Construct a delta that appends `suffix` to the base and preserves all base bytes.
pub fn append_delta(base_len: u64, suffix: &[u8]) -> Vec<u8> {
    let mut d = encode_delta_varint(base_len);
    d.extend_from_slice(&encode_delta_varint(base_len + suffix.len() as u64));
    // copy entire base
    push_copy(&mut d, 0, base_len as usize);
    // insert suffix
    d.push(suffix.len() as u8);
    d.extend_from_slice(suffix);
    d
}

pub fn encode_delta_varint(mut v: u64) -> Vec<u8> {
    let mut bytes = vec![(v & 0x7f) as u8];
    v >>= 7;
    while v != 0 {
        bytes.push((v & 0x7f) as u8);
        v >>= 7;
    }
    bytes.reverse();
    let upto = bytes.len().saturating_sub(1);
    for b in bytes.iter_mut().take(upto) {
        *b |= 0x80;
    }
    bytes
}

fn push_copy(d: &mut Vec<u8>, offset: usize, len: usize) {
    let mut opcode = 0x80u8;
    let mut args = Vec::new();
    for i in 0..4 {
        let byte = ((offset >> (8 * i)) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << i;
            args.push(byte);
        }
    }
    for i in 0..3 {
        let byte = ((len >> (8 * i)) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << (4 + i);
            args.push(byte);
        }
    }
    d.push(opcode);
    d.extend_from_slice(&args);
}

pub fn base_spec(data: &[u8]) -> PackEntrySpec<'_> {
    PackEntrySpec::Base {
        kind: ObjType::Blob,
        data,
        force_spoof_size: None,
    }
}
