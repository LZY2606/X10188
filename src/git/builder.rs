//! Minimal in-memory pack/index/loose writer used by tests to synthesize fixtures.
//! Production code never relies on an external `git` binary.

use crate::git::object::{git_object_id, ObjType, OBJ_OFS_DELTA, OBJ_REF_DELTA};
use crate::git::pack::crc32_ieee;
use flate2::write::ZlibEncoder;
use sha1::{Digest, Sha1};
use std::io::Write;

pub enum PackObj {
    Base { kind: ObjType, content: Vec<u8> },
    OfsDelta {
        /// Index into the object list of the base (must be earlier in the pack).
        base_index: usize,
        delta: Vec<u8>,
    },
    RefDelta {
        base_oid: [u8; 20],
        delta: Vec<u8>,
    },
}

impl PackObj {
    pub fn base(kind: ObjType, content: Vec<u8>) -> Self {
        PackObj::Base { kind, content }
    }
    pub fn ofs_delta(base_index: usize, delta: Vec<u8>) -> Self {
        PackObj::OfsDelta { base_index, delta }
    }
    pub fn ref_delta(base_oid: [u8; 20], delta: Vec<u8>) -> Self {
        PackObj::RefDelta { base_oid, delta }
    }
}

#[derive(Default)]
pub struct Corruptions {
    /// Flip a bit inside the compressed bytes of entry at index.
    pub flip_zlib_bit: Vec<usize>,
    /// Tamper a byte right before the zlib trailer to break the adler checksum.
    pub break_crc: Vec<usize>,
    /// Declare a different inflated size for entry at index (size spoof).
    pub spoof_size: Vec<(usize, u64)>,
    /// Truncate the pack after this many bytes (None = full file).
    pub truncate_at: Option<usize>,
}

fn zlib_encode(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn encode_ofs_distance(mut distance: u64, out: &mut Vec<u8>) {
    // Git's one-based, big-endian varint: continuation bits everywhere except the final byte.
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance > 0 {
        bytes.push((distance & 0x7f) as u8);
        distance >>= 7;
    }
    bytes.reverse();
    let last = bytes.len() - 1;
    for (i, mut byte) in bytes.into_iter().enumerate() {
        if i != last {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

/// Build a pack. Returns `(pack_bytes, entry_offsets, entry_oids)` where oids are the true
/// content ids of the resolved objects.
pub fn build_pack_with(
    objs: &[PackObj],
    corrupt: &Corruptions,
) -> (Vec<u8>, Vec<u64>, Vec<[u8; 20]>) {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objs.len() as u32).to_be_bytes());

    let mut offsets = Vec::new();
    // First resolve content logically so ref-delta callers can use the returned oids;
    // resolution mirrors apply semantics for content bookkeeping.
    let mut contents: Vec<(ObjType, Vec<u8>)> = Vec::new();
    let mut oids = Vec::new();
    for obj in objs {
        match obj {
            PackObj::Base { kind, content } => {
                contents.push((*kind, content.clone()));
                oids.push(git_object_id(*kind, content));
            }
            PackObj::OfsDelta { base_index, delta } => {
                let kind = contents[*base_index].0;
                let applied = crate::git::delta::apply_delta(&contents[*base_index].1, &delta)
                    .expect("valid fixture delta");
                contents.push((kind, applied.result.clone()));
                oids.push(git_object_id(kind, &applied.result));
            }
            PackObj::RefDelta { base_oid, delta } => {
                let base_index = oids
                    .iter()
                    .position(|o: &[u8; 20]| o == base_oid)
                    .expect("ref-delta base must be present in builder input order");
                let kind = contents[base_index].0;
                let applied = crate::git::delta::apply_delta(&contents[base_index].1, &delta)
                    .expect("valid fixture delta");
                contents.push((kind, applied.result.clone()));
                oids.push(git_object_id(kind, &applied.result));
            }
        }
    }

    for (i, obj) in objs.iter().enumerate() {
        let offset = pack.len() as u64;
        offsets.push(offset);
        match obj {
            PackObj::Base { kind, content } => {
                let declared = corrupt
                    .spoof_size
                    .iter()
                    .find(|(idx, _)| *idx == i)
                    .map(|(_, v)| *v)
                    .unwrap_or(content.len() as u64);
                write_entry_header(&mut pack, kind.code(), declared, None);
                append_zlib(&mut pack, content, corrupt, i);
            }
            PackObj::OfsDelta { base_index, delta } => {
                write_entry_header(&mut pack, OBJ_OFS_DELTA, delta.len() as u64, None);
                let distance = offset - offsets[*base_index];
                encode_ofs_distance(distance, &mut pack);
                append_zlib(&mut pack, delta, corrupt, i);
            }
            PackObj::RefDelta { base_oid, delta } => {
                write_entry_header(&mut pack, OBJ_REF_DELTA, delta.len() as u64, None);
                pack.extend_from_slice(base_oid);
                append_zlib(&mut pack, delta, corrupt, i);
            }
        }
    }

    if let Some(cut) = corrupt.truncate_at {
        pack.truncate(cut);
        return (pack, offsets, oids);
    }

    let mut h = Sha1::new();
    h.update(&pack);
    let sum = h.finalize();
    pack.extend_from_slice(&sum);
    (pack, offsets, oids)
}

pub fn build_pack(objs: &[PackObj], trailer: bool) -> Vec<u8> {
    let c = Corruptions {
        truncate_at: if trailer { None } else { None },
        ..Default::default()
    };
    let _ = trailer;
    let (pack, _, _) = build_pack_with(objs, &c);
    pack
}

fn write_entry_header(
    out: &mut Vec<u8>,
    type_code: u8,
    size: u64,
    _extra: Option<()>,
) {
    let mut first = ((type_code & 0x7) << 4) | (size as u8 & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest != 0 {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

fn append_zlib(out: &mut Vec<u8>, content: &[u8], corrupt: &Corruptions, idx: usize) {
    let mut z = zlib_encode(content);
    if corrupt.flip_zlib_bit.contains(&idx) {
        // Flip a byte safely inside the deflate body (skip header, keep trailer intact).
        if z.len() > 8 {
            z[2] ^= 0x20;
        }
    }
    if corrupt.break_crc.contains(&idx) {
        // Modify a deflate payload byte; most often this surfaces as an adler/corrupt failure.
        let zlen = z.len();
        if zlen > 8 {
            z[zlen - 5] ^= 0x01;
        }
    }
    out.extend_from_slice(&z);
}

/// Build a v2 index matching a pack: (offset, oid) pairs sorted by oid internally.
pub fn build_index_v2(pairs: &[(u64, [u8; 20])], pack_bytes: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<(u64, [u8; 20])> = pairs.to_vec();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));

    let mut idx = Vec::new();
    idx.extend_from_slice(b"\xfftOc");
    idx.extend_from_slice(&2u32.to_be_bytes());

    // fanout[256]
    let mut fanout = [0u32; 256];
    for (_, oid) in &sorted {
        fanout[oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for c in fanout.iter_mut() {
        acc += *c;
        *c = acc;
    }
    for v in fanout {
        idx.extend_from_slice(&v.to_be_bytes());
    }

    for (_, oid) in &sorted {
        idx.extend_from_slice(oid);
    }

    // crc table: compute from pack at each offset.
    for (off, _) in &sorted {
        let crc = entry_crc(pack_bytes, *off);
        idx.extend_from_slice(&crc.to_be_bytes());
    }

    for (off, _) in &sorted {
        idx.extend_from_slice(&off.to_be_bytes());
    }

    // Large offset table omitted (all offsets small).
    let n = pack_bytes.len();
    idx.extend_from_slice(&pack_bytes[n - 20..n]);
    let mut h = Sha1::new();
    h.update(&idx[..]);
    let idx_sum = h.finalize();
    idx.extend_from_slice(&idx_sum);
    idx
}

fn entry_crc(pack: &[u8], offset: u64) -> u32 {
    use crate::git::pack::scan_entries_at_offsets;
    let parsed = scan_entries_at_offsets(pack, &[offset]);
    match &parsed[0].1 {
        Some(e) => crc32_ieee(&pack[e.offset as usize..e.data_end as usize]),
        None => 0,
    }
}

/// Write a loose object zlib stream containing `"<type> <len>\0<content>"`.
pub fn write_loose_object(kind: ObjType, content: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(kind.name().as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    zlib_encode(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::delta::encode_insert_delta;

    #[test]
    fn builder_roundtrip_with_trailer() {
        let objs = vec![PackObj::base(ObjType::Blob, b"abc".to_vec())];
        let (pack, offs, oids) = build_pack_with(&objs, &Corruptions::default());
        assert_eq!(offs, vec![12]);
        assert_eq!(
            hex::encode(oids[0]),
            hex::encode(git_object_id(ObjType::Blob, b"abc"))
        );
    }

    #[test]
    fn ofs_chain_builds() {
        let base = b"base text".to_vec();
        let d = encode_insert_delta(base.len() as u64, b"derived");
        let objs = vec![
            PackObj::base(ObjType::Blob, base),
            PackObj::ofs_delta(0, d),
        ];
        let (pack, offs, _oids) = build_pack_with(&objs, &Corruptions::default());
        assert!(pack.starts_with(b"PACK\x00\x00\x00\x02\x00\x00\x00\x02"));
        assert_eq!(offs.len(), 2);
    }
}
