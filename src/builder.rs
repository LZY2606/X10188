//! Synthetic Git pack/index/loose writer used by tests. Pure Rust:
//! exercises the same on-disk formats the parser consumes without ever
//! invoking system git.

use crate::model::{ObjType, Oid};
use crate::parse::git_object::RawObject;
use crate::parse::varint::write as write_varint;
use crc32fast::Hasher as CrcHasher;
use sha1::{Digest, Sha1};
use std::io::Write;

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

pub fn raw(typ: ObjType, content: &[u8]) -> RawObject {
    RawObject { typ, content: content.to_vec() }
}

pub fn raw_oid(typ: ObjType, content: &[u8]) -> String {
    raw(typ, content).oid()
}

#[derive(Clone)]
pub enum BuildEntry {
    Plain { obj: RawObject },
    OfsDelta { base: usize, delta: Vec<u8>, result_size: u64 },
    RefDelta { base_oid: Oid, delta: Vec<u8>, result_size: u64 },
}

pub struct PackBuilder {
    entries: Vec<BuildEntry>,
}

impl PackBuilder {
    pub fn new() -> Self {
        PackBuilder { entries: Vec::new() }
    }

    pub fn add_plain(&mut self, obj: RawObject) -> usize {
        let idx = self.entries.len();
        self.entries.push(BuildEntry::Plain { obj });
        idx
    }

    pub fn add_ofs_delta(&mut self, base: usize, delta: Vec<u8>, result_size: u64) -> usize {
        let idx = self.entries.len();
        self.entries.push(BuildEntry::OfsDelta { base, delta, result_size });
        idx
    }

    pub fn add_ref_delta(&mut self, base_oid: Oid, delta: Vec<u8>, result_size: u64) -> usize {
        let idx = self.entries.len();
        self.entries.push(BuildEntry::RefDelta { base_oid, delta, result_size });
        idx
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Build the pack, returning `(bytes, header offsets)`.
    pub fn build(&self) -> (Vec<u8>, Vec<u64>) {
        self.build_with(|_, _| {})
    }

    /// Like [`Self::build`], but invokes `patch(header_offset, header_bytes)`
    /// right after each header is appended, enabling corruption tests.
    pub fn build_with(
        &self,
        patch: impl Fn(usize, &mut Vec<u8>),
    ) -> (Vec<u8>, Vec<u64>) {
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());

        let mut offsets = Vec::with_capacity(self.entries.len());
        for (i, entry) in self.entries.iter().enumerate() {
            let header_offset = out.len();
            offsets.push(header_offset as u64);
            match entry {
                BuildEntry::Plain { obj } => {
                    let frame = obj.frame();
                    // Stored "content" inside a pack is the raw object frame.
                    let compressed = deflate(&frame);
                    let mut header = crate::parse::pack::varint_size_wire(
                        frame.len() as u64,
                        obj.typ as u8,
                    );
                    patch(i, &mut header);
                    out.extend_from_slice(&header);
                    out.extend_from_slice(&compressed);
                }
                BuildEntry::OfsDelta { base, delta, result_size } => {
                    let compressed = deflate(delta);
                    let mut header = crate::parse::pack::varint_size_wire(*result_size, 6);
                    let distance = header_offset as u64 - offsets[*base];
                    encode_ofs_distance(distance, &mut header);
                    patch(i, &mut header);
                    out.extend_from_slice(&header);
                    out.extend_from_slice(&compressed);
                }
                BuildEntry::RefDelta { base_oid, delta, result_size } => {
                    let compressed = deflate(delta);
                    let mut header = crate::parse::pack::varint_size_wire(*result_size, 7);
                    patch(i, &mut header);
                    out.extend_from_slice(&header);
                    out.extend_from_slice(&base_oid.to_bytes().unwrap());
                    out.extend_from_slice(&compressed);
                }
            }
        }

        let mut hasher = Sha1::new();
        hasher.update(&out);
        let digest = hasher.finalize();
        out.extend_from_slice(&digest);
        (out, offsets)
    }
}

/// Encode the ofs-delta negative distance (same encoding the parser reads).
pub fn encode_ofs_distance(mut distance: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        let mut byte = (distance & 0x7f) as u8 | 0x80;
        distance >>= 7;
        bytes.push(byte);
    }
    bytes.reverse();
    if bytes.len() > 1 {
        for b in &mut bytes[..bytes.len() - 1] {
            *b |= 0x80;
        }
    }
    out.extend_from_slice(&bytes);
}

/// Build a v2 index for a pack.
/// `oid_at(off, entry_index)` and the CRCs are computed from pack bytes.
pub fn build_index_v2(
    pack: &[u8],
    offsets: &[u64],
    entry_ends: &[u64],
    oids: &[Oid],
) -> Vec<u8> {
    build_index_v2_with(pack, offsets, entry_ends, oids, |_, _, bytes| {
        let _ = bytes;
    })
}

pub fn build_index_v2_with(
    pack: &[u8],
    offsets: &[u64],
    entry_ends: &[u64],
    oids: &[Oid],
    mut patch: impl FnMut(usize, &mut u32, &[u8]),
) -> Vec<u8> {
    let n = offsets.len();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| oids[a].0.cmp(&oids[b].0));

    let mut out = Vec::new();
    out.extend_from_slice(&[0xff, b't', b'O', b'c']);
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    for oid in oids {
        let first = u8::from_str_radix(&oid.0[..2], 16).unwrap();
        fanout[first as usize] += 1;
    }
    let mut cumulative = 0u32;
    for count in fanout.iter_mut() {
        cumulative += *count;
        *count = cumulative;
    }
    for bucket in fanout {
        out.extend_from_slice(&bucket.to_be_bytes());
    }

    for &i in &order {
        out.extend_from_slice(&oids[i].to_bytes().unwrap());
    }

    let mut crcs: Vec<u32> = Vec::with_capacity(n);
    for &i in &order {
        let start = offsets[i] as usize;
        let end = entry_ends[i] as usize;
        let bytes = &pack[start..end];
        let mut hasher = CrcHasher::new();
        hasher.update(bytes);
        let mut crc = hasher.finalize();
        patch(i, &mut crc, bytes);
        crcs.push(crc);
    }
    for crc in &crcs {
        out.extend_from_slice(&crc.to_be_bytes());
    }

    for &i in &order {
        out.extend_from_slice(&(offsets[i] as u32).to_be_bytes());
    }

    // Pack checksum = SHA-1 of pack body excluding its trailer.
    let mut pack_hasher = Sha1::new();
    pack_hasher.update(&pack[..pack.len() - 20]);
    let pack_sum: [u8; 20] = pack_hasher.finalize().into();
    out.extend_from_slice(&pack_sum);

    let mut self_hasher = Sha1::new();
    self_hasher.update(&out);
    let self_sum: [u8; 20] = self_hasher.finalize().into();
    out.extend_from_slice(&self_sum);
    out
}

pub fn build_loose(obj: &RawObject) -> (String, Vec<u8>) {
    let oid = obj.oid();
    let rel = format!("objects/{}/{}", &oid[..2], &oid[2..]);
    (rel, deflate(&obj.frame()))
}

/// A trivial delta: full insert of `target` (base must be empty or this
/// must be used with a matching base_size 0). For realistic chains use
/// [`delta_insert_then_copy`].
pub fn delta_all_insert(base_len: u64, target: &[u8]) -> Vec<u8> {
    assert!(target.len() <= 127);
    let mut d = Vec::new();
    write_varint(base_len, &mut d);
    write_varint(target.len() as u64, &mut d);
    d.push(target.len() as u8);
    d.extend_from_slice(target);
    d
}

pub fn delta_insert_then_copy(base: &[u8], insert: &[u8], copy_off: u32, copy_len: u32) -> Vec<u8> {
    assert!(insert.len() <= 127);
    let target_len = insert.len() + copy_len as usize;
    let mut d = Vec::new();
    write_varint(base.len() as u64, &mut d);
    write_varint(target_len as u64, &mut d);
    d.push(insert.len() as u8);
    d.extend_from_slice(insert);
    // COPY opcode, offset and size bytes.
    let mut op = 0x80u8;
    let mut args = Vec::new();
    for bit in 0u32..4 {
        if copy_off & (0xff << (8 * bit)) != 0 {
            op |= 1 << bit;
            args.push(((copy_off >> (8 * bit)) & 0xff) as u8);
        }
    }
    for bit in 0u32..3 {
        if copy_len & (0xff << (8 * bit)) != 0 {
            op |= 1 << (4 + bit);
            args.push(((copy_len >> (8 * bit)) & 0xff) as u8);
        }
    }
    d.push(op);
    d.extend(args);
    d
}
