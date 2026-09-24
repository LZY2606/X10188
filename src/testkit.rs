//! Builders for hand-crafted git pack / idx / loose fixtures.
//! Used by the test-suite (and available to embedders) so that no test ever
//! shells out to the system `git` binary.

use crate::gitobj::{object_id, ObjType};
use flate2::{Compress, Compression, FlushCompress, Status};

/// zlib-compress `data` and return the compressed bytes.
pub fn zdeflate(data: &[u8]) -> Vec<u8> {
    let mut c = Compress::new(Compression::default(), true);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    let mut pos = 0usize;
    loop {
        let in_before = c.total_in();
        let out_before = c.total_out();
        let flush = if pos == data.len() {
            FlushCompress::Finish
        } else {
            FlushCompress::None
        };
        let status = c
            .compress(&data[pos..], &mut buf, flush)
            .expect("compress");
        pos += (c.total_in() - in_before) as usize;
        out.extend_from_slice(&buf[..(c.total_out() - out_before) as usize]);
        if status == Status::StreamEnd {
            return out;
        }
    }
}

/// Encode the pack object-entry header (type + size varint).
pub fn entry_header(typ: ObjType, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut size = size;
    let mut first = (typ.code() << 4) as u8 | (size as u8 & 0x0f);
    size >>= 4;
    if size > 0 {
        first |= 0x80;
    }
    out.push(first);
    while size > 0 {
        let mut b = (size as u8) & 0x7f;
        size >>= 7;
        if size > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Encode an ofs-delta negative offset (distance to the base entry).
pub fn ofs_distance(mut dist: u64) -> Vec<u8> {
    let mut bytes = vec![(dist & 0x7f) as u8];
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(((dist & 0x7f) as u8) | 0x80);
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

/// A single pack object; either a full object or a delta.
pub enum PackObj {
    Full(ObjType, Vec<u8>),
    /// Delta against the entry at `base_distance` bytes before this entry.
    OfsDelta { base_distance: u64, delta: Vec<u8> },
    /// Delta against the object with the given id (may be external).
    RefDelta { base_oid: String, delta: Vec<u8> },
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    /// Offset of each entry, in insertion order.
    pub offsets: Vec<u64>,
}

/// Build a complete pack (with correct sha1 trailer) from the given objects.
pub fn build_pack(objs: &[PackObj]) -> BuiltPack {
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(objs.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    for obj in objs {
        offsets.push(out.len() as u64);
        match obj {
            PackObj::Full(typ, content) => {
                out.extend_from_slice(&entry_header(*typ, content.len() as u64));
                out.extend_from_slice(&zdeflate(content));
            }
            PackObj::OfsDelta { base_distance, delta } => {
                out.extend_from_slice(&entry_header(ObjType::OfsDelta, delta.len() as u64));
                out.extend_from_slice(&ofs_distance(*base_distance));
                out.extend_from_slice(&zdeflate(delta));
            }
            PackObj::RefDelta { base_oid, delta } => {
                out.extend_from_slice(&entry_header(ObjType::RefDelta, delta.len() as u64));
                out.extend_from_slice(&hex::decode(base_oid).expect("oid hex"));
                out.extend_from_slice(&zdeflate(delta));
            }
        }
    }
    let trailer = crate::gitobj::sha1_hex(&out);
    out.extend_from_slice(&hex::decode(trailer).expect("trailer hex"));
    BuiltPack { bytes: out, offsets }
}

/// Build a git delta: copy `base` fully, then append `extra` bytes.
pub fn delta_append(base_len: usize, extra: &[u8], result_len: usize) -> Vec<u8> {
    let mut d = Vec::new();
    push_delta_varint(&mut d, base_len as u64);
    push_delta_varint(&mut d, result_len as u64);
    if base_len > 0 {
        // copy offset=0 len=base_len
        d.push(0x90); // copy, size byte 0 present
        let mut len = base_len;
        let mut size_bytes = Vec::new();
        while len > 0 {
            size_bytes.push((len & 0xff) as u8);
            len >>= 8;
        }
        // rebuild opcode with the right size bits
        let mut cmd = 0x80u8; // offset bits all zero (offset=0)
        for (i, b) in size_bytes.iter().enumerate() {
            cmd |= 0x10 << i;
            let _ = b;
        }
        d.pop();
        d.push(cmd);
        for b in &size_bytes {
            d.push(*b);
        }
    }
    if !extra.is_empty() {
        assert!(extra.len() < 128, "single insert op limited to 127 bytes");
        d.push(extra.len() as u8);
        d.extend_from_slice(extra);
    }
    d
}

fn push_delta_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// Build a v2 index for `pack_bytes` given (oid, offset) pairs.
/// `crc_override` lets tests inject a wrong CRC for one oid.
pub fn build_idx(
    pack_bytes: &[u8],
    mut entries: Vec<(String, u64)>,
    crc_override: Option<(&str, u32)>,
) -> Vec<u8> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _) in &entries {
        let first = u8::from_str_radix(&oid[0..2], 16).unwrap();
        fanout[first as usize] += 1;
    }
    for i in 1..256 {
        fanout[i] += fanout[i - 1];
    }
    for f in fanout {
        out.extend_from_slice(&f.to_be_bytes());
    }
    for (oid, _) in &entries {
        out.extend_from_slice(&hex::decode(oid).unwrap());
    }
    for (oid, offset) in &entries {
        let crc = match crc_override {
            Some((o, c)) if o == oid => c,
            _ => crc32fast::hash(&pack_bytes[*offset as usize..entry_end(pack_bytes, *offset)]),
        };
        out.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, offset) in &entries {
        out.extend_from_slice(&(*offset as u32).to_be_bytes());
    }
    let pack_sum = &pack_bytes[pack_bytes.len() - 20..];
    out.extend_from_slice(pack_sum);
    let idx_sum = crate::gitobj::sha1_hex(&out);
    out.extend_from_slice(&hex::decode(idx_sum).unwrap());
    out
}

fn entry_end(pack: &[u8], offset: u64) -> usize {
    // Re-parse a single entry to find its end (used only by the idx builder).
    let parsed = crate::pack::parse_pack(pack, None, 1 << 30).expect("pack parses");
    parsed
        .entries
        .iter()
        .find(|e| e.offset == offset)
        .map(|e| e.end_offset as usize)
        .unwrap_or(pack.len() - 20)
}

/// Build a loose object file body.
pub fn build_loose(typ: ObjType, content: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(typ.name().as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    zdeflate(&raw)
}

/// Convenience: git oid of a blob with this content.
pub fn blob_oid(content: &[u8]) -> String {
    object_id(ObjType::Blob, content)
}
