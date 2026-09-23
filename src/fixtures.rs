//! Self-contained builders for git pack/idx/loose byte streams.
//! Used by tests; no system git involved.

use crate::crc32::crc32;
use crate::delta::encode_delta;
use crate::oid::{object_id, Oid};
use sha1::{Digest, Sha1};

#[derive(Clone)]
pub struct Entry {
    pub kind: u8, // 1 commit,2 tree,3 blob,4 tag,6 ofs,7 ref
    pub size: u64,
    pub data: Vec<u8>,
    /// For ofs-delta: index of base entry within the same pack.
    pub ofs_base: Option<usize>,
    /// For ref-delta: explicit base oid.
    pub ref_base: Option<Oid>,
}

pub fn blob_entry(content: &[u8]) -> Entry {
    Entry { kind: 3, size: content.len() as u64, data: content.to_vec(), ofs_base: None, ref_base: None }
}

pub fn ofs_delta_entry(base: &[u8], target: &[u8], base_index: usize) -> Entry {
    let d = encode_delta(base, target);
    Entry { kind: 6, size: d.len() as u64, data: d, ofs_base: Some(base_index), ref_base: None }
}

pub fn ref_delta_entry(base: &[u8], target: &[u8], base_oid: Oid) -> Entry {
    let d = encode_delta(base, target);
    Entry { kind: 7, size: d.len() as u64, data: d, ofs_base: None, ref_base: Some(base_oid) }
}

fn write_size_header(out: &mut Vec<u8>, kind: u8, mut size: u64) {
    let mut b = (size as u8 & 0x0f) | (kind << 4);
    size >>= 4;
    if size > 0 {
        b |= 0x80;
    }
    out.push(b);
    while size > 0 {
        let mut nb = size as u8 & 0x7f;
        size >>= 7;
        if size > 0 {
            nb |= 0x80;
        }
        out.push(nb);
    }
}

fn write_ofs_distance(out: &mut Vec<u8>, dist: u64) {
    let mut bytes = Vec::new();
    let mut d = dist;
    bytes.push((d & 0x7f) as u8);
    d >>= 7;
    while d > 0 {
        d -= 1;
        bytes.push(0x80 | ((d & 0x7f) as u8));
        d >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

/// Build a pack. `entry_offsets` receives the byte offset of each entry.
pub fn build_pack(entries: &[Entry]) -> (Vec<u8>, Vec<u64>) {
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut offsets = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        offsets.push(out.len() as u64);
        write_size_header(&mut out, e.kind, e.size);
        if e.kind == 6 {
            let base_off = offsets[e.ofs_base.unwrap()];
            let dist = out.len() as u64 - base_off;
            write_ofs_distance(&mut out, dist);
        } else if e.kind == 7 {
            out.extend_from_slice(e.ref_base.unwrap().as_bytes());
        }
        let mut comp = flate2::Compression::default();
        let _ = &mut comp;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write;
        enc.write_all(&e.data).unwrap();
        let z = enc.finish().unwrap();
        out.extend_from_slice(&z);
        let _ = i;
    }

    let mut h = Sha1::new();
    h.update(&out);
    let sum: [u8; 20] = h.finalize().into();
    out.extend_from_slice(&sum);
    (out, offsets)
}

/// Pack trailer checksum (also used as idx pack checksum).
pub fn pack_checksum(pack: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(&pack[..pack.len() - 20]);
    Oid(h.finalize().into())
}

/// Build an idx v2 for a pack given (oid, offset) per entry.
pub fn build_idx(
    pack: &[u8],
    mut mapping: Vec<(Oid, u64)>,
    corrupt_crc_for: Option<&Oid>,
) -> Vec<u8> {
    mapping.sort_by(|a, b| a.0.cmp(&b.0));
    let n = mapping.len();
    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    for (oid, _) in &mapping {
        fanout[oid.as_bytes()[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for i in 0..256 {
        acc += fanout[i];
        fanout[i] = acc;
    }
    for v in fanout {
        out.extend_from_slice(&v.to_be_bytes());
    }
    for (oid, _) in &mapping {
        out.extend_from_slice(oid.as_bytes());
    }
    // CRC over on-disk pack entry bytes: re-inflate boundaries via stored
    // offsets by scanning the pack (entries are known contiguous).
    let body_end = pack.len() - 20;
    let mut sorted_offsets: Vec<u64> = mapping.iter().map(|(_, o)| *o).collect();
    sorted_offsets.sort();
    let mut end_by_off = std::collections::HashMap::new();
    for (i, off) in sorted_offsets.iter().enumerate() {
        let end = if i + 1 < sorted_offsets.len() {
            sorted_offsets[i + 1]
        } else {
            body_end as u64
        };
        end_by_off.insert(*off, end);
    }
    for (oid, off) in &mapping {
        let end = end_by_off[off] as usize;
        let crc = crc32(&pack[*off as usize..end]);
        let crc = if corrupt_crc_for == Some(oid) { crc ^ 0xdead_beef } else { crc };
        out.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, off) in &mapping {
        assert!(*off < 0x8000_0000, "test packs must be small");
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }
    // no large offsets table
    out.extend_from_slice(pack_checksum(pack).as_bytes());
    let mut h = Sha1::new();
    h.update(&out);
    let idx_sum: [u8; 20] = h.finalize().into();
    out.extend_from_slice(&idx_sum);
    out
}

/// Build an idx whose pack checksum points somewhere else (mismatch).
pub fn build_mismatched_idx(pack: &[u8], mapping: Vec<(Oid, u64)>) -> Vec<u8> {
    let mut idx = build_idx(pack, mapping, None);
    // Replace pack checksum (20 bytes immediately before idx checksum).
    let at = idx.len() - 40;
    idx[at..at + 20].copy_from_slice(&[0xa5u8; 20]);
    // Recompute idx checksum so only the pack pairing is wrong.
    let mut h = Sha1::new();
    h.update(&idx[..idx.len() - 20]);
    let sum: [u8; 20] = h.finalize().into();
    idx[idx.len() - 20..].copy_from_slice(&sum);
    idx
}

pub fn build_loose(kind: &str, content: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(kind.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap()
}

/// Loose object that lies about its size header.
pub fn build_loose_fake_size(kind: &str, content: &[u8], declared: usize) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(kind.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(declared.to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap()
}

/// Loose object whose zlib stream is truncated mid-way.
pub fn build_loose_truncated(kind: &str, content: &[u8], drop_bytes: usize) -> Vec<u8> {
    let mut z = build_loose(kind, content);
    z.truncate(z.len().saturating_sub(drop_bytes));
    z
}

pub fn blob_oid(content: &[u8]) -> Oid {
    object_id("blob", content)
}

/// Tamper the last byte of the entry's on-disk range [off, end).
pub fn corrupt_entry_at(pack: &mut [u8], off: u64, end: u64) {
    let at = end as usize - 2;
    if at > off as usize && at < pack.len() - 20 {
        pack[at] ^= 0xff;
    }
}
