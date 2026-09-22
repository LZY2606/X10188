use crate::git::{crc32_ieee, git_object_id, GitType};
use flate2::{write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};
use std::io::Write;
use std::collections::HashMap;

#[derive(Clone)]
pub enum BuilderEntry {
    Object { kind: GitType, data: Vec<u8> },
    OfsDelta { distance: u64, delta: Vec<u8> },
    RefDelta { base: [u8; 20], delta: Vec<u8> },
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn loose_object(kind: GitType, data: &[u8]) -> ([u8; 20], Vec<u8>) {
    let oid = git_object_id(kind, data);
    let mut raw = format!("{} {}\0", kind.name(), data.len()).into_bytes();
    raw.extend_from_slice(data);
    (oid, zlib(&raw))
}

pub fn entry_size_header(type_code: u8, size: usize) -> Vec<u8> {
    let mut first = (type_code << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest > 0 {
        first |= 0x80;
    }
    let mut out = vec![first];
    while rest > 0 {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

pub fn ofs_header(mut distance: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut value = distance & 0x7f;
    distance >>= 7;
    while distance > 0 {
        value |= 0x80;
        bytes.push(value as u8);
        value = distance & 0x7f;
        distance >>= 7;
    }
    bytes.reverse();
    bytes.push(value as u8);
    bytes
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    pub idx: Vec<u8>,
    pub entry_offsets: Vec<u64>,
    pub entry_ends: Vec<u64>,
    pub entry_oids: Vec<[u8; 20]>,
    pub crcs: Vec<u32>,
}

pub fn write_pack(entries: &[BuilderEntry]) -> BuiltPack {
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    let mut ends = Vec::new();
    let mut crcs = Vec::new();
    let mut resolved: Vec<(GitType, Vec<u8>)> = Vec::new();
    let mut resolved_offset: HashMap<u64, usize> = HashMap::new();
    let mut oids = Vec::new();
    for entry in entries {
        let offset = out.len() as u64;
        offsets.push(offset);
        match entry {
            BuilderEntry::Object { kind, data } => {
                out.extend_from_slice(&entry_size_header(kind.code(), data.len()));
                out.extend_from_slice(&zlib(data));
                oids.push(git_object_id(*kind, data));
                resolved.push((*kind, data.clone()));
                resolved_offset.insert(offset, resolved.len() - 1);
            }
            BuilderEntry::OfsDelta { distance, delta } => {
                out.extend_from_slice(&entry_size_header(6, delta.len()));
                out.extend_from_slice(&ofs_header(*distance));
                out.extend_from_slice(&zlib(delta));
                let base_index = resolved_offset[&(offset - *distance)];
                let base = &resolved[base_index];
                let applied = crate::git::apply_delta(&base.1, delta).unwrap();
                oids.push(git_object_id(base.0, &applied.data));
                resolved.push((base.0, applied.data));
                resolved_offset.insert(offset, resolved.len() - 1);
            }
            BuilderEntry::RefDelta { base, delta } => {
                out.extend_from_slice(&entry_size_header(7, delta.len()));
                out.extend_from_slice(base);
                out.extend_from_slice(&zlib(delta));
                let base_entry = resolved.iter().find(|(_, data)| {
                    use crate::git::GitType::*;
                    [Commit, Tree, Blob, Tag].iter().any(|kind| git_object_id(*kind, data) == *base)
                });
                let kind = base_entry.map(|(kind, _)| *kind).unwrap_or(GitType::Blob);
                let base_data = base_entry.map(|(_, data)| data.clone()).unwrap_or_default();
                let applied = crate::git::apply_delta(&base_data, delta).unwrap_or(crate::git::AppliedDelta {
                    base_size: 0,
                    result_size: 0,
                    instructions: Vec::new(),
                    data: Vec::new(),
                });
                oids.push(git_object_id(kind, &applied.data));
                resolved.push((kind, applied.data));
                resolved_offset.insert(offset, resolved.len() - 1);
            }
        }
        ends.push(out.len() as u64);
        crcs.push(crc32_ieee(&out[offset as usize..]));
    }
    let mut hasher = Sha1::new();
    hasher.update(&out);
    let pack_checksum: [u8; 20] = hasher.finalize().into();
    out.extend_from_slice(&pack_checksum);
    let idx = write_idx(&oids, &offsets, &crcs, &pack_checksum);
    BuiltPack { bytes: out, idx, entry_offsets: offsets, entry_ends: ends, entry_oids: oids, crcs }
}

pub fn write_idx(
    oids: &[[u8; 20]],
    offsets: &[u64],
    crcs: &[u32],
    pack_checksum: &[u8; 20],
) -> Vec<u8> {
    let mut indexed: Vec<([u8; 20], u64, u32)> = oids
        .iter()
        .zip(offsets.iter().zip(crcs.iter()))
        .map(|(oid, (offset, crc))| (*oid, *offset, *crc))
        .collect();
    indexed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    out.extend_from_slice(&[0xff, b't', b'O', b'c']);
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut cumulative = 0u32;
    for bucket in 0..256u32 {
        cumulative += indexed.iter().filter(|(oid, _, _)| oid[0] as u32 == bucket).count() as u32;
        out.extend_from_slice(&cumulative.to_be_bytes());
    }
    for (oid, _, _) in &indexed {
        out.extend_from_slice(oid);
    }
    for (_, _, crc) in &indexed {
        out.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, offset, _) in &indexed {
        out.extend_from_slice(&(*offset as u32).to_be_bytes());
    }
    out.extend_from_slice(pack_checksum);
    let mut hasher = Sha1::new();
    hasher.update(&out);
    let idx_checksum: [u8; 20] = hasher.finalize().into();
    out.extend_from_slice(&idx_checksum);
    out
}

pub fn repair_idx_checksum(mut idx: Vec<u8>) -> Vec<u8> {
    use sha1::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(&idx[..idx.len() - 20]);
    let checksum: [u8; 20] = hasher.finalize().into();
    let len = idx.len();
    idx[len - 20..].copy_from_slice(&checksum);
    idx
}

pub fn write_cyclic_pack() -> Vec<u8> {
    let delta = delta_replace(&[], &[]);
    let first_header = entry_size_header(6, delta.len());
    let second_header = entry_size_header(6, delta.len());
    let first_offset = 12u64;
    let second_delta_distance = (first_header.len() + zlib(&delta).len()) as u64;
    let second_offset = first_offset + first_header.len() as u64 + zlib(&delta).len() as u64;
    let forward_distance = (second_offset - first_offset) as u64;
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&first_header);
    out.extend_from_slice(&ofs_header(forward_distance));
    out.extend_from_slice(&zlib(&delta));
    out.extend_from_slice(&second_header);
    out.extend_from_slice(&ofs_header(second_delta_distance));
    out.extend_from_slice(&zlib(&delta));
    let checksum: [u8; 20] = {
        use sha1::Sha1;
        let mut hasher = Sha1::new();
        hasher.update(&out);
        hasher.finalize().into()
    };
    out.extend_from_slice(&checksum);
    out
}

pub fn delta_replace(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    fn size(out: &mut Vec<u8>, mut value: usize) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }
    size(&mut out, old.len());
    size(&mut out, new.len());
    let _ = old;
    out.push(new.len() as u8);
    out.extend_from_slice(new);
    out
}
