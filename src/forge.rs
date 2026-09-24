use crate::git::{git_object_id, GitType};
use crc32fast::Hasher as CrcHasher;
use flate2::{write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};
use std::io::Write;

#[derive(Debug, Clone)]
pub enum ForgeEntry {
    Object { object_type: GitType, data: Vec<u8> },
    OfsDelta { base: usize, delta: Vec<u8> },
    RefDelta { base_oid: [u8; 20], delta: Vec<u8> },
}

pub struct BuiltPack {
    pub pack: Vec<u8>,
    pub idx: Vec<u8>,
    pub oids: Vec<[u8; 20]>,
    pub offsets: Vec<usize>,
}

fn zlib_encode(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn write_size(value: usize) -> Vec<u8> {
    let mut value = value;
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value != 0 {
        bytes.last_mut().map(|byte| *byte |= 0x80);
        bytes.push((value & 0x7f) as u8);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

pub fn write_pack_object_header(object_type: GitType, size: usize, delta_ref: Option<crate::git::DeltaRef>, current_offset: usize) -> Vec<u8> {
    let type_code = object_type.pack_code();
    let mut size_bytes = write_size(size);
    size_bytes[0] |= (type_code << 4) as u8;
    if size_bytes.len() > 1 || size >= 16 {
        size_bytes[0] |= 0x80;
    }
    if let Some(crate::git::DeltaRef::Offset(base_offset)) = delta_ref {
        let distance = current_offset - base_offset as usize;
        let mut bytes = vec![(distance & 0x7f) as u8];
        let mut rest = distance >> 7;
        while rest != 0 {
            bytes.last_mut().map(|byte| *byte |= 0x80);
            bytes.push((rest & 0x7f) as u8);
            rest >>= 7;
        }
        bytes.reverse();
        size_bytes.extend(bytes);
    } else if let Some(crate::git::DeltaRef::Oid(oid)) = delta_ref {
        size_bytes.extend(oid);
    }
    size_bytes
}

pub fn delta_for(base: &[u8], target: &[u8]) -> Vec<u8> {
    let common = base.len().min(target.len());
    let mut delta = write_size(base.len());
    delta.extend(write_size(target.len()));
    if common > 0 {
        let mut size_mask = 0u8;
        let mut size_bytes = Vec::new();
        let mut size_value = common;
        for bit in 0..3 {
            if size_value & 0xff != 0 || bit == 0 {
                size_mask |= 1 << (bit + 4);
                size_bytes.push((size_value & 0xff) as u8);
            }
            size_value >>= 8;
        }
        delta.push(0x80 | size_mask);
        delta.extend(size_bytes);
    }
    let inserted = &target[common..];
    let mut cursor = 0usize;
    while cursor < inserted.len() {
        let length = inserted.len() - cursor;
        let chunk = length.min(127);
        delta.push(chunk as u8);
        delta.extend_from_slice(&inserted[cursor..cursor + chunk]);
        cursor += chunk;
    }
    delta
}

pub fn build_pack(entries: Vec<ForgeEntry>) -> BuiltPack {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    let mut resolved = Vec::new();
    let mut offsets = Vec::new();
    let mut encoded_entries = Vec::new();
    for entry in entries {
        let offset = pack.len();
        offsets.push(offset);
        match entry {
            ForgeEntry::Object { object_type, data } => {
                let encoded = zlib_encode(&data);
                let header = write_pack_object_header(object_type, data.len(), None, offset);
                pack.extend_from_slice(&header);
                pack.extend_from_slice(&encoded);
                encoded_entries.push(encoded);
                resolved.push((object_type, data));
            }
            ForgeEntry::OfsDelta { base, delta } => {
                let encoded = zlib_encode(&delta);
                let header = write_pack_object_header(GitType::OfsDelta, delta.len(), Some(crate::git::DeltaRef::Offset(offsets[base] as u64)), offset);
                pack.extend_from_slice(&header);
                pack.extend_from_slice(&encoded);
                encoded_entries.push(encoded);
                let (object_type, _) = resolved[base];
                let (target, _) = crate::git::apply_delta(&resolved[base].1, &delta).unwrap();
                resolved.push((object_type, target));
            }
            ForgeEntry::RefDelta { base_oid, delta } => {
                let encoded = zlib_encode(&delta);
                let header = write_pack_object_header(GitType::RefDelta, delta.len(), Some(crate::git::DeltaRef::Oid(base_oid)), offset);
                pack.extend_from_slice(&header);
                pack.extend_from_slice(&encoded);
                encoded_entries.push(encoded);
                let object_type = resolved.iter().find_map(|(kind, data)| {
                    git_object_id(*kind, data).ok().filter(|oid| *oid == base_oid).map(|_| *kind)
                }).unwrap_or(GitType::Blob);
                let base_data = resolved.iter().find_map(|(_, data)| {
                    git_object_id(object_type, data).ok().filter(|oid| *oid == base_oid).map(|_| data.clone())
                }).unwrap_or_default();
                let (target, _) = crate::git::apply_delta(&base_data, &delta).unwrap();
                resolved.push((object_type, target));
            }
        }
    }
    let mut oids = Vec::new();
    for (kind, data) in &resolved {
        oids.push(git_object_id(*kind, *data).unwrap());
    }
    let checksum = {
        let mut hasher = Sha1::new();
        hasher.update(&pack);
        let digest: [u8; 20] = hasher.finalize().into();
        digest
    };
    pack.extend_from_slice(&checksum);

    let mut ordered: Vec<usize> = (0..oids.len()).collect();
    ordered.sort_by_key(|index| oids[*index]);
    let mut idx = Vec::new();
    idx.extend_from_slice(b"\xfftOc");
    idx.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for index in &ordered {
        fanout[oids[*index][0] as usize] += 1;
    }
    let mut cumulative = 0u32;
    for value in fanout.iter_mut() {
        cumulative += *value;
        *value = cumulative;
    }
    for value in fanout {
        idx.extend_from_slice(&value.to_be_bytes());
    }
    for index in &ordered {
        idx.extend_from_slice(&oids[*index]);
    }
    for index in &ordered {
        let start = offsets[*index];
        let end = if *index + 1 < offsets.len() { offsets[*index + 1] } else { pack.len() - 20 };
        let mut hasher = CrcHasher::new();
        hasher.update(&pack[start..end]);
        idx.extend_from_slice(&hasher.finalize().to_be_bytes());
    }
    for index in &ordered {
        idx.extend_from_slice(&(offsets[*index] as u32).to_be_bytes());
    }
    idx.extend_from_slice(&checksum);
    let index_checksum = {
        let mut hasher = Sha1::new();
        hasher.update(&idx);
        let digest: [u8; 20] = hasher.finalize().into();
        digest
    };
    idx.extend_from_slice(&index_checksum);
    BuiltPack { pack, idx, oids, offsets }
}

pub fn loose_object(object_type: GitType, data: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let oid = git_object_id(object_type, data).unwrap();
    let mut raw = format!("{} {}\0", object_type.name(), data.len()).into_bytes();
    raw.extend_from_slice(&zlib_encode(data));
    (raw, oid)
}
