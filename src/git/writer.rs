use sha1::Digest;
use crate::git::{encode_size, object_id, zlib_compress, ObjectId, ObjectType};

#[derive(Clone)]
pub enum DeltaBase { Ref(ObjectId), Ofs(usize) }

#[derive(Clone)]
pub struct BuildObject {
    pub kind: ObjectType,
    pub data: Vec<u8>,
    pub delta_base: Option<DeltaBase>,
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    pub offsets: Vec<u64>,
    pub oids: Vec<ObjectId>,
    pub crcs: Vec<u32>,
}

fn entry_header(kind: ObjectType, size: u64) -> Vec<u8> {
    let mut bytes = encode_size(size, 4);
    bytes[0] |= kind.code() << 4;
    bytes
}

pub fn build_pack(objects: &[BuildObject]) -> BuiltPack {
    let count = objects.len() as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PACK");
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut offsets = Vec::new();
    let mut crcs = Vec::new();

    for (index, object) in objects.iter().enumerate() {
        let offset = bytes.len();
        offsets.push(offset as u64);
        if let Some(base) = &object.delta_base {
            match base {
                DeltaBase::Ref(oid) => {
                    bytes.extend(entry_header(ObjectType::RefDelta, object.data.len() as u64));
                    bytes.extend_from_slice(oid.as_bytes());
                }
                DeltaBase::Ofs(base_index) => {
                    bytes.extend(entry_header(ObjectType::OfsDelta, object.data.len() as u64));
                    let distance = (offset - offsets[*base_index] as usize) as u64;
                    write_ofs_distance(&mut bytes, distance);
                }
            }
        } else {
            bytes.extend(entry_header(object.kind, object.data.len() as u64));
        }
        bytes.extend(zlib_compress(&object.data));
        crcs.push(crc32fast::hash(&bytes[offset..]));
    }

    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, &bytes);
    let checksum: [u8; 20] = sha1::Digest::finalize(hasher).into();
    bytes.extend_from_slice(&checksum);
    let oids = objects.iter().map(|o| object_id(o.kind, &o.data)).collect();
    BuiltPack { bytes, offsets, oids, crcs }
}

pub fn write_ofs_distance(out: &mut Vec<u8>, distance: u64) {
    let mut value = distance;
    let mut bytes = Vec::new();
    let mut byte = (value & 0x7f) as u8;
    value >>= 7;
    while value != 0 {
        bytes.push(byte | 0x80);
        byte = (value & 0x7f) as u8;
        value >>= 7;
    }
    bytes.push(byte);
    bytes.reverse();
    let len=bytes.len();
    for (i, b) in bytes.iter_mut().enumerate() {
        if i + 1 < len { *b |= 0x80; }
    }
    out.extend_from_slice(&bytes);
}

pub fn build_idx(pack: &BuiltPack) -> Vec<u8> {
    let mut rows: Vec<(ObjectId, u64, u32)> = pack.oids.iter().enumerate()
        .map(|(i, oid)| (*oid, pack.offsets[i], pack.crcs[i]))
        .collect();
    rows.sort_by_key(|(oid, _, _)| *oid);
    let n = rows.len();
    let mut data = Vec::new();
    data.extend_from_slice(b"\xfftOc");
    data.extend_from_slice(&2u32.to_be_bytes());
    let mut next = 0u32;
    let mut fanout = [0u32; 256];
    for bucket in 0..256usize {
        while next < rows.len() as u32 && rows[next as usize].0.as_bytes()[0] as usize == bucket {
            next += 1;
        }
        fanout[bucket] = next;
    }
    for value in fanout { data.extend_from_slice(&value.to_be_bytes()); }
    for (oid, _, _) in &rows { data.extend_from_slice(oid.as_bytes()); }
    for (_, _, crc) in &rows { data.extend_from_slice(&crc.to_be_bytes()); }
    for (_, offset, _) in &rows { data.extend_from_slice(&(*offset as u32).to_be_bytes()); }
    data.extend_from_slice(&pack.bytes[pack.bytes.len()-20..]);
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, &data);
    let idx_checksum: [u8; 20] = sha1::Digest::finalize(hasher).into();
    data.extend_from_slice(&idx_checksum);
    data
}

pub fn make_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    let mut delta = Vec::new();
    append_delta_size(&mut delta, base.len() as u64);
    append_delta_size(&mut delta, result.len() as u64);
    let common = base.iter().zip(result.iter()).take_while(|(a,b)| a == b).count();
    if common > 0 {
        delta.push(0x80 | 0x10 | 0x01);
        delta.push(0);
        delta.push((common >> 16) as u8);
        delta.push((common >> 8) as u8);
        delta.push(common as u8);
    }
    for chunk in result[common..].chunks(127) {
        delta.push(chunk.len() as u8);
        delta.extend_from_slice(chunk);
    }
    delta
}

pub fn append_delta_size(out: &mut Vec<u8>, mut value: u64) -> &mut Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { byte |= 0x80; }
        bytes.push(byte);
        if value == 0 { break; }
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delta_roundtrip() {
        let base = b"hello world";
        let result = b"hello Rust";
        let delta = make_delta(base, result);
        let (output, ranges) = crate::git::delta::parse_delta(&delta, base, 1000, None).unwrap();
        assert_eq!(output, result);
        assert!(!ranges.is_empty());
    }
}
