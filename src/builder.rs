use crate::git::{apply_delta, encode_delta_size, encode_pack_header, git_object_id, GitType};
use crc32fast::Hasher;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::io::Write;

#[derive(Debug, Clone)]
pub enum PackInput {
    Raw(GitType, Vec<u8>),
    OfsDelta { base: usize, delta: Vec<u8> },
    RefDelta { base_oid: String, delta: Vec<u8>, final_oid: Option<String> },
}

#[derive(Debug, Clone)]
pub struct BuiltPack {
    pub pack: Vec<u8>,
    pub idx: Vec<u8>,
    pub oids: Vec<String>,
}

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
}

fn encode_ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        bytes.push(((distance & 0x7f) as u8) | 0x80);
        distance >>= 7;
    }
    bytes.reverse();
    if bytes.len() > 1 {
        for byte in bytes.iter_mut().skip(1) {
            *byte |= 0x80;
        }
        bytes[0] &= 0x7f;
    }
    bytes
}

pub fn build_pack(inputs: &[PackInput]) -> BuiltPack {
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    let mut offsets = Vec::new();
    let mut kinds: Vec<Option<GitType>> = vec![None; inputs.len()];
    let mut payloads: Vec<Vec<u8>> = vec![Vec::new(); inputs.len()];
    let mut oids: Vec<String> = vec![String::new(); inputs.len()];

    for (index, input) in inputs.iter().enumerate() {
        let offset = 12 + encoded.iter().map(|item| item.len() as u64).sum::<u64>();
        offsets.push(offset);
        let mut entry = Vec::new();
        match input {
            PackInput::Raw(kind, payload) => {
                entry.extend(encode_pack_header(kind_code(*kind), payload.len() as u64));
                entry.extend(zlib_compress(payload));
                kinds[index] = Some(*kind);
                payloads[index] = payload.clone();
                oids[index] = hex::encode(git_object_id(*kind, payload));
            }
            PackInput::OfsDelta { base, delta } => {
                entry.extend(encode_pack_header(6, delta.len() as u64));
                entry.extend(encode_ofs_distance(offset - offsets[*base]));
                entry.extend(zlib_compress(delta));
                let base_kind = kinds[*base].expect("ofs base must already be built");
                let (out, _) = apply_delta(&payloads[*base], delta).expect("valid test delta");
                let oid = hex::encode(git_object_id(base_kind, &out));
                kinds[index] = Some(base_kind);
                payloads[index] = out;
                oids[index] = oid;
            }
            PackInput::RefDelta {
                base_oid,
                delta,
                final_oid,
            } => {
                entry.extend(encode_pack_header(7, delta.len() as u64));
                entry.extend(hex::decode(base_oid).expect("valid test base oid"));
                entry.extend(zlib_compress(delta));
                if let Some(base_index) = oids.iter().position(|oid| oid == base_oid) {
                    let base_kind = kinds[base_index].expect("ref base in pack has type");
                    let (out, _) = apply_delta(&payloads[base_index], delta).expect("valid delta");
                    kinds[index] = Some(base_kind);
                    payloads[index] = out;
                    oids[index] = hex::encode(git_object_id(base_kind, &out));
                } else {
                    oids[index] = final_oid
                        .clone()
                        .expect("external ref delta test must provide final oid");
                }
            }
        }
        encoded.push(entry);
    }

    let mut pack = Vec::new();
    pack.extend(b"PACK");
    pack.extend(2u32.to_be_bytes());
    pack.extend((inputs.len() as u32).to_be_bytes());
    for entry in &encoded {
        pack.extend(entry);
    }
    let mut hasher = Sha1::new();
    hasher.update(&pack);
    let checksum: [u8; 20] = hasher.finalize().into();
    pack.extend(checksum);

    let mut order: Vec<usize> = (0..inputs.len()).collect();
    order.sort_by(|left, right| oids[*left].cmp(&oids[*right]));
    let mut idx = Vec::new();
    idx.extend(b"\xfftOc");
    idx.extend(2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for &item in &order {
        let first = u8::from_str_radix(&oids[item][..2], 16).unwrap();
        fanout[first as usize] += 1;
    }
    let mut running = 0u32;
    for bucket in fanout.iter_mut() {
        running += *bucket;
        *bucket = running;
    }
    for value in fanout {
        idx.extend(value.to_be_bytes());
    }
    for &item in &order {
        idx.extend(hex::decode(&oids[item]).unwrap());
    }
    let mut crcs = Vec::new();
    for &item in &order {
        let mut hasher = Hasher::new();
        hasher.update(&encoded[item]);
        crcs.push(hasher.finalize());
    }
    for crc in &crcs {
        idx.extend(crc.to_be_bytes());
    }
    for &item in &order {
        idx.extend((offsets[item] as u32).to_be_bytes());
    }
    idx.extend(checksum);
    let mut idx_hasher = Sha1::new();
    idx_hasher.update(&idx);
    let idx_checksum: [u8; 20] = idx_hasher.finalize().into();
    idx.extend(idx_checksum);

    BuiltPack { pack, idx, oids }
}

pub fn delta_insert_then_copy(base_len: usize, inserted: &[u8]) -> Vec<u8> {
    let mut delta = encode_delta_size(base_len as u64);
    delta.extend(encode_delta_size((base_len + inserted.len()) as u64));
    delta.push(inserted.len() as u8);
    delta.extend(inserted);
    delta.push(0x80);
    delta.extend(0u32.to_le_bytes()[..1].to_vec());
    delta.extend((base_len as u32).to_le_bytes()[..3].to_vec());
    delta
}

pub fn loose_object(kind: GitType, payload: &[u8]) -> (String, Vec<u8>) {
    let oid = hex::encode(git_object_id(kind, payload));
    let mut raw = format!("{} {}\0", kind.name(), payload.len()).into_bytes();
    raw.extend(zlib_compress(payload));
    (oid, raw)
}

fn kind_code(kind: GitType) -> u8 {
    match kind {
        GitType::Commit => 1,
        GitType::Tree => 2,
        GitType::Blob => 3,
        GitType::Tag => 4,
    }
}
