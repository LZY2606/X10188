#![allow(dead_code)]
//! Pure-Rust fixture builders: no system git is used anywhere.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use pack_microscope::delta::{make_copy_append_delta, make_insert_delta};
use pack_microscope::gitobj::{framed, hex, object_id, ptype};
use pack_microscope::leb128::{write_ofs_distance, write_pack_header};
use sha1::{Digest, Sha1};
use std::io::Write;

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn loose_object(type_code: u8, content: &[u8]) -> (Vec<u8>, String) {
    let frame = framed(type_code, content);
    let oid = hex(&object_id(type_code, content));
    (deflate(&frame), oid)
}

#[derive(Clone)]
pub enum EntrySpec {
    Full {
        obj_type: u8,
        content: Vec<u8>,
    },
    OfsDelta {
        base_index: usize,
        delta: Vec<u8>,
        declared: usize,
    },
    OfsDeltaRaw {
        distance: u64,
        delta: Vec<u8>,
        declared: usize,
    },
    RefDelta {
        base_oid: [u8; 20],
        delta: Vec<u8],
        declared: usize,
    },
}

pub fn build_pack(entries: &[EntrySpec]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut offsets: Vec<usize> = Vec::new();
    for spec in entries {
        let entry_offset = body.len();
        offsets.push(entry_offset);
        match spec {
            EntrySpec::Full { obj_type, content } => {
                body.extend_from_slice(&write_pack_header(*obj_type, content.len() as u64));
                body.extend_from_slice(&deflate(content));
            }
            EntrySpec::OfsDelta {
                base_index,
                delta,
                declared,
            } => {
                body.extend_from_slice(&write_pack_header(ptype::OFS_DELTA, *declared as u64));
                let header_pos = body.len();
                let dist = (header_pos as u64) + 1 - offsets[*base_index] as u64;
                body.extend_from_slice(&write_ofs_distance(dist));
                body.extend_from_slice(&deflate(delta));
            }
            EntrySpec::OfsDeltaRaw {
                distance,
                delta,
                declared,
            } => {
                body.extend_from_slice(&write_pack_header(ptype::OFS_DELTA, *declared as u64));
                body.extend_from_slice(&write_ofs_distance(*distance));
                body.extend_from_slice(&deflate(delta));
            }
            EntrySpec::RefDelta {
                base_oid,
                delta,
                declared,
            } => {
                body.extend_from_slice(&write_pack_header(ptype::REF_DELTA, *declared as u64));
                body.extend_from_slice(base_oid);
                body.extend_from_slice(&deflate(delta));
            }
        }
    }
    let mut hasher = Sha1::new();
    hasher.update(&body);
    body.extend_from_slice(&hasher.finalize());
    body
}

pub fn build_idx_v2(
    rows: &[(usize, [u8; 20], u32)],
    pack_checksum: [u8; 20],
    corrupt_idx_checksum: bool,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]);
    data.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (_, oid, _) in rows {
        for i in (oid[0] as usize)..256 {
            fanout[i] += 1;
        }
    }
    for f in fanout {
        data.extend_from_slice(&f.to_be_bytes());
    }
    let mut sorted: Vec<&(usize, [u8; 20], u32)> = rows.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    for (_, oid, _) in &sorted {
        data.extend_from_slice(oid);
    }
    for (_, _, crc) in &sorted {
        data.extend_from_slice(&crc.to_be_bytes());
    }
    for (off, _, _) in &sorted {
        data.extend_from_slice(&(*off as u32).to_be_bytes());
    }
    data.extend_from_slice(&pack_checksum);
    let mut h = Sha1::new();
    h.update(&data);
    let mut sum = h.finalize().to_vec();
    if corrupt_idx_checksum {
        sum[0] ^= 0xff;
    }
    data.extend_from_slice(&sum);
    data
}

pub fn pack_checksum(pack: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(&pack[..pack.len() - 20]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h.finalize());
    a
}

pub fn range_crc(pack: &[u8], start: usize, end: usize) -> u32 {
    crc32fast::hash(&pack[start..end])
}

pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "packmicro_{}_{}_{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn blob_oid(content: &[u8]) -> [u8; 20] {
    object_id(ptype::BLOB, content)
}

pub fn insert_delta_for(base_content: &[u8], result: &[u8]) -> Vec<u8> {
    make_insert_delta(base_content.len() as u64, result)
}

pub fn append_delta_for(base_content: &[u8], extra: &[u8]) -> Vec<u8> {
    make_copy_append_delta(base_content.len() as u64, extra)
}
