//! Hand-built Git pack / idx / loose object fixtures. No system git involved.

use flate2::{write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};

use pack_chain_microscope::git::{
    encode_ofs_distance, encode_pack_header, envelope, git_oid, GitType,
};

pub fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

pub fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

pub fn loose_bytes(kind: GitType, content: &[u8]) -> Vec<u8> {
    zlib(&envelope(kind, content))
}

pub enum PackItem {
    Base(GitType, Vec<u8>),
    OfsDelta { base_index: usize, delta: Vec<u8> },
    RefDelta { base_oid: [u8; 20], delta: Vec<u8> },
}

pub fn build_pack(items: &[PackItem]) -> (Vec<u8>, Vec<u64>) {
    let mut body: Vec<u8> = Vec::new();
    let mut offsets = Vec::new();

    for (i, item) in items.iter().enumerate() {
        offsets.push(body.len() as u64 + 12);
        match item {
            PackItem::Base(_kind, content) => {
                body.extend(encode_pack_header(item.kind_at(), content.len() as u64));
                body.extend(zlib(content));
            }
            PackItem::OfsDelta { base_index, delta } => {
                let distance = offsets[i] - offsets[*base_index];
                body.extend(encode_pack_header(GitType::OfsDelta, delta.len() as u64));
                body.extend(encode_ofs_distance(distance));
                body.extend(zlib(delta));
            }
            PackItem::RefDelta { base_oid, delta } => {
                body.extend(encode_pack_header(GitType::RefDelta, delta.len() as u64));
                body.extend(base_oid);
                body.extend(zlib(delta));
            }
        }
    }

    let mut pack = Vec::new();
    pack.extend(b"PACK");
    pack.extend(2u32.to_be_bytes());
    pack.extend((items.len() as u32).to_be_bytes());
    pack.extend(body);
    let checksum = sha1(&pack);
    pack.extend(&checksum);
    (pack, offsets)
}

impl PackItem {
    fn kind_at(&self) -> GitType {
        match self {
            PackItem::Base(k, _) => *k,
            PackItem::OfsDelta { .. } => GitType::OfsDelta,
            PackItem::RefDelta { .. } => GitType::RefDelta,
        }
    }
}

pub fn oid_bytes(oid: &str) -> [u8; 20] {
    let v = hex::decode(oid).unwrap();
    v.try_into().unwrap()
}

pub fn build_idx(pack: &[u8], rows: &[(String, u64)]) -> Vec<u8> {
    let mut sorted: Vec<(String, u64)> = rows.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut fanout = [0u32; 256];
    for (oid, _) in &sorted {
        let first = u8::from_str_radix(&oid[0..2], 16).unwrap();
        for b in first..=255u8 {
            fanout[b as usize] += 1;
        }
    }

    let mut out = Vec::new();
    out.extend(b"\xff\x74\x4f\x63");
    out.extend(2u32.to_be_bytes());
    for v in fanout {
        out.extend(v.to_be_bytes());
    }
    for (oid, _) in &sorted {
        out.extend(hex::decode(oid).unwrap());
    }
    for (_, offset) in &sorted {
        let span = object_span(pack, *offset);
        let mut h = crc32fast::Hasher::new();
        h.update(&pack[*offset as usize..(*offset as usize + span)]);
        out.extend(h.finalize().to_be_bytes());
    }
    for (_, offset) in &sorted {
        out.extend((*offset as u32).to_be_bytes());
    }
    let pack_checksum = &pack[pack.len() - 20..];
    out.extend(pack_checksum);
    let idx_checksum = sha1(&out);
    out.extend(idx_checksum);
    out
}

fn object_span(pack: &[u8], offset: u64) -> usize {
    use pack_chain_microscope::git::pack::inflate_at;
    use pack_chain_microscope::git::{read_ofs_varint, read_size_varint, GitType};
    let start = offset as usize;
    let first = pack[start];
    let code = (first >> 4) & 7;
    let kind = GitType::from_code(code).unwrap();
    let (_, extra) = read_size_varint(&pack[start + 1..], first).unwrap();
    let mut p = start + 1 + extra;
    if matches!(kind, GitType::OfsDelta) {
        let (_, e) = read_ofs_varint(&pack[p + 1..], pack[p]).unwrap();
        p += 1 + e;
    } else if matches!(kind, GitType::RefDelta) {
        p += 20;
    }
    let (_, consumed) = inflate_at(pack, p, u64::MAX).unwrap();
    p + consumed - start
}

pub fn full_replace_delta(base_len: usize, new_content: &[u8]) -> Vec<u8> {
    use pack_chain_microscope::git::delta::{encode_delta_sizes, insert_command};
    let mut d = encode_delta_sizes(base_len as u64, new_content.len() as u64);
    d.extend(insert_command(new_content));
    d
}

pub fn copy_then_insert(base_len: usize, copy_n: u32, insert: &[u8]) -> Vec<u8> {
    use pack_chain_microscope::git::delta::{
        copy_command, encode_delta_sizes, insert_command,
    };
    let result_len = copy_n as usize + insert.len();
    let mut d = encode_delta_sizes(base_len as u64, result_len as u64);
    d.extend(copy_command(0, copy_n));
    d.extend(insert_command(insert));
    d
}

pub fn temp_store() -> (tempfile::TempDir, pack_chain_microscope::Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = pack_chain_microscope::Store::open(dir.path()).unwrap();
    (dir, store)
}

pub fn import(store: &pack_chain_microscope::Store, name: &str, bytes: &[u8]) -> i64 {
    store.import_bytes(name, bytes).unwrap().source_id
}

pub fn analyze(
    store: &pack_chain_microscope::Store,
    budget: pack_chain_microscope::Budget,
) -> pack_chain_microscope::analyze::engine::RunSummary {
    pack_chain_microscope::analyze::analyze_branch(store, "main", budget, None)
    .unwrap()
}

pub fn default_budget() -> pack_chain_microscope::Budget {
    pack_chain_microscope::Budget::default()
}

pub fn oid_of(kind: GitType, content: &[u8]) -> String {
    git_oid(kind, content)
}
