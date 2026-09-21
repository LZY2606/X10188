use pack_chain_microscope::git::pack::{parse_pack, ParseBudget};
use pack_chain_microscope::git::{encode_ofs_distance, encode_pack_header, GitType};

fn z(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder; use flate2::Compression; use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap(); e.finish().unwrap()
}

fn main() {
    check_header();
    let v0 = vec![b'a'; 4000];
    let mut d = pack_chain_microscope::git::delta::encode_delta_sizes(v0.len() as u64, (v0.len()+12) as u64);
    d.extend(pack_chain_microscope::git::delta::copy_command(0, v0.len() as u32));
    d.extend(pack_chain_microscope::git::delta::insert_command(b"changed-tail"));

    let mut body = Vec::new();
    body.extend(encode_pack_header(GitType::Blob, v0.len() as u64));
    body.extend(z(&v0));
    let delta_off = body.len() as u64 + 12;
    body.extend(encode_pack_header(GitType::OfsDelta, d.len() as u64));
    body.extend(encode_ofs_distance(delta_off - 12));
    body.extend(z(&d));
    let mut pack = Vec::new();
    pack.extend(b"PACK"); pack.extend(2u32.to_be_bytes()); pack.extend(2u32.to_be_bytes());
    pack.extend(body);
    let cs = { use sha1::{Sha1, Digest}; Sha1::digest(&pack).to_vec() };
    pack.extend(cs);
    println!("delta_off={delta_off}");
    let parsed = parse_pack(&pack, None, None, &ParseBudget::default());
    for e in &parsed.entries {
        println!("entry off={} datastart={} complen={} err={:?} inflen={}", e.offset, e.data_start, e.compressed_len, e.error, e.inflated.len());
    }
    println!("pack errors: {:?}", parsed.errors);
}

#[allow(dead_code)]
fn check_header() {
    let h = encode_pack_header(GitType::Blob, 4000);
    println!("header bytes: {:?}", h);
}
