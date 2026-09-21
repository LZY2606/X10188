use pack_chain_microscope::git::{encode_ofs_distance, encode_pack_header, GitType};
use pack_chain_microscope::git::pack::parse_pack;
fn z(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder; use flate2::Compression; use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap(); e.finish().unwrap()
}
fn main(){
    let v0=vec![b'a';4000];
    let mut d=pack_chain_microscope::git::delta::encode_delta_sizes(4000,4012);
    d.extend(pack_chain_microscope::git::delta::copy_command(0,4000));
    d.extend(pack_chain_microscope::git::delta::insert_command(b"changed-tail"));
    let mut body=Vec::new();
    body.extend(encode_pack_header(GitType::Blob,4000));
    body.extend(z(&v0));
    let doff=body.len() as u64+12;
    body.extend(encode_pack_header(GitType::OfsDelta,d.len() as u64));
    body.extend(encode_ofs_distance(doff-12));
    body.extend(z(&d));
    let mut p=Vec::new();
    p.extend(b"PACK"); p.extend(2u32.to_be_bytes()); p.extend(2u32.to_be_bytes());
    p.extend(body);
    let cs={use sha1::{Sha1,Digest};Sha1::digest(&p).to_vec()};
    p.extend(cs);
    println!("delta stream len={}",d.len());
    let parsed=parse_pack(&p,None,None,&pack_chain_microscope::git::pack::ParseBudget::default());
    for e in &parsed.entries { println!("off={} start={} len={} err={:?} inflated={}",e.offset,e.data_start,e.compressed_len,e.error,e.inflated.len()); }
    println!("{:?}",parsed.errors);
}
