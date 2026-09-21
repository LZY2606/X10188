fn main(){
    // mirror test using common logic inline
    let v0=vec![b'a';4000];
    let mut v=v0.clone(); v.extend_from_slice(b"changed-tail"); let v1=v;
    let copy_n=v0.len() as u32;
    let result_len=copy_n as usize+12;
    let mut d=pack_chain_microscope::git::delta::encode_delta_sizes(v0.len() as u64,result_len as u64);
    d.extend(pack_chain_microscope::git::delta::copy_command(0,copy_n));
    d.extend(pack_chain_microscope::git::delta::insert_command(b"changed-tail"));
    println!("delta len {} starts with {:?}",d.len(), &d[..6]);
}
