fn main(){
    let v0=b"hello world, this is the original blob payload".to_vec();
    let v1=b"hello world, this is the MODIFIED blob payload!!".to_vec();
    let mut d=pack_chain_microscope::git::delta::encode_delta_sizes(v0.len() as u64,v1.len() as u64);
    d.extend(pack_chain_microscope::git::delta::copy_command(0,25));
    d.extend(pack_chain_microscope::git::delta::insert_command(b"MODIFIED blob payload!!"));
    let out=pack_chain_microscope::git::delta::apply_delta(&v0,&d,u64::MAX).unwrap();
    println!("got:      {:?}",String::from_utf8_lossy(&out.output));
    println!("expected: {:?}",String::from_utf8_lossy(&v1));
    println!("match={}",out.output==v1);
    for c in &out.commands { println!("cmd {} src_off={} src_len={} out_off={} out_len={}",c.kind,c.src_offset,c.src_len,c.out_offset,c.out_len); }
}
