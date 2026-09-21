#[path="../tests/common/mod.rs"]
mod common;
use common::*;
use pack_chain_microscope::git::GitType;
fn main(){
    let (_d, store)=temp_store();
    let big=vec![b'z';5000];
    let oid=oid_of(GitType::Blob,&big);
    import(&store,"big",&loose_bytes(GitType::Blob,&big));
    let g=store.load_graph("main").unwrap();
    println!("nodes={} by_oid bucket={:?}",g.nodes.len(), g.by_oid.get(&oid).map(|v|v.len()));
    let budget=pack_chain_microscope::Budget{max_depth:50,max_expand_bytes:100000,max_single_bytes:1000};
    let s=analyze(&store,budget);
    println!("status={} blocked={} resolved={} paused={}",s.status,s.blocked,s.resolved,s.paused);
    let conn=store.db.lock().unwrap();
    let mut st=conn.prepare("SELECT status,summary FROM runs ORDER BY id DESC LIMIT 1").unwrap();
    let row: (String,String)=st.query_row([],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    println!("run {row:?}");
}
