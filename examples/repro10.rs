#[path="../tests/common/mod.rs"]
mod common;
use common::*;
use pack_chain_microscope::git::GitType;
fn main(){
    let (_d,store)=temp_store();
    let v0=b"hello world, this is the original blob payload".to_vec();
    let v1=b"hello world, this is the MODIFIED blob payload!!".to_vec();
    let v2=b"hello world, this is the MODIFIED blob payload!! and more".to_vec();
    let oid0=oid_of(GitType::Blob,&v0); let oid1=oid_of(GitType::Blob,&v1); let oid2=oid_of(GitType::Blob,&v2);
    let d1={
        let mut d=pack_chain_microscope::git::delta::encode_delta_sizes(v0.len() as u64,v1.len() as u64);
        d.extend(pack_chain_microscope::git::delta::copy_command(0,25));
        d.extend(pack_chain_microscope::git::delta::insert_command(b"MODIFIED blob payload!!"));
        d
    };
    let d2=copy_then_insert(v1.len(),v1.len() as u32,b" and more");
    let (pa,oa)=build_pack(&[PackItem::Base(GitType::Blob,v0.clone()),PackItem::OfsDelta{base_index:0,delta:d1}]);
    let idxa=build_idx(&pa,&[(oid0.clone(),oa[0]),(oid1.clone(),oa[1])]);
    import(&store,"a.pack",&pa); import(&store,"a.idx",&idxa);
    let (pb,ob)=build_pack(&[PackItem::RefDelta{base_oid:oid_bytes(&oid1),delta:d2}]);
    let idxb=build_idx(&pb,&[(oid2.clone(),ob[0])]);
    import(&store,"b.pack",&pb); import(&store,"b.idx",&idxb);
    let s=analyze(&store,default_budget());
    println!("status={} resolved={} blocked={}",s.status,s.resolved,s.blocked);
    let conn=store.db.lock().unwrap();
    let mut st=conn.prepare("SELECT message FROM evidence WHERE run_id=?1").unwrap();
    let msgs:Vec<String>=st.query_map(rusqlite::params![s.run_id],|r|r.get(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
    for m in msgs {println!("EV {m}");}
    let oid1c=pack_chain_microscope::git::git_oid(pack_chain_microscope::git::GitType::Blob,&v1);
    println!("oid1 computed={oid1c} given={oid1} equal={}",oid1c==oid1);
}
