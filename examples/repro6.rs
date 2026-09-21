#[path="../tests/common/mod.rs"]
mod common;
use common::*;
use pack_chain_microscope::git::GitType;
use pack_chain_microscope::Budget;
fn main(){
    let (_dir, store)=temp_store();
    let v0=vec![b'a';4000];
    let mut v1=v0.clone(); v1.extend_from_slice(b"changed-tail");
    let oid0=oid_of(GitType::Blob,&v0);
    let oid1=oid_of(GitType::Blob,&v1);
    let d1=copy_then_insert(v0.len(),v0.len() as u32,b"changed-tail");
    let (pack,offs)=build_pack(&[
        PackItem::Base(GitType::Blob,v0),
        PackItem::OfsDelta{base_index:0,delta:d1},
    ]);
    let idx=build_idx(&pack,&[(oid0,offs[0]),(oid1,offs[1])]);
    import(&store,"b.pack",&pack);
    import(&store,"b.idx",&idx);
    {
        let conn=store.db.lock().unwrap();
        let mut s=conn.prepare("SELECT oid,kind_name,inflate_size FROM objects").unwrap();
        let rows:Vec<_>=s.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        for r in rows { println!("{r:?}"); }
    }
    let summary=analyze(&store, Budget{max_depth:50,max_expand_bytes:100,max_single_bytes:1_000_000});
    println!("status={} resolved={} blocked={} paused={}",summary.status,summary.resolved,summary.blocked,summary.paused);
}
