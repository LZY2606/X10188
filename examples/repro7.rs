#[path="../tests/common/mod.rs"]
mod common;
use common::*;
use pack_chain_microscope::git::GitType;
fn main(){
    // loose cap
    {
        let (_d, store)=temp_store();
        let big=vec![b'z';5000];
        let oid=oid_of(GitType::Blob,&big);
        import(&store,"big",&loose_bytes(GitType::Blob,&big));
        let s=analyze(&store,pack_chain_microscope::Budget{max_depth:50,max_expand_bytes:100000,max_single_bytes:1000});
        println!("CAP status={} blocked={} bytes={}",s.status,s.blocked,s.bytes_used);
    }
    // later base
    {
        let (_d, store)=temp_store();
        let base=b"the base body".to_vec();
        let base_oid=oid_of(GitType::Blob,&base);
        let next=b"the base body EXTENDED".to_vec();
        let next_oid=oid_of(GitType::Blob,&next);
        let delta=copy_then_insert(base.len(),base.len() as u32,b" EXTENDED");
        let (pack,offs)=build_pack(&[PackItem::RefDelta{base_oid:oid_bytes(&base_oid),delta}]);
        let idx=build_idx(&pack,&[(next_oid,offs[0])]);
        import(&store,"d.pack",&pack);
        import(&store,"d.idx",&idx);
        let s1=analyze(&store,default_budget());
        println!("FIRST {} {}",s1.status,s1.blocked);
        import(&store,&base_oid,&loose_bytes(GitType::Blob,&base));
        let s2=analyze(&store,default_budget());
        println!("SECOND {} resolved={} blocked={}",s2.status,s2.resolved,s2.blocked);
        let conn=store.db.lock().unwrap();
        let mut st=conn.prepare("SELECT message FROM evidence WHERE run_id=?1").unwrap();
        let msgs:Vec<String>=st.query_map(rusqlite::params![s2.run_id],|r|r.get(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        for m in msgs { println!("EV {m}"); }
    }
}
