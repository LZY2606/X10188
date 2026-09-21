#[path="../tests/common/mod.rs"]
mod common;
use common::*;
use pack_chain_microscope::git::GitType;
fn main(){
    let (_d, store)=temp_store();
    let big=vec![b'z';5000];
    let oid=oid_of(GitType::Blob,&big);
    let r=store.import_bytes("big",&loose_bytes(GitType::Blob,&big)).unwrap();
    println!("import kind={} errors={:?} id={}",r.kind,r.parse_errors,r.source_id);
    {
        let conn=store.db.lock().unwrap();
        let mut st=conn.prepare("SELECT id,oid,kind_name,inflate_size,parse_error,source_id FROM objects").unwrap();
        let rows:Vec<(i64,String,String,i64,Option<String>,i64)>=st.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        for row in rows { println!("{row:?}"); }
    }
    let g=store.load_graph("main").unwrap();
    println!("by_oid keys={:?}",g.by_oid.keys().collect::<Vec<_>>());
    let _=oid;
}
