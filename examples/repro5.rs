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
    let r1=store.import_bytes("b.pack",&pack).unwrap();
    println!("pack report errors: {:?}", r1.parse_errors);
    let r2=store.import_bytes("b.idx",&idx).unwrap();
    println!("idx report errors: {:?}", r2.parse_errors);
    {
        let conn=store.db.lock().unwrap();
        let mut s=conn.prepare("SELECT id,locator,parse_error FROM objects").unwrap();
        let rows:Vec<_>=s.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        for row in rows { println!("obj {row:?}"); }
        let (summary,errors):(String,String)=conn.query_row("SELECT parse_summary,parse_errors FROM sources WHERE kind='pack'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        println!("pack summary={summary} errors={errors}");
    }
    let summary=analyze(&store, Budget{max_depth:50,max_expand_bytes:100,max_single_bytes:1_000_000});
    println!("summary status={} run_id={}",summary.status,summary.run_id);
}
