#[path="../tests/common/mod.rs"] mod common;
use common::*;
use microscope::git::{git_oid, Kind};
fn main(){
    let app = temp_app("dbgadd");
    let base = b"late arriving base object body".to_vec();
    let base_oid = git_oid(Kind::Blob, &base);
    let unrelated = b"totally unrelated content x".to_vec();
    let d = encode_delta(base.len(), &[DeltaOp::Copy(0,base.len()),DeltaOp::Insert(b"+late".to_vec())]);
    let mut derived=base.clone(); derived.extend_from_slice(b"+late");
    let thin = build_pack(&[PackObj::Ref{base_oid: base_oid.clone(), delta:d, result:(Kind::Blob,derived)}]);
    let unrel = build_pack(&[PackObj::Full(Kind::Blob, unrelated)]);
    app.import_file("unrel.pack",&unrel.bytes).unwrap();
    app.import_file("unrel.idx",&unrel.idx).unwrap();
    app.import_file("thin.pack",&thin.bytes).unwrap();
    let loose = loose_object(Kind::Blob,&base);
    let rep = app.import_file(&format!("{base_oid}.zlib"), &loose).unwrap();
    println!("run ok={} paused={} err={} reused={} total={}", rep.run.ok, rep.run.paused, rep.run.error, rep.run.reused, rep.run.total_bytes);
    let s=app.store.lock().unwrap();
    let mut stmt=s.db.prepare("SELECT entry_id,status,run_seq,reused FROM resolutions WHERE branch='default' ORDER BY entry_id").unwrap();
    for r in stmt.query_map([],|r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?))).unwrap(){
        println!("{:?}", r.unwrap());
    }
    let mut e=s.db.prepare("SELECT entry_id,error FROM resolutions WHERE branch='default'").unwrap();
    for r in e.query_map([],|r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?))).unwrap(){
        println!("ERR {:?}", r.unwrap());
    }
}
