use packchain_microscope::support::*;
#[test]
fn dbg() {
    let dir=tempfile::tempdir().unwrap();
    let conn=packchain_microscope::db::open(dir.path().join("t.db").to_str().unwrap()).unwrap();
    let db=std::sync::Arc::new(Db(std::sync::Mutex::new(conn)));
    let base=b"hello base object".to_vec();
    let s1=b" + delta one".to_vec(); let s2=b" + delta two".to_vec();
    let d1=append_delta(base.len() as u64,&s1);
    let mut mid=base.clone(); mid.extend_from_slice(&s1);
    let d2=append_delta(mid.len() as u64,&s2);
    let mut out=mid.clone(); out.extend_from_slice(&s2);
    let (pack,built)=build_pack(&[base_spec(&base),
        PackEntrySpec::OfsDelta{base_index:0,delta:&d1},
        PackEntrySpec::OfsDelta{base_index:1,delta:&d2}]);
    let oids=[parse_oid_bytes(&git_oid(ObjType::Blob,&base)),
        parse_oid_bytes(&git_oid(ObjType::Blob,&mid)),
        parse_oid_bytes(&git_oid(ObjType::Blob,&out))];
    let idx=build_idx_for(&pack,&built,&oids);
    packchain_microscope::engine::import::import_bytes(&db,dir.path().to_str().unwrap(),"a.pack",&pack);
    packchain_microscope::engine::import::import_bytes(&db,dir.path().to_str().unwrap(),"a.idx",&idx);
    let c=db.0.lock().unwrap();
    let mut stmt=c.prepare("SELECT id,oid,kind,status,error_code,error_note,resolve_depth FROM nodes").unwrap();
    for r in stmt.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,i64>(6)?))).unwrap() {
        println!("NODE {:?}",r.unwrap());
    }
    let n: i64=c.query_row("SELECT COUNT(*) FROM steps",[],|r|r.get(0)).unwrap();
    println!("steps={}",n);
}
