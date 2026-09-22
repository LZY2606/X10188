mod common;

use common::*;
use pack_microscope::types::ObjKind;
use tempfile::tempdir;

#[test]
fn adding_base_only_recomputes_affected_subgraph() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    // 两个 ref-delta：d1 依赖 base(缺)；d2 独立 resolved。
    let base = b"later added external base body".to_vec();
    let t1 = b"later added external base body with suffix".to_vec();
    let base_oid = oid_of(ObjKind::Blob, &base);
    let t1_oid = oid_of(ObjKind::Blob, &t1);

    let independent = b"totally unrelated standalone blob".to_vec();
    let ind_oid = oid_of(ObjKind::Blob, &independent);

    let d1 = make_delta(&base, &t1);
    let d1len = d1.len() as u64;

    // 一个 pack 含 ref-delta(d1) 和独立 base(independent)
    let built = build_pack(&[
        EntrySpec::RefDelta { base: base_oid, delta: d1, declared: d1len },
        EntrySpec::Base { kind: 3, content: independent.clone() },
    ]);
    eng.import_bytes("later.pack", &built.bytes, None).unwrap();

    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.missing_base, 1);
    assert_eq!(stats.resolved, 1);

    // 记录独立对象的 run_id（补入 base 后不应被动到）
    let independent_run_before: i64 = {
        let db = eng.db.lock().unwrap();
        db.conn
            .query_row(
                "SELECT run_id FROM candidates WHERE claim_oid IS NULL AND etype='blob' AND declared_size=?1",
                rusqlite::params![independent.len() as i64],
                |r| r.get(0),
            )
            .unwrap()
    };

    // 补入缺失 base（loose）
    let (loose_bytes, loose_oid) = loose_object(3, &base);
    assert_eq!(loose_oid, base_oid);
    let name = format!("objects/{}/{}", &base_oid.hex()[..2], &base_oid.hex()[2..]);
    let imp = eng.import_bytes(&name, &loose_bytes, Some(&base_oid.hex())).unwrap();
    let seed = imp.report.source_id; // 注意：需要的是 cand id，下面从 DB 取

    // 取新 loose 候选 id
    let seed_cand: i64 = {
        let db = eng.db.lock().unwrap();
        db.conn
            .query_row(
                "SELECT id FROM candidates WHERE source_id=?1",
                rusqlite::params![seed],
                |r| r.get(0),
            )
            .unwrap()
    };

    let stats = eng
        .analyze_after_import(vec![seed_cand], None, None)
        .unwrap();
    // 新 base 与其依赖 d1 被解析；独立对象不应被重算
    assert!(stats.complete);
    assert_eq!(stats.resolved, 2, "局部重算只处理 base+d1 两个对象");

    let db = eng.db.lock().unwrap();
    // d1 现在 resolved 且 oid 正确
    let d1_status: String = db
        .conn
        .query_row(
            "SELECT status FROM candidates WHERE etype='ref-delta'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(d1_status, "resolved");

    // 通过 resolved_content 校验 t1 内容
    let got: String = db
        .conn
        .query_row(
            "SELECT hex(resolved_content) FROM candidates WHERE etype='ref-delta'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(got.to_lowercase(), hex::encode(&t1));
    let _ = t1_oid;
    let _ = ind_oid;

    // 独立对象 run_id 保持不变（未被局部重算触及）
    let independent_run_after: i64 = db
        .conn
        .query_row(
            "SELECT run_id FROM candidates WHERE claim_oid IS NULL AND etype='blob' AND declared_size=?1",
            rusqlite::params![independent.len() as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        independent_run_before, independent_run_after,
        "补入 base 不应重算无关对象"
    );
}
