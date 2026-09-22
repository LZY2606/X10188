mod common;
use common::*;
use microscope::git::{git_oid, Kind};
use microscope::Budget;

fn status(app: &microscope::AppState, entry: i64) -> serde_json::Value {
    let store = app.store.lock().unwrap();
    store
        .db
        .query_row(
            "SELECT status,COALESCE(actual_oid,''),COALESCE(oid_ok,-1),COALESCE(depth,0),COALESCE(blockers,'')
             FROM resolutions WHERE branch='default' AND entry_id=?1",
            rusqlite::params![entry],
            |r| {
                Ok(serde_json::json!({
                    "status": r.get::<_,String>(0).unwrap(),
                    "oid": r.get::<_,String>(1).unwrap(),
                    "oid_ok": r.get::<_,i64>(2).unwrap(),
                    "depth": r.get::<_,i64>(3).unwrap(),
                    "blockers": r.get::<_,String>(4).unwrap(),
                }))
            },
        )
        .unwrap()
}

#[test]
fn chained_ofs_and_ref_delta_roundtrip() {
    let app = temp_app("chain");
    // base blob
    let base = b"hello world, this is the immutable base content!!".to_vec();
    let base_oid = git_oid(Kind::Blob, &base);
    // delta 1 -> base: copy all + insert
    let d1 = encode_delta(
        base.len(),
        &[
            DeltaOp::Copy(0, base.len()),
            DeltaOp::Insert(b"-delta1".to_vec()),
        ],
    );
    let mut r1 = base.clone();
    r1.extend_from_slice(b"-delta1");
    // ofs delta (neg = distance to base)
    // We must know offsets; build once to measure.
    let probe = build_pack(&[
        PackObj::Full(Kind::Blob, base.clone()),
        PackObj::Ofs { neg: 1, delta: d1.clone(), result: (Kind::Blob, r1.clone()) },
    ]);
    let neg = probe.offsets[1] - probe.offsets[0];
    let built = build_pack(&[
        PackObj::Full(Kind::Blob, base.clone()),
        PackObj::Ofs { neg, delta: d1.clone(), result: (Kind::Blob, r1.clone()) },
    ]);
    // ref delta in a separate pack, based on the ofs result oid
    let r1_oid = git_oid(Kind::Blob, &r1);
    let d2 = encode_delta(
        r1.len(),
        &[
            DeltaOp::Copy(0, r1.len()),
            DeltaOp::Insert(b"-ref2".to_vec()),
        ],
    );
    let mut r2 = r1.clone();
    r2.extend_from_slice(b"-ref2");
    let r2_oid = git_oid(Kind::Blob, &r2);
    let pack2 = build_pack(&[PackObj::Ref {
        base_oid: r1_oid.clone(),
        delta: d2,
        result: (Kind::Blob, r2.clone()),
    }]);

    let rep1 = app.import_file("chained.pack", &built.bytes).expect("pack1");
    app.import_file("chained.idx", &built.idx).expect("idx1");
    let rep2 = app.import_file("ref.pack", &pack2.bytes).expect("pack2");
    app.import_file("ref.idx", &pack2.idx).expect("idx2");

    let _ = (rep1, rep2, base_oid, r2_oid.clone());
    // entries: pack1 has 2, pack2 has 1
    let s = status(&app, 1);
    assert_eq!(s["status"], "ok");
    let s2 = status(&app, 2);
    assert_eq!(s2["status"], "ok", "ofs-delta must resolve");
    assert_eq!(s2["oid"], serde_json::json!(r1_oid));
    assert_eq!(s2["oid_ok"], 1);
    assert_eq!(s2["depth"], 1);
    let s3 = status(&app, 3);
    assert_eq!(s3["status"], "ok", "ref-delta across packs must resolve");
    assert_eq!(s3["oid"], serde_json::json!(r2_oid.clone()));
    assert_eq!(s3["depth"], 2);
}

#[test]
fn missing_external_base_is_blocked_not_fatal() {
    let app = temp_app("missing");
    let ghost = "0".repeat(40);
    let delta = encode_delta(8, &[DeltaOp::Insert(b"00000000".to_vec())]);
    let result = b"00000000".to_vec();
    let built = build_pack(&[PackObj::Ref {
        base_oid: ghost.clone(),
        delta,
        result: (Kind::Blob, result),
    }]);
    app.import_file("thin.pack", &built.bytes).unwrap();
    // no idx: claimed oid absent -> entry still resolves to missing_base
    let s = status(&app, 1);
    assert_eq!(s["status"], "error");
    let blockers: serde_json::Value = serde_json::from_str(s["blockers"].as_str().unwrap()).unwrap();
    assert!(blockers[0]["code"].as_str().unwrap().contains("missing"));
}
