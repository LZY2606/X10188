mod common;

use common::*;
use pack_microscope::pack::parse_pack;
use pack_microscope::types::ObjKind;
use tempfile::tempdir;

#[test]
fn missing_external_base_is_isolated_with_blocking_chain() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let v1 = b"target object after missing ref base".to_vec();
    // 一个内容确定但不导入的外部 base
    let missing = oid_of(ObjKind::Blob, b"definitely not imported base body");
    let d = make_delta(b"stale base placeholder different length", &v1);
    let dlen = d.len() as u64;
    let built = build_pack(&[EntrySpec::RefDelta {
        base: missing,
        delta: d,
        declared: dlen,
    }]);

    eng.import_bytes("p.pack", &built.bytes, None).unwrap();
    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.missing_base, 1);
    assert_eq!(stats.resolved, 0);

    let db = eng.db.lock().unwrap();
    let (status, chain): (String, String) = db
        .conn
        .query_row(
            "SELECT status, blocking_chain FROM candidates",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "missing_base");
    let chain_v: serde_json::Value = serde_json::from_str(&chain).unwrap();
    let arr = chain_v.as_array().unwrap();
    assert!(!arr.is_empty(), "必须列出阻塞链");
    assert!(chain.contains(&missing.hex()));
}


#[test]
fn ref_delta_cycle_is_marked_bad() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    // 三个 ref-delta，用 idx 把它们的 claim_oid 绑定成彼此引用：
    //  entry0 base->oid1, entry1 base->oid2, entry2 base->oid0 => 环。
    let oid0 = oid_of(ObjKind::Blob, b"fake claimed body 0");
    let oid1 = oid_of(ObjKind::Blob, b"fake claimed body 1");
    let oid2 = oid_of(ObjKind::Blob, b"fake claimed body 2");

    // delta 的“假定 base”内容长度，用一段固定缓冲区；环检测先于 apply 成功。
    let base0 = b"00000000000000000000".to_vec();
    let base1 = b"11111111111111111111".to_vec();
    let base2 = b"22222222222222222222".to_vec();
    let d0 = make_delta(&base1, &base0);
    let d1 = make_delta(&base2, &base1);
    let d2 = make_delta(&base0, &base2);

    let built = build_pack(&[
        EntrySpec::RefDelta { base: oid1, delta: d0.clone(), declared: d0.len() as u64 },
        EntrySpec::RefDelta { base: oid2, delta: d1.clone(), declared: d1.len() as u64 },
        EntrySpec::RefDelta { base: oid0, delta: d2.clone(), declared: d2.len() as u64 },
    ]);
    let parsed = parse_pack(&built.bytes);
    assert!(parsed.fatal.is_none());

    let entries = vec![
        (oid0, parsed.entries[0].offset, parsed.entries[0].compressed.clone()),
        (oid1, parsed.entries[1].offset, parsed.entries[1].compressed.clone()),
        (oid2, parsed.entries[2].offset, parsed.entries[2].compressed.clone()),
    ];
    let refs: Vec<_> = entries.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    let idx = build_idx_v2(&refs, built.checksum);

    eng.import_bytes("cycle.pack", &built.bytes, None).unwrap();
    eng.import_bytes("cycle.idx", &idx, None).unwrap();

    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.bad, 3, "环上三个对象都应隔离为 bad");
    let db = eng.db.lock().unwrap();
    let codes: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM candidates WHERE status='bad' AND runtime_error_code='delta_cycle'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(codes, 3);
}
