mod common;

use common::*;
use pack_microscope::types::ObjKind;
use tempfile::tempdir;

#[test]
fn ofs_distance_out_of_bounds_is_reported() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    // 手工构造一个 ofs-delta，其负向距离大于自身偏移（落到 header 之前）。
    let payload = make_delta(b"base placeholder data", b"target placeholder data!!");
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes());
    // 对象位于偏移 12，声明距离 100（越界）
    body.extend(encode_obj_header(6, payload.len() as u64));
    body.extend(encode_ofs_distance(100));
    body.extend(zlib(&payload));

    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&body);
    body.extend_from_slice(&h.finalize());

    let outcome = eng.import_bytes("oob.pack", &body, None).unwrap();
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.contains("ofs") || w.contains("包级问题")),
        "应报告 ofs 越界/包级问题: {:?}",
        outcome.warnings
    );
    // 头部级 ofs 越界无法定位该对象，记录为 pack 源的 fatal 证据（隔离其后所有对象）。
    let db = eng.db.lock().unwrap();
    let (status, note): (String, String) = db
        .conn
        .query_row(
            "SELECT status, note FROM sources WHERE kind='pack'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "fatal");
    assert!(note.contains("ofs-delta") || note.contains("越界"), "note={}", note);
}

#[test]
fn mismatched_index_is_flagged_and_pack_still_analyzed() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let content = b"standalone blob for mismatch test".to_vec();
    let _oid = oid_of(ObjKind::Blob, &content);
    let p1 = build_pack(&[EntrySpec::Base {
        kind: 3,
        content: content.clone(),
    }]);
    let p2 = build_pack(&[EntrySpec::Base {
        kind: 3,
        content: b"different pack content entirely body".to_vec(),
    }]);
    let parsed2 = pack_microscope::pack::parse_pack(&p2.bytes);
    // 用 p2 的 checksum 造一个 idx，却去配 p1
    let fake_oid = oid_of(ObjKind::Blob, &content);
    let entries = vec![(
        fake_oid,
        parsed2.entries[0].offset,
        parsed2.entries[0].compressed.clone(),
    )];
    let refs: Vec<_> = entries
        .iter()
        .map(|(o, f, c)| (*o, *f, c.as_slice()))
        .collect();
    let idx = build_idx_v2(&refs, p2.checksum);

    eng.import_bytes("real.pack", &p1.bytes, None).unwrap();
    let imp = eng.import_bytes("wrong.idx", &idx, None).unwrap();
    assert!(
        imp.warnings.iter().any(|w| w.contains("不配套") || w.contains("找不到配套")),
        "应提示 index 与 pack 不配套: {:?}",
        imp.warnings
    );
    // pack 仍可独立分析（无 idx 时自证 oid）
    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.resolved, 1);
}
