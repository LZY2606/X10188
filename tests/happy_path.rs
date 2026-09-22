mod common;

use common::*;
use pack_microscope::pack::parse_pack;
use pack_microscope::types::ObjKind;
use tempfile::tempdir;

#[test]
fn chained_ofs_and_ref_delta_restores_and_recomputes_oid() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    // 三个文本 blob：
    //  v0 是独立 base；
    //  v1 由 v0 经 ofs-delta 得到；
    //  v2 由 v1 再经 ofs-delta 得到（链式 ofs）。
    let v0 = b"hello pack chain microscope base".to_vec();
    let v1 = b"hello pack chain microscope v1!!!".to_vec();
    let v2 = b"hello pack chain microscope v2-final".to_vec();
    let oid0 = oid_of(ObjKind::Blob, &v0);
    let oid1 = oid_of(ObjKind::Blob, &v1);
    let oid2 = oid_of(ObjKind::Blob, &v2);

    // 先放一个独立 loose blob 作为 ref-delta 的外部 base
    let vx = b"external loose base object body".to_vec();
    let oidx = oid_of(ObjKind::Blob, &vx);
    let (loose_bytes, loose_oid) = loose_object(3, &vx);
    assert_eq!(loose_oid, oidx);
    let loose_name = format!("objects/{}/{}", &oidx.hex()[..2], &oidx.hex()[2..]);
    let imp = eng
        .import_bytes(&loose_name, &loose_bytes, Some(&oidx.hex()))
        .unwrap();
    assert_eq!(imp.report.kind, "loose");

    // v3 由外部 loose base 经 ref-delta 还原
    let v3 = b"external loose base object body + ref-extension".to_vec();
    let oid3 = oid_of(ObjKind::Blob, &v3);
    let d3 = make_delta(&vx, &v3);

    let d01 = make_delta(&v0, &v1);
    let d12 = make_delta(&v1, &v2);

    // 逐步累加，确保 ofs 距离编码字节数已计入后续偏移。
    let h0 = encode_obj_header(3, v0.len() as u64);
    let h1_prefix = encode_obj_header(6, v1.len() as u64);
    let h2_prefix = encode_obj_header(6, v2.len() as u64);
    // zlib 压缩长度稳定（固定内容），用一次预构建获取。
    let probe = build_pack(&[
        EntrySpec::Base { kind: 3, content: v0.clone() },
        EntrySpec::OfsDelta { distance: 1, delta: d01.clone(), declared: d01.len() as u64 },
        EntrySpec::OfsDelta { distance: 1, delta: d12.clone(), declared: d12.len() as u64 },
        EntrySpec::RefDelta { base: oidx, delta: d3.clone(), declared: d3.len() as u64 },
    ]);
    let len0 = (probe.offsets[1] - probe.offsets[0]) as usize;
    let len1 = (probe.offsets[2] - probe.offsets[1]) as usize;
    let _ = (h0, h1_prefix, h2_prefix);
    let off0 = 12u64;
    let off1 = off0 + len0 as u64;
    let off2 = off1 + len1 as u64;
    let dist01 = off1 - off0;
    let dist12 = off2 - off1;
    // 校验：真实距离编码后字节数与试探一致（距离 <128 时为 1 字节）
    assert_eq!(encode_ofs_distance(dist01).len(), encode_ofs_distance(1).len());
    assert_eq!(encode_ofs_distance(dist12).len(), encode_ofs_distance(1).len());
    let built = build_pack(&[
        EntrySpec::Base { kind: 3, content: v0.clone() },
        EntrySpec::OfsDelta { distance: dist01, delta: d01.clone(), declared: d01.len() as u64 },
        EntrySpec::OfsDelta { distance: dist12, delta: d12.clone(), declared: d12.len() as u64 },
        EntrySpec::RefDelta { base: oidx, delta: d3.clone(), declared: d3.len() as u64 },
    ]);

    // 用核心解析器拿压缩数据，构造配套 idx
    let parsed = parse_pack(&built.bytes);
    assert!(parsed.fatal.is_none(), "pack 应解析成功: {:?}", parsed.fatal);
    let mut idx_entries: Vec<(pack_microscope::Oid, u64, Vec<u8>)> = Vec::new();
    let claimed = [oid0, oid1, oid2, oid3];
    for (i, e) in parsed.entries.iter().enumerate() {
        idx_entries.push((claimed[i], e.offset, e.compressed.clone()));
    }
    let refs: Vec<(pack_microscope::Oid, u64, &[u8])> = idx_entries
        .iter()
        .map(|(o, f, c)| (*o, *f, c.as_slice()))
        .collect();
    let idx = build_idx_v2(&refs, built.checksum);

    let p_imp = eng.import_bytes("small.pack", &built.bytes, None).unwrap();
    let i_imp = eng.import_bytes("small.idx", &idx, None).unwrap();
    assert_eq!(p_imp.report.candidates, 4);
    assert_eq!(i_imp.report.candidates, 4);

    let stats = eng.analyze(None, None).unwrap();
    assert!(stats.complete, "默认预算下应完整");
    assert_eq!(stats.resolved, 5, "4 pack + 1 loose");
    assert_eq!(stats.bad, 0);
    assert_eq!(stats.missing_base, 0);

    // 数据库核对每个对象 resolved_oid == 重算 git oid
    let db = eng.db.lock().unwrap();
    for (expect, content) in [
        (oid0, v0.clone()),
        (oid1, v1.clone()),
        (oid2, v2.clone()),
        (oid3, v3.clone()),
        (oidx, vx.clone()),
    ] {
        let got: String = db
            .conn
            .query_row(
                "SELECT resolved_oid FROM candidates WHERE resolved_oid=?1 AND resolved_size=?2",
                rusqlite::params![expect.hex(), content.len() as i64],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| panic!("未找到还原对象 {}", expect.hex()));
        assert_eq!(got, expect.hex());
    }

    // v2 的 delta 链应有两步取证（v0->v1->v2），且长度校验都通过
    let v2_id: i64 = db
        .conn
        .query_row(
            "SELECT c.id FROM candidates c WHERE c.resolved_oid=?1",
            rusqlite::params![oid2.hex()],
            |r| r.get(0),
        )
        .unwrap();
    let step_count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM delta_steps WHERE cand_id=?1",
            rusqlite::params![v2_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(step_count, 2, "链式 ofs delta 应记录两步");
    let all_ok: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM delta_steps WHERE cand_id=?1 AND input_ok=1 AND output_ok=1",
            rusqlite::params![v2_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(all_ok, 2);

    // 边表：v1->v0 ofs；v3->loose ref
    let ref_edge: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE kind='ref' AND ref_oid=?1 AND to_cand IS NOT NULL",
            rusqlite::params![oidx.hex()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ref_edge, 1);
}

#[test]
fn import_order_does_not_change_resolution() {
    // 同一组 pack/index，先 idx 后 pack vs 先 pack 后 idx，最终还原结果应一致。
    fn run(idx_first: bool) -> Vec<(String, String)> {
        let dir = tempdir().unwrap();
        let eng = engine(dir.path());
        let v0 = b"order independent base content".to_vec();
        let v1 = b"order independent base content changed!".to_vec();
        let oid0 = oid_of(ObjKind::Blob, &v0);
        let oid1 = oid_of(ObjKind::Blob, &v1);
        let d = make_delta(&v0, &v1);
        let dlen = d.len();
        let pre = build_pack(&[EntrySpec::Base { kind: 3, content: v0.clone() }]);
        let off0 = pre.offsets[0];
        let tmp = build_pack(&[
            EntrySpec::Base { kind: 3, content: v0.clone() },
            EntrySpec::OfsDelta { distance: 1, delta: d.clone(), declared: dlen as u64 },
        ]);
        let off1 = tmp.offsets[1];
        let built = build_pack(&[
            EntrySpec::Base { kind: 3, content: v0.clone() },
            EntrySpec::OfsDelta { distance: off1 - off0, delta: d, declared: dlen as u64 },
        ]);
        let parsed = parse_pack(&built.bytes);
        let entries = vec![
            (oid0, parsed.entries[0].offset, parsed.entries[0].compressed.clone()),
            (oid1, parsed.entries[1].offset, parsed.entries[1].compressed.clone()),
        ];
        let refs: Vec<_> = entries.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
        let idx = build_idx_v2(&refs, built.checksum);

        if idx_first {
            eng.import_bytes("a.idx", &idx, None).unwrap();
            eng.import_bytes("a.pack", &built.bytes, None).unwrap();
        } else {
            eng.import_bytes("a.pack", &built.bytes, None).unwrap();
            eng.import_bytes("a.idx", &idx, None).unwrap();
        }
        eng.analyze(None, None).unwrap();

        let db = eng.db.lock().unwrap();
        let mut out: Vec<(String, String)> = db
            .conn
            .prepare("SELECT resolved_oid, status FROM candidates ORDER BY resolved_oid")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .flatten()
            .collect();
        out.sort();
        out
    }
    let a = run(true);
    let b = run(false);
    assert_eq!(a, b);
    assert!(a.iter().all(|(_, s)| s == "resolved"));
}
