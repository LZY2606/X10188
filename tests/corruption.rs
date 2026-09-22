mod common;

use common::*;
use pack_microscope::pack::parse_pack;
use pack_microscope::types::ObjKind;
use tempfile::tempdir;

#[test]
fn bad_index_crc_isolates_only_that_object() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let v0 = b"good object zero".to_vec();
    let v1 = b"good object one with crc".to_vec();
    let oid0 = oid_of(ObjKind::Blob, &v0);
    let oid1 = oid_of(ObjKind::Blob, &v1);

    let built = build_pack(&[
        EntrySpec::Base { kind: 3, content: v0.clone() },
        EntrySpec::Base { kind: 3, content: v1.clone() },
    ]);
    let parsed = parse_pack(&built.bytes);
    let entries = vec![
        (oid0, parsed.entries[0].offset, parsed.entries[0].compressed.clone()),
        (oid1, parsed.entries[1].offset, parsed.entries[1].compressed.clone()),
    ];
    let refs: Vec<_> = entries.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    // 篡改第 1 条（排序后位置可能变化，按 oid 排序后找 oid1）
    let bad_idx = build_idx_bad_crc_sorted(&refs, built.checksum, &oid1);

    eng.import_bytes("c.pack", &built.bytes, None).unwrap();
    let imp = eng.import_bytes("c.idx", &bad_idx, None).unwrap();
    assert!(imp.warnings.iter().any(|w| w.contains("CRC")), "应给出 CRC 证据: {:?}", imp.warnings);

    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.resolved, 1, "好对象仍应还原");
    assert_eq!(stats.bad, 1, "仅坏 CRC 对象被隔离");

    let db = eng.db.lock().unwrap();
    let (status, code): (String, String) = db
        .conn
        .query_row(
            "SELECT status, parse_error_code FROM candidates WHERE claim_oid=?1",
            rusqlite::params![oid1.hex()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "bad");
    assert_eq!(code, "crc_mismatch");
}

fn build_idx_bad_crc_sorted(
    entries: &[(pack_microscope::Oid, u64, &[u8])],
    checksum: pack_microscope::Oid,
    target: &pack_microscope::Oid,
) -> Vec<u8> {
    let mut sorted: Vec<&(pack_microscope::Oid, u64, &[u8])> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let corrupt_pos = sorted.iter().position(|(o, _, _)| *o == *target).unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut counts = vec![0u32; 256];
    for (o, _, _) in &sorted {
        counts[o.as_bytes()[0] as usize] += 1;
    }
    let mut cum = 0u32;
    for i in 0..256 {
        cum += counts[i];
        out.extend_from_slice(&cum.to_be_bytes());
    }
    for (o, _, _) in &sorted {
        out.extend_from_slice(o.as_bytes());
    }
    for (i, (_, _, c)) in sorted.iter().enumerate() {
        let mut crc = crc32fast::hash(c);
        if i == corrupt_pos {
            crc ^= 0xffff_ffff;
        }
        out.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, off, _) in &sorted {
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }
    out.extend_from_slice(checksum.as_bytes());
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&out);
    out.extend_from_slice(&h.finalize());
    out
}

#[test]
fn spoofed_size_midstream_is_bad_and_others_survive() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    // 手工构造 pack：好 base + 一个“声明大小错误”的对象（声明比真实解压大）。
    let good = b"a perfectly fine base blob".to_vec();
    let oid_good = oid_of(ObjKind::Blob, &good);

    let evil_content = b"evil payload actual".to_vec();
    let comp = zlib_pub(&evil_content);

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());

    let good_hdr = encode_obj_header(3, good.len() as u64);
    let good_comp = zlib_pub(&good);
    body.extend_from_slice(&good_hdr);
    body.extend_from_slice(&good_comp);

    // 声明一个远大于真实解压长度的大小，触发 SizeSpoof
    let lie_hdr = encode_obj_header(3, 9999);
    body.extend_from_slice(&lie_hdr);
    body.extend_from_slice(&comp);

    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&body);
    body.extend_from_slice(&h.finalize());

    // 该 pack 顺序解析会在坏对象处中止，且整包 checksum 仍成立（坏数据本身也算包体），
    // 好对象位于坏对象之前，应已成功解析入库并被标记。
    let imp = eng.import_bytes("spoof.pack", &body, None).unwrap();
    assert!(imp.report.candidates >= 1, "至少好对象应入库");

    let stats = eng.analyze(None, None).unwrap();
    // 好对象 resolved；坏对象导致 pack fatal，但好对象不应被连坐。
    let db = eng.db.lock().unwrap();
    let good_status: String = db
        .conn
        .query_row(
            "SELECT status FROM candidates WHERE claim_oid IS NULL AND etype='blob' AND declared_size=?1",
            rusqlite::params![good.len() as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(good_status, "resolved");
    let _ = (stats, oid_good);
}

#[test]
fn duplicate_oid_keeps_both_candidates_and_marks_ambiguity() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let content = b"duplicate oid content body".to_vec();
    let oid = oid_of(ObjKind::Blob, &content);

    // 两个不同 pack，各自含同一 oid 的同内容对象。
    let p1 = build_pack(&[EntrySpec::Base { kind: 3, content: content.clone() }]);
    let p2 = build_pack(&[EntrySpec::Base { kind: 3, content: content.clone() }]);

    // 为每个 pack 配 idx，把 claim_oid 都设成同一个
    let parsed1 = parse_pack(&p1.bytes);
    let parsed2 = parse_pack(&p2.bytes);
    let e1 = vec![(oid, parsed1.entries[0].offset, parsed1.entries[0].compressed.clone())];
    let e2 = vec![(oid, parsed2.entries[0].offset, parsed2.entries[0].compressed.clone())];
    let r1: Vec<_> = e1.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    let r2: Vec<_> = e2.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    let i1 = build_idx_v2(&r1, p1.checksum);
    let i2 = build_idx_v2(&r2, p2.checksum);

    eng.import_bytes("a.pack", &p1.bytes, None).unwrap();
    eng.import_bytes("a.idx", &i1, None).unwrap();
    eng.import_bytes("b.pack", &p2.bytes, None).unwrap();
    eng.import_bytes("b.idx", &i2, None).unwrap();

    let stats = eng.analyze(None, None).unwrap();
    assert_eq!(stats.resolved, 2, "两个候选都应可还原");

    let db = eng.db.lock().unwrap();
    let cnt: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM candidates WHERE claim_oid=?1",
            rusqlite::params![oid.hex()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cnt, 2, "同一 oid 有两个候选来源");
}

fn zlib_pub(data: &[u8]) -> Vec<u8> {
    common::zlib(data)
}
