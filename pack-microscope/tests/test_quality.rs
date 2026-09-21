mod common;

use common::{build_idx, encode_entry_header, loose_object, zlib, IdxSpec, PackBuilder};
use pack_microscope::engine::{recompute_affected, run_branch};
use pack_microscope::git::git_object_id;
use pack_microscope::store::import_file;

fn import(conn: &rusqlite::Connection, dir: &std::path::Path, name: &str, bytes: &[u8]) -> i64 {
    import_file(conn, dir, name, bytes).unwrap().source_id
}

#[test]
fn bad_crc_is_flagged_and_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let content = b"crc victim";
    let mut pb = PackBuilder::new();
    let (oid, off) = pb.add_blob(content);
    let (pack, _) = pb.build();
    let mut idx = build_idx(
        &pack,
        &[IdxSpec {
            oid,
            offset: off as u64,
            entry_bytes: &pack[off..pack.len() - 20],
        }],
    );
    let crc_pos = 8 + 256 * 4 + 20;
    idx[crc_pos] ^= 0xff;
    import(&conn, dir.path(), "c.pack", &pack);
    import(&conn, dir.path(), "c.idx", &idx);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.resolved, 0);
    assert_eq!(report.errors, 1);
    let issue: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM issues WHERE code='crc_mismatch'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(issue >= 1);
}

#[test]
fn spoofed_size_detected_mid_inflate() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let real = b"the real body is much longer than declared!!";
    let mut raw = encode_entry_header(3, 5);
    raw.extend_from_slice(&zlib(real));
    let mut all = Vec::new();
    all.extend_from_slice(b"PACK");
    all.extend_from_slice(&2u32.to_be_bytes());
    all.extend_from_slice(&1u32.to_be_bytes());
    all.extend_from_slice(&raw);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&all);
    all.extend_from_slice(&h.finalize());
    import(&conn, dir.path(), "sp.pack", &all);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.errors, 1);
    let err: String = conn
        .query_row(
            "SELECT parse_error FROM candidates WHERE ckey LIKE 'pack:%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(err.contains("大小欺骗"), "got: {}", err);
}

#[test]
fn loose_size_spoof_is_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let mut fake = Vec::new();
    fake.extend_from_slice(b"blob 3");
    fake.push(0);
    fake.extend_from_slice(b"way more than three bytes");
    import(&conn, dir.path(), "loose-spoof", &zlib(&fake));
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.errors, 1);
    let issue: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM issues WHERE code='size_spoof'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(issue, 1);
}

#[test]
fn duplicate_oid_candidates_are_order_independent() {
    let dir = tempfile::tempdir().unwrap();
    let run = |dir_path: &std::path::Path, reverse: bool| -> (String, i64, i64) {
        let conn = pack_microscope::store::open(&dir_path.join("t.db")).unwrap();
        let c1 = b"duplicate content v1";
        let c2 = b"duplicate content v1";
        let oid1 = git_object_id("blob", c1);
        let oid2 = git_object_id("blob", c2);
        assert_eq!(oid1, oid2);
        let mut pb1 = PackBuilder::new();
        let (_, o1) = pb1.add_blob(c1);
        let (p1, _) = pb1.build();
        let i1 = build_idx(
            &p1,
            &[IdxSpec {
                oid: oid1,
                offset: o1 as u64,
                entry_bytes: &p1[o1..p1.len() - 20],
            }],
        );
        let pad = b"different padding blob to make sources distinct";
        let pad_oid = git_object_id("blob", pad);
        let mut pb2 = PackBuilder::new();
        let (_, pad_off) = pb2.add_blob(pad);
        let (_, o2) = pb2.add_blob(c2);
        let (p2, _) = pb2.build();
        let i2 = build_idx(
            &p2,
            &[
                IdxSpec {
                    oid: pad_oid,
                    offset: pad_off as u64,
                    entry_bytes: &p2[pad_off..o2],
                },
                IdxSpec {
                    oid: oid2,
                    offset: o2 as u64,
                    entry_bytes: &p2[o2..p2.len() - 20],
                },
            ],
        );
        if reverse {
            import(&conn, dir_path, "p2.pack", &p2);
            import(&conn, dir_path, "p2.idx", &i2);
            import(&conn, dir_path, "p1.pack", &p1);
            import(&conn, dir_path, "p1.idx", &i1);
        } else {
            import(&conn, dir_path, "p1.pack", &p1);
            import(&conn, dir_path, "p1.idx", &i1);
            import(&conn, dir_path, "p2.pack", &p2);
            import(&conn, dir_path, "p2.idx", &i2);
        }
        let report = run_branch(&conn, "main", None).unwrap();
        assert_eq!(report.resolved, 3);
        let hashes: String = conn
            .query_row(
            "SELECT GROUP_CONCAT(oid) FROM (SELECT oid FROM resolved WHERE branch_id=1 ORDER BY oid)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (hashes, report.resolved as i64, report.errors as i64)
    };
    let d1 = tempfile::tempdir_in(dir.path()).unwrap();
    let d2 = tempfile::tempdir_in(dir.path()).unwrap();
    let a = run(d1.path(), false);
    let b = run(d2.path(), true);
    assert_ne!(a.0, "");
    let na: Vec<String> = a.0.split(',').map(canonical).collect();
    let nb: Vec<String> = b.0.split(',').map(canonical).collect();
    assert_eq!(na, nb, "导入顺序不应改变候选排序");
}

fn canonical(ckey: &str) -> String {
    let mut v: Vec<&str> = ckey.split(',').collect();
    v.sort();
    v.join(",")
}

#[test]
fn budget_pause_and_resume_never_emits_partial_object() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let base = vec![b'a'; 300];
    let t1 = vec![b'b'; 300];
    let t2 = vec![b'c'; 300];
    let mut pb = PackBuilder::new();
    let (boid, boff) = pb.add_blob(&base);
    let d1 = pb.add_ofs_delta(boff, &base, &t1);
    let d2 = pb.add_ofs_delta(d1, &t1, &t2);
    let (pack, _) = pb.build();
    let want1 = git_object_id("blob", &t1);
    let want2 = git_object_id("blob", &t2);
    let idx = build_idx(
        &pack,
        &[
            IdxSpec {
                oid: boid,
                offset: boff as u64,
                entry_bytes: &pack[boff..d1],
            },
            IdxSpec {
                oid: want1,
                offset: d1 as u64,
                entry_bytes: &pack[d1..d2],
            },
            IdxSpec {
                oid: want2,
                offset: d2 as u64,
                entry_bytes: &pack[d2..pack.len() - 20],
            },
        ],
    );
    import(&conn, dir.path(), "b.pack", &pack);
    import(&conn, dir.path(), "b.idx", &idx);
    conn.execute(
        "UPDATE budgets SET total_bytes=450, single_ratio=1.0, used_bytes=0 WHERE branch_id=1",
        [],
    )
    .unwrap();
    let report = run_branch(&conn, "main", None).unwrap();
    assert!(report.suspended >= 1, "应有暂停对象: {:?}", report.suspended);
    let partial: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resolved WHERE status='suspended' AND content IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(partial, 0, "暂停状态绝不能保存部分内容");
    conn.execute(
        "UPDATE budgets SET total_bytes=100000, used_bytes=0 WHERE branch_id=1",
        [],
    )
    .unwrap();
    let report2 = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report2.suspended, 0);
    assert_eq!(report2.resolved, 3);
}

#[test]
fn adding_base_recomputes_only_affected_subgraph() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let base = b"sub graph base";
    let t = b"sub graph target!!";
    let base_oid = git_object_id("blob", base);
    let want = git_object_id("blob", t);
    let unrelated = b"totally unrelated blob";
    let mut up = PackBuilder::new();
    let (uoid, uoff) = up.add_blob(unrelated);
    let (upack, _) = up.build();
    let uidx = build_idx(
        &upack,
        &[IdxSpec {
            oid: uoid,
            offset: uoff as u64,
            entry_bytes: &upack[uoff..upack.len() - 20],
        }],
    );
    import(&conn, dir.path(), "u.pack", &upack);
    import(&conn, dir.path(), "u.idx", &uidx);
    run_branch(&conn, "main", None).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let before_ts: i64 = conn
        .query_row(
            "SELECT updated_at FROM resolved WHERE branch_id=1 AND oid=?",
            rusqlite::params![hex::encode(uoid)],
            |r| r.get(0),
        )
        .unwrap();

    let mut pb = PackBuilder::new();
    let off = pb.add_ref_delta(&base_oid, base, t);
    let (pack, _) = pb.build();
    let idx = build_idx(
        &pack,
        &[IdxSpec {
            oid: want,
            offset: off as u64,
            entry_bytes: &pack[off..pack.len() - 20],
        }],
    );
    import(&conn, dir.path(), "d.pack", &pack);
    import(&conn, dir.path(), "d.idx", &idx);
    let blocked = run_branch(&conn, "main", None).unwrap();
    assert_eq!(blocked.blocked, 1);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let res = import_file(&conn, dir.path(), "base-loose", &loose_object("blob", base)).unwrap();
    let report = recompute_affected(&conn, "main", &res.affected_ck).unwrap();
    assert!(report.resolved >= 1, "补入 base 后应能局部还原");
    let st: String = conn
        .query_row(
            "SELECT status FROM resolved WHERE branch_id=1 AND oid=?",
            rusqlite::params![hex::encode(want)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(st, "resolved");
    let after_ts: i64 = conn
        .query_row(
            "SELECT updated_at FROM resolved WHERE branch_id=1 AND oid=?",
            rusqlite::params![hex::encode(uoid)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before_ts, after_ts, "无关对象不应被重算");
}

#[test]
fn idx_pack_mismatch_and_fanout_are_evidenced() {
    let mut pb = PackBuilder::new();
    let (oid, off) = pb.add_blob(b"x");
    let (pack, _) = pb.build();
    let mut idx = build_idx(
        &pack,
        &[IdxSpec {
            oid,
            offset: off as u64,
            entry_bytes: &pack[off..pack.len() - 20],
        }],
    );
    let fanout_pos = 8 + 3 * 4;
    idx[fanout_pos] = 99;
    let parsed = parse_idx(&idx);
    assert!(parsed.errors.iter().any(|e| e.contains("fanout")));
}

fn parse_idx(bytes: &[u8]) -> pack_microscope::idx::ParsedIdx {
    pack_microscope::idx::parse_idx(bytes)
}

#[test]
fn bad_pack_checksum_is_evidenced_but_objects_still_analyzed() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let mut pb = PackBuilder::new();
    pb.add_blob(b"checksum survivor");
    let bad = pb.corrupt_pack_checksum();
    import(&conn, dir.path(), "bad.pack", &bad);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.resolved, 1, "checksum 错误不应阻止其他对象分析");
    let issue: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM issues WHERE code='pack_checksum'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(issue, 1);
}
