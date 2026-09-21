mod common;

use common::{build_idx, loose_object, zlib, IdxSpec, PackBuilder};
use pack_microscope::engine::{recompute_affected, run_branch};
use pack_microscope::git::git_object_id;
use pack_microscope::pack::parse_pack;
use pack_microscope::store::import_file;

fn import(conn: &rusqlite::Connection, dir: &std::path::Path, name: &str, bytes: &[u8]) -> i64 {
    import_file(conn, dir, name, bytes).unwrap().source_id
}

fn status_of(conn: &rusqlite::Connection, branch: i64, oid_sub: &str) -> Option<(String, String)> {
    conn.prepare(
        "SELECT ckey, status FROM resolved WHERE branch_id=?1 AND (oid LIKE ?2 OR ckey LIKE ?2) ORDER BY ckey LIMIT 1",
    )
    .unwrap()
    .query_row(rusqlite::params![branch, format!("%{}%", oid_sub)], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })
    .ok()
}

#[test]
fn parses_pack_header_entries_and_offsets() {
    let mut pb = PackBuilder::new();
    let (_oid, off) = pb.add_blob(b"hello microscope");
    let (pack, offsets) = pb.build();
    let parsed = parse_pack(&pack, Some(64 * 1024 * 1024));
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.count, 1);
    assert_eq!(offsets, vec![off]);
    assert_eq!(parsed.entries[0].offset, off as u64);
    assert_eq!(parsed.checksum_ok, Some(true));
    assert_eq!(
        parsed.entries[0].data.as_deref(),
        Some(b"hello microscope".as_slice())
    );
    assert!(parsed.entries[0].next_offset.is_some());
    assert_eq!(parsed.entries[0].compressed_len > 0, true);
}

#[test]
fn chained_ofs_deltas_reconstruct_and_rehash() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let base = b"base content line one";
    let target1 = b"base content line two!!";
    let target2 = b"base content line three!!!";
    let mut pb = PackBuilder::new();
    let (base_oid, base_off) = pb.add_blob(base);
    let d1_off = pb.add_ofs_delta(base_off, base, target1);
    let d2_off = pb.add_ofs_delta(d1_off, target1, target2);
    let (pack, _offsets) = pb.build();
    let want1 = git_object_id("blob", target1);
    let want2 = git_object_id("blob", target2);
    let idx = build_idx(
        &pack,
        &[
            IdxSpec {
                oid: base_oid,
                offset: base_off as u64,
                entry_bytes: &pack[base_off..d1_off],
            },
            IdxSpec {
                oid: want1,
                offset: d1_off as u64,
                entry_bytes: &pack[d1_off..d2_off],
            },
            IdxSpec {
                oid: want2,
                offset: d2_off as u64,
                entry_bytes: &pack[d2_off..pack.len() - 20],
            },
        ],
    );
    import(&conn, dir.path(), "a.pack", &pack);
    import(&conn, dir.path(), "a.idx", &idx);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.resolved, 3);
    assert_eq!(report.blocked + report.errors + report.suspended, 0);
    let (ckey, st) = status_of(&conn, 1, &hex::encode(want2)).unwrap();
    assert_eq!(st, "resolved");
    let (typ, content): (String, Vec<u8>) = conn
        .query_row(
            "SELECT obj_type, content FROM resolved WHERE branch_id=1 AND ckey=?",
            rusqlite::params![ckey],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(typ, "blob");
    assert_eq!(content, target2);
    let chain_cks: Vec<String> = serde_json::from_str::<Vec<serde_json::Value>>(
        &conn.query_row(
            "SELECT chain_json FROM resolved WHERE branch_id=1 AND ckey=?",
            rusqlite::params![ckey],
            |r| r.get::<_, String>(0),
        )
        .unwrap(),
    )
    .unwrap()
    .into_iter()
    .map(|v| v["ckey"].as_str().unwrap().to_string())
    .collect();
    let chain_in = chain_cks
        .iter()
        .map(|c| format!("'{}'", c))
        .collect::<Vec<_>>()
        .join(",");
    let step_count: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM steps WHERE branch_id=1 AND ckey IN ({})",
                chain_in
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(step_count, 2);
    let depths: Vec<i64> = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT output_len, copies, inserts, check_ok FROM steps WHERE branch_id=1 AND ckey IN ({}) ORDER BY ckey",
                chain_in
            ))
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap();
        let mut outs = Vec::new();
        for r in rows {
            let (olen, copies, inserts, check) = r.unwrap();
            assert!(copies + inserts >= 1);
            assert_eq!(check, 1);
            outs.push(olen);
        }
        outs
    };
    assert_eq!(depths, vec![target1.len() as i64, target2.len() as i64]);
}

#[test]
fn chained_ref_deltas_across_sources() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let base = b"external base data";
    let t1 = b"external base data v2";
    let t2 = b"external base data v3";
    let base_oid = git_object_id("blob", base);
    import(&conn, dir.path(), "loose-base", &loose_object("blob", base));

    let mut pb = PackBuilder::new();
    let d1_off = pb.add_ref_delta(&base_oid, base, t1);
    let (pack1, _) = pb.build();
    let want1 = git_object_id("blob", t1);
    let idx1 = build_idx(
        &pack1,
        &[IdxSpec {
            oid: want1,
            offset: d1_off as u64,
            entry_bytes: &pack1[d1_off..pack1.len() - 20],
        }],
    );
    import(&conn, dir.path(), "d1.pack", &pack1);
    import(&conn, dir.path(), "d1.idx", &idx1);

    let mut pb2 = PackBuilder::new();
    let d2_off = pb2.add_ref_delta(&want1, t1, t2);
    let (pack2, _) = pb2.build();
    let want2 = git_object_id("blob", t2);
    let idx2 = build_idx(
        &pack2,
        &[IdxSpec {
            oid: want2,
            offset: d2_off as u64,
            entry_bytes: &pack2[d2_off..pack2.len() - 20],
        }],
    );
    import(&conn, dir.path(), "d2.pack", &pack2);
    import(&conn, dir.path(), "d2.idx", &idx2);

    let report = recompute_affected(
        &conn,
        "main",
        &["loose:".to_string()],
    );
    let _ = report;
    let r = run_branch(&conn, "main", None).unwrap();
    assert!(r.resolved >= 3);
    let (_, st) = status_of(&conn, 1, &hex::encode(want2)).unwrap();
    assert_eq!(st, "resolved");
}

#[test]
fn missing_external_base_is_blocked_with_chain() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let ghost = [7u8; 20];
    let target = b"target requiring ghost";
    let mut pb = PackBuilder::new();
    let off = pb.add_ref_delta(&ghost, &[0u8; 0], target);
    let (pack, _) = pb.build();
    let want = git_object_id("blob", target);
    let idx = build_idx(
        &pack,
        &[IdxSpec {
            oid: want,
            offset: off as u64,
            entry_bytes: &pack[off..pack.len() - 20],
        }],
    );
    import(&conn, dir.path(), "thin.pack", &pack);
    import(&conn, dir.path(), "thin.idx", &idx);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.blocked, 1);
    let evidence: String = conn
        .query_row(
            "SELECT evidence FROM resolved WHERE branch_id=1 AND status='blocked'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(evidence.contains(&hex::encode(ghost)));
}

#[test]
fn ofs_distance_out_of_range_is_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let target = b"orphan ofs";
    let base = b"";
    let delta = pack_microscope::delta::make_delta(base, target);
    let mut entry = common::encode_entry_header(6, delta.len());
    entry.extend_from_slice(&common::encode_ofs_distance(5000));
    entry.extend_from_slice(&zlib(&delta));
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&1u32.to_be_bytes());
    pack.extend_from_slice(&entry);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&pack);
    pack.extend_from_slice(&h.finalize());
    import(&conn, dir.path(), "o.pack", &pack);
    let report = run_branch(&conn, "main", None).unwrap();
    assert!(report.errors >= 1);
    let reason: String = conn
        .query_row(
            "SELECT reason FROM resolved WHERE branch_id=1 AND status='error'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(reason.contains("越界"));
}

#[test]
fn delta_cycle_is_detected_and_others_continue() {
    let dir = tempfile::tempdir().unwrap();
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).unwrap();
    let a_oid = git_object_id("blob", b"placeholder-a");
    let b_oid = git_object_id("blob", b"placeholder-b");
    let good = b"independent good blob";
    let mut pb = PackBuilder::new();
    let (good_oid2, good_off) = pb.add_blob(good);
    let _ = good_oid2;
    let da = {
        let d = pack_microscope::delta::make_delta(b"placeholder-b", b"a-after-b");
        pb.add_ref_delta_raw(&b_oid, &d)
    };
    let db = {
        let d = pack_microscope::delta::make_delta(b"placeholder-a", b"b-after-a");
        pb.add_ref_delta_raw(&a_oid, &d)
    };
    let (pack, _) = pb.build();
    let good_oid = git_object_id("blob", good);
    let idx = build_idx(
        &pack,
        &[
            IdxSpec {
                oid: good_oid,
                offset: good_off as u64,
                entry_bytes: &pack[good_off..da],
            },
            IdxSpec {
                oid: a_oid,
                offset: da as u64,
                entry_bytes: &pack[da..db],
            },
            IdxSpec {
                oid: b_oid,
                offset: db as u64,
                entry_bytes: &pack[db..pack.len() - 20],
            },
        ],
    );
    import(&conn, dir.path(), "cyc.pack", &pack);
    import(&conn, dir.path(), "cyc.idx", &idx);
    let report = run_branch(&conn, "main", None).unwrap();
    assert_eq!(report.resolved, 1);
    assert!(report.blocked + report.errors >= 2);
    let bad: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resolved WHERE branch_id=1 AND (reason LIKE '%环%' OR evidence LIKE '%cycle%')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(bad >= 1, "必须记录环证据");
}
