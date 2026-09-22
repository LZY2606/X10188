use packchain_microscope::support::*;

fn setup() -> (std::sync::Arc<Db>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("t.sqlite");
    let conn = packchain_microscope::db::open(db_path.to_str().unwrap()).unwrap();
    let db = std::sync::Arc::new(Db(std::sync::Mutex::new(conn)));
    (db, dir)
}

fn import(db: &Db, dir: &std::path::Path, name: &str, data: &[u8]) -> ImportReport {
    packchain_microscope::engine::import::import_bytes(
        db,
        dir.to_str().unwrap(),
        name,
        data,
    )
}

fn status(db: &Db, id: i64) -> (String, Option<String>) {
    let c = db.0.lock().unwrap();
    c.query_row("SELECT status,error_code FROM nodes WHERE id=?1", [id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    })
    .unwrap()
}

fn oid(db: &Db, id: i64) -> String {
    db.0.lock().unwrap().query_row(
        "SELECT oid FROM nodes WHERE id=?1", [id], |r| r.get(0)).unwrap()
}

fn resolved_data(db: &Db, id: i64) -> Vec<u8> {
    db.0.lock().unwrap().query_row(
        "SELECT data FROM objects WHERE node_id=?1 AND stage='resolved'", [id],
        |r| r.get(0)).unwrap()
}

fn count_status(db: &Db, s: &str) -> i64 {
    db.0.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM nodes WHERE status=?1", [s], |r| r.get(0)).unwrap()
}

#[test]
fn chained_ofs_and_ref_deltas_resolve_and_oid_checks() {
    let base = b"hello base object";
    let suffix1 = b" + delta one";
    let suffix2 = b" + delta two";

    let d1 = append_delta(base.len() as u64, suffix1);
    let mid = {
        let mut m = base.to_vec();
        m.extend_from_slice(suffix1);
        m
    };
    let d2 = append_delta(mid.len() as u64, suffix2);
    let final_content = {
        let mut f = mid.clone();
        f.extend_from_slice(suffix2);
        f
    };

    let (pack, built) = build_pack(&[
        base_spec(base),
        PackEntrySpec::OfsDelta { base_index: 0, delta: &d1 },
        PackEntrySpec::OfsDelta { base_index: 1, delta: &d2 },
    ]);
    let oids: Vec<[u8; 20]> = vec![
        parse_oid_bytes(&git_oid(ObjType::Blob, base)),
        parse_oid_bytes(&git_oid(ObjType::Blob, &mid)),
        parse_oid_bytes(&git_oid(ObjType::Blob, &final_content)),
    ];
    let idx = build_idx_for(&pack, &built, &oids);

    let (db, dir) = setup();
    import(&db, dir.path(), "a.pack", &pack);
    import(&db, dir.path(), "a.idx", &idx);

    for i in 1..=3i64 {
        assert_eq!(status(&db, i).0, "resolved", "node {} resolved", i);
    }
    assert_eq!(resolved_data(&db, 3), final_content);
    assert_eq!(oid(&db, 3), git_oid(ObjType::Blob, &final_content));

    let steps: i64 = db.0.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM steps WHERE node_id=3", [], |r| r.get(0)).unwrap();
    assert!(steps >= 2, "copy+insert steps recorded");
    let depth: i64 = db.0.lock().unwrap().query_row(
        "SELECT resolve_depth FROM nodes WHERE id=3", [], |r| r.get(0)).unwrap();
    assert_eq!(depth, 2);

    // ref-delta chained against an imported loose base
    let d3 = append_delta(final_content.len() as u64, b" ref!");
    let mut ref_content = final_content.clone();
    ref_content.extend_from_slice(b" ref!");
    let base_oid = parse_oid_bytes(&git_oid(ObjType::Blob, &final_content));
    let (pack2, built2) = build_pack(&[PackEntrySpec::RefDelta {
        base_oid,
        delta: &d3,
    }]);
    let oid2 = parse_oid_bytes(&git_oid(ObjType::Blob, &ref_content));
    let idx2 = build_idx_for(&pack2, &built2, &[oid2]);
    import(&db, dir.path(), "b.pack", &pack2);
    import(&db, dir.path(), "b.idx", &idx2);
    assert_eq!(status(&db, 4).0, "resolved");
    assert_eq!(resolved_data(&db, 4), ref_content);
}

#[test]
fn missing_base_blocks_and_unblocks_after_import() {
    let base = b"future base".to_vec();
    let suffix = b" derived";
    let delta = append_delta(base.len() as u64, suffix);
    let base_oid_arr = parse_oid_bytes(&git_oid(ObjType::Blob, &base));

    let (pack, built) = build_pack(&[PackEntrySpec::RefDelta {
        base_oid: base_oid_arr,
        delta: &delta,
    }]);
    let mut final_data = base.clone();
    final_data.extend_from_slice(suffix);
    let final_oid = parse_oid_bytes(&git_oid(ObjType::Blob, &final_data));
    let idx = build_idx_for(&pack, &built, &[final_oid]);

    let (db, dir) = setup();
    import(&db, dir.path(), "d.pack", &pack);
    import(&db, dir.path(), "d.idx", &idx);

    assert_eq!(status(&db, 1).0, "blocked");
    assert_eq!(status(&db, 1).1.as_deref(), Some("missing_base"));
    let snap = packchain_microscope::engine::inspect::snapshot(&db);
    let n = snap.nodes.iter().find(|n| n.id == 1).unwrap();
    assert!(n
        .blocking_chain
        .iter()
        .any(|l| l.missing_oid.is_some()));

    // import the missing base later (loose object) -> only affected subtree recomputes
    let loose = loose_object(ObjType::Blob, &base);
    import(&db, dir.path(), "base", &loose);
    assert_eq!(status(&db, 1).0, "resolved");
    assert_eq!(resolved_data(&db, 1), final_data);
}

#[test]
fn delta_cycle_is_error_not_hang() {
    // Two ref-deltas pointing at each other's *expected* oids.
    let a_data = b"alpha".to_vec();
    let b_data = b"beta-beta".to_vec();
    let a_oid = parse_oid_bytes(&git_oid(ObjType::Blob, &a_data));
    let b_oid = parse_oid_bytes(&git_oid(ObjType::Blob, &b_data));
    // delta content validity is irrelevant; cycle must be detected first
    let da = append_delta(b_data.len() as u64, b"x");
    let db_ = append_delta(a_data.len() as u64, b"yy");
    let (pack, _built) = build_pack(&[
        PackEntrySpec::RefDelta { base_oid: b_oid, delta: &da },
        PackEntrySpec::RefDelta { base_oid: a_oid, delta: &db_ },
    ]);
    let (db, dir) = setup();
    import(&db, dir.path(), "cyc.pack", &pack);
    // no candidates at all -> blocked (missing). To form a real cycle, supply
    // candidates with those oids via a second pack whose deltas cross-reference
    // entries already present: build a 2-entry pack using idx declared oids
    // making each node claim the other's oid.
    let (pack2, built2) = build_pack(&[
        PackEntrySpec::RefDelta { base_oid: b_oid, delta: &da },
        PackEntrySpec::RefDelta { base_oid: a_oid, delta: &db_ },
    ]);
    let idx2 = build_idx_for(&pack2, &built2, &[a_oid, b_oid]);
    import(&db, dir.path(), "cyc2.pack", &pack2);
    import(&db, dir.path(), "cyc2.idx", &idx2);
    assert!(count_status(&db, "error") >= 2);
    assert!(db.0.lock().unwrap()
        .query_row::<i64,_,_>("SELECT COUNT(*) FROM evidence WHERE code='delta_cycle'", [], |r| r.get(0))
        .unwrap() >= 1);
}

#[test]
fn bad_crc_isolates_object_others_continue() {
    let a = b"object a";
    let b = b"object b content";
    let (pack, built) = build_pack(&[base_spec(a), base_spec(b)]);
    let oid_a = parse_oid_bytes(&git_oid(ObjType::Blob, a));
    let oid_b = parse_oid_bytes(&git_oid(ObjType::Blob, b));
    let mut idx = build_idx_for(&pack, &built, &[oid_a, oid_b]);
    // corrupt one CRC32 table entry (position: 8+1024 + 2*20 .. first crc)
    let crc_pos = 8 + 1024 + 2 * 20;
    idx[crc_pos] ^= 0xff;
    let (db, dir) = setup();
    import(&db, dir.path(), "c.pack", &pack);
    import(&db, dir.path(), "c.idx", &idx);
    assert_eq!(status(&db, 1).1.as_deref(), Some("bad_crc"));
    assert_eq!(status(&db, 2).0, "resolved");
}

#[test]
fn spoofed_size_detected_mid_inflate() {
    let real = vec![b'Z'; 5000];
    let (pack, _built) = build_pack(&[PackEntrySpec::Base {
        kind: ObjType::Blob,
        data: &real,
        force_spoof_size: Some(10),
    }]);
    let (db, dir) = setup();
    import(&db, dir.path(), "s.pack", &pack);
    assert_eq!(status(&db, 1).0, "error");
    assert_eq!(status(&db, 1).1.as_deref(), Some("size_spoof"));
}

#[test]
fn duplicate_oid_candidates_order_independent_and_pin_branch() {
    let a = b"duplicate blob payload";
    let oid_arr = parse_oid_bytes(&git_oid(ObjType::Blob, a));
    let (p1, b1) = build_pack(&[base_spec(a)]);
    let (p2, b2) = build_pack(&[base_spec(a)]);
    let i1 = build_idx_for(&p1, &b1, &[oid_arr]);
    let i2 = build_idx_for(&p2, &b2, &[oid_arr]);

    let (db, dir) = setup();
    import(&db, dir.path(), "z-first.pack", &p1);
    import(&db, dir.path(), "z-first.idx", &i1);
    import(&db, dir.path(), "a-second.pack", &p2);
    import(&db, dir.path(), "a-second.idx", &i2);

    let snap = packchain_microscope::engine::inspect::snapshot(&db);
    let any = snap.nodes.iter().find(|n| n.oid.len() == 40).unwrap();
    assert_eq!(any.candidates.len(), 2);
    // sorting independent of import order: a-second.pack first
    assert_eq!(any.candidates[0].source_filename, "a-second.pack");

    // pin the second candidate (z-first) then check flag
    let target = any.candidates[1].node_id;
    packchain_microscope::engine::inspect::pin_candidate(&db, target);
    packchain_microscope::engine::resolve::incremental(&db);
    let snap2 = packchain_microscope::engine::inspect::snapshot(&db);
    let n2 = snap2.nodes.iter().find(|n| n.id == target).unwrap();
    assert!(n2.candidates.iter().any(|c| c.pinned && c.node_id == target));
}

#[test]
fn budget_pause_is_retryable_no_partial_output() {
    let base = vec![b'q'; 1000];
    let suffix = vec![b'r'; 1000];
    let delta = append_delta(base.len() as u64, &suffix);
    let (pack, built) = build_pack(&[
        base_spec(&base),
        PackEntrySpec::OfsDelta { base_index: 0, delta: &delta },
    ]);
    let mut out = base.clone();
    out.extend_from_slice(&suffix);
    let oids = [
        parse_oid_bytes(&git_oid(ObjType::Blob, &base)),
        parse_oid_bytes(&git_oid(ObjType::Blob, &out)),
    ];
    let idx = build_idx_for(&pack, &built, &oids);

    let (db, dir) = setup();
    use packchain_microscope::engine::resolve::set_budgets;
    set_budgets(&db, Some(64), Some(1500), Some(100));
    import(&db, dir.path(), "b.pack", &pack);
    import(&db, dir.path(), "b.idx", &idx);

    assert!(count_status(&db, "paused") >= 1, "paused by total budget");
    let partial: i64 = db.0.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM objects WHERE stage='resolved' AND
         node_id IN (SELECT id FROM nodes WHERE status='paused')",
        [], |r| r.get(0)).unwrap();
    assert_eq!(partial, 0, "no half materialized object stored");

    // raise budget and retry
    set_budgets(&db, Some(64), Some(100_000), Some(100));
    let rep = packchain_microscope::engine::resolve::resume(&db);
    assert_eq!(rep.paused, 0);
    assert_eq!(status(&db, 2).0, "resolved");

    // single-object ratio cap pauses on oversize result
    let big = vec![b's'; 5000];
    let (p2, b2) = build_pack(&[base_spec(&big)]);
    let i2 = build_idx_for(&p2, &b2, &[parse_oid_bytes(&git_oid(ObjType::Blob, &big))]);
    set_budgets(&db, Some(64), Some(100_000), Some(1)); // single cap = 1000 bytes
    import(&db, dir.path(), "big.pack", &p2);
    import(&db, dir.path(), "big.idx", &i2);
    let (st, code) = status(&db, 3);
    assert_eq!(st, "paused");
    assert_eq!(code.as_deref(), Some("single_budget"));
    set_budgets(&db, Some(64), Some(100_000), Some(100));
    packchain_microscope::engine::resolve::resume(&db);
    assert_eq!(status(&db, 3).0, "resolved");
}

#[test]
fn depth_limit_pauses_and_resumes() {
    let base = b"depth0".to_vec();
    let mut contents: Vec<Vec<u8>> = vec![base.clone()];
    let mut deltas: Vec<Vec<u8>> = Vec::new();
    for i in 0..5u32 {
        let suffix = format!("-{}", i).into_bytes();
        deltas.push(append_delta(contents[i as usize].len() as u64, &suffix));
        let mut c = contents[i as usize].clone();
        c.extend_from_slice(&suffix);
        contents.push(c);
    }
    let specs: Vec<PackEntrySpec> = vec![
        base_spec(&base),
        PackEntrySpec::OfsDelta { base_index: 0, delta: &deltas[0] },
        PackEntrySpec::OfsDelta { base_index: 1, delta: &deltas[1] },
        PackEntrySpec::OfsDelta { base_index: 2, delta: &deltas[2] },
        PackEntrySpec::OfsDelta { base_index: 3, delta: &deltas[3] },
        PackEntrySpec::OfsDelta { base_index: 4, delta: &deltas[4] },
    ];
    let (pack, built) = build_pack(&specs);
    let oids: Vec<[u8; 20]> = contents
        .iter()
        .map(|c| parse_oid_bytes(&git_oid(ObjType::Blob, c)))
        .collect();
    let idx = build_idx_for(&pack, &built, &oids);

    let (db, dir) = setup();
    packchain_microscope::engine::resolve::set_budgets(&db, Some(2), Some(1 << 30), Some(100));
    import(&db, dir.path(), "deep.pack", &pack);
    import(&db, dir.path(), "deep.idx", &idx);
    assert!(count_status(&db, "paused") >= 1);
    packchain_microscope::engine::resolve::set_budgets(&db, Some(64), Some(1 << 30), Some(100));
    packchain_microscope::engine::resolve::resume(&db);
    assert_eq!(count_status(&db, "paused"), 0);
    assert_eq!(status(&db, 6).0, "resolved");
}

#[test]
fn delete_source_reports_dependents_then_force() {
    let base = b"base for delete".to_vec();
    let suffix = b" derived";
    let delta = append_delta(base.len() as u64, suffix);
    let (pack, built) = build_pack(&[
        base_spec(&base),
        PackEntrySpec::OfsDelta { base_index: 0, delta: &delta },
    ]);
    let mut out = base.clone();
    out.extend_from_slice(suffix);
    let oids = [
        parse_oid_bytes(&git_oid(ObjType::Blob, &base)),
        parse_oid_bytes(&git_oid(ObjType::Blob, &out)),
    ];
    let idx = build_idx_for(&pack, &built, &oids);

    let (db, dir) = setup();
    let r = import(&db, dir.path(), "x.pack", &pack);
    import(&db, dir.path(), "x.idx", &idx);
    let check = packchain_microscope::engine::inspect::delete_source_check(&db, r.source_id);
    assert!(!check.can_delete);
    assert!(check.dependent_objects.len() >= 2);

    let deleted = packchain_microscope::engine::inspect::delete_source(&db, r.source_id, true);
    assert_eq!(deleted.removed_nodes, 2);
    let remaining: i64 = db.0.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM nodes", [], |r| r.get(0)).unwrap();
    assert_eq!(remaining, 0);
}
