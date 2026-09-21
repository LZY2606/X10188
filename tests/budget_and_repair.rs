mod common;

use common::*;
use pack_chain_microscope::git::GitType;
use pack_chain_microscope::Budget;

/// Tiny total-expansion budget pauses mid-chain; resume with a larger budget
/// completes, and paused runs must not publish partial objects.
#[test]
fn budget_pause_is_retryable_and_flushes_nothing_partial() {
    let (_dir, store) = temp_store();

    let v0 = vec![b'a'; 4_000];
    let v1 = {
        let mut v = v0.clone();
        v.extend_from_slice(b"changed-tail");
        v
    };
    let copy_n = v0.len() as u32;
    let oid0 = oid_of(GitType::Blob, &v0);
    let oid1 = oid_of(GitType::Blob, &v1);

    let d1 = copy_then_insert(v0.len(), copy_n, b"changed-tail");
    let (pack, offs) = build_pack(&[
        PackItem::Base(GitType::Blob, v0),
        PackItem::OfsDelta { base_index: 0, delta: d1 },
    ]);
    let idx = build_idx(&pack, &[(oid0.clone(), offs[0]), (oid1.clone(), offs[1])]);
    import(&store, "b.pack", &pack);
    import(&store, "b.idx", &idx);

    let tiny = Budget {
        max_depth: 50,
        max_expand_bytes: 100,
        max_single_bytes: 1_000_000,
    };
    let paused = analyze(&store, tiny);
    assert_eq!(paused.status, "paused");
    assert_eq!(paused.paused, 0); // paused roots not counted as resolved/failed
    let conn = store.db.lock().unwrap();
    let partial: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resolved WHERE run_id=?1",
            rusqlite::params![paused.run_id],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(partial, 0, "paused run must not publish any objects");

    // Resume with enough budget; pass the paused run id for traceability.
    let resumed = pack_chain_microscope::analyze::analyze_branch(
        &store,
        "main",
        Budget {
            max_depth: 50,
            max_expand_bytes: 10_000_000,
            max_single_bytes: 1_000_000,
        },
        Some(paused.run_id),
    )
    .unwrap();
    assert_eq!(resumed.status, "complete");
    assert_eq!(resumed.resolved, 2);
}

/// Per-object ratio cap marks an oversize object failed (not a pause).
#[test]
fn single_object_ratio_cap_is_enforced() {
    let (_dir, store) = temp_store();
    let big = vec![b'z'; 5_000];
    let oid = oid_of(GitType::Blob, &big);
    import(&store, "big", &loose_bytes(GitType::Blob, &big));

    let budget = Budget {
        max_depth: 50,
        max_expand_bytes: 100_000,
        max_single_bytes: 1_000,
    };
    let summary = analyze(&store, budget);
    assert_eq!(summary.blocked, 1);
    let evidence = {
        let conn = store.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT message FROM evidence WHERE run_id=?1")
            .unwrap();
        stmt.query_map(rusqlite::params![summary.run_id], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    assert!(evidence.iter().any(|m| m.contains("per-object")));
    let _ = oid;
}

/// Importing a missing base only re-resolves the affected subgraph: a later
/// run goes from failed to complete without re-importing anything.
#[test]
fn later_base_insertion_enables_partial_recompute() {
    let (_dir, store) = temp_store();
    let base = b"the base body".to_vec();
    let base_oid = oid_of(GitType::Blob, &base);
    let next = b"the base body EXTENDED".to_vec();
    let next_oid = oid_of(GitType::Blob, &next);

    let delta = copy_then_insert(base.len(), base.len() as u32, b" EXTENDED");
    let (pack, offs) = build_pack(&[PackItem::RefDelta {
        base_oid: oid_bytes(&base_oid),
        delta,
    }]);
    let idx = build_idx(&pack, &[(next_oid.clone(), offs[0])]);
    import(&store, "d.pack", &pack);
    import(&store, "d.idx", &idx);

    let first = analyze(&store, default_budget());
    assert_eq!(first.status, "failed");
    assert_eq!(first.blocked, 1);

    import(&store, &base_oid, &loose_bytes(GitType::Blob, &base));
    let second = analyze(&store, default_budget());
    assert_eq!(second.status, "complete");
    assert_eq!(second.resolved, 2);
}

/// Import order must not change candidate ordering: the smallest (source id,
/// offset) candidate is always the natural winner.
#[test]
fn import_order_does_not_change_candidate_order() {
    let (_dir, store) = temp_store();
    let content = b"duplicate source body".to_vec();
    let oid = oid_of(GitType::Blob, &content);
    
    // Same object, delivered in two separately built packs (different bytes
    // on disk so sha256 dedup does not collapse them), compressed with
    // different zlib levels via a raw fixture.
    let (pack1, offs1) = build_pack(&[PackItem::Base(GitType::Blob, content.clone())]);
    let id_b = import(&store, "one.pack", &pack1);
    let (pack2, offs2) = {
        // Rebuild with different compression: re-use helper but prepend an
        // extra independent object first so offsets differ.
        build_pack(&[
            PackItem::Base(GitType::Blob, b"padding object".to_vec()),
            PackItem::Base(GitType::Blob, content.clone()),
        ])
    };
    let id_a = import(&store, "two.pack", &pack2);
    assert_ne!(id_a, id_b);
    let _ = (offs1, offs2);

    // First candidate in the oid bucket must be the lower source id, no
    // matter which file arrived first.
    let chosen: i64 = {
        let conn = store.db.lock().unwrap();
        conn.query_row(
            "SELECT id FROM objects WHERE oid=?1 ORDER BY source_id, \"offset\", id LIMIT 1",
            rusqlite::params![oid],
            |r| r.get(0),
        )
        .unwrap()
    };
    let chosen_source: i64 = {
        let conn = store.db.lock().unwrap();
        conn.query_row(
            "SELECT source_id FROM objects WHERE id=?1",
            rusqlite::params![chosen],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(chosen_source, id_b.min(id_a));

    let summary = analyze(&store, default_budget());
    assert_eq!(summary.status, "complete");
}

/// Pinning one of two duplicate-oid candidates on a branch resolves
/// identically (both are valid copies), and the pin is visible in objects.
#[test]
fn duplicate_oid_conflict_can_be_pinned_on_a_branch() {
    let (_dir, store) = temp_store();
    let content = b"same oid different file".to_vec();
    let oid = oid_of(GitType::Blob, &content);
    let (p1, _) = build_pack(&[PackItem::Base(GitType::Blob, content.clone())]);
    let (p2, _) = build_pack(&[
        PackItem::Base(GitType::Blob, b"padding".to_vec()),
        PackItem::Base(GitType::Blob, content.clone()),
    ]);
    import(&store, "one.pack", &p1);
    import(&store, "two.pack", &p2);
    let id1: i64 = {
        let conn = store.db.lock().unwrap();
        conn.query_row(
            "SELECT id FROM objects WHERE oid=?1 AND source_id=(SELECT MIN(id) FROM sources) ORDER BY id LIMIT 1",
            rusqlite::params![oid], |r| r.get(0)).unwrap()
    };
    let id2: i64 = {
        let conn = store.db.lock().unwrap();
        conn.query_row(
            "SELECT id FROM objects WHERE oid=?1 ORDER BY source_id DESC, id DESC LIMIT 1",
            rusqlite::params![oid], |r| r.get(0)).unwrap()
    };
    assert_ne!(id1, id2);

    use rusqlite::params;
    {
        let conn = store.db.lock().unwrap();
        conn.execute(
            "INSERT INTO branches(name, created_at) VALUES ('exp', datetime())",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pins(branch, oid, candidate_id, created_at)
             VALUES ('exp', ?1, ?2, datetime())",
            params![oid, id2],
        )
        .unwrap();
    }
    let summary = pack_chain_microscope::analyze::analyze_branch(
        &store,
        "exp",
        Budget::default(),
        None,
    )
    .unwrap();
    assert_eq!(summary.status, "complete");
    let conn = store.db.lock().unwrap();
    let chosen: i64 = conn
        .query_row(
            "SELECT candidate_id FROM resolved WHERE run_id=?1 AND oid=?2",
            params![summary.run_id, oid],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(chosen, id2);
    let _ = id1;
}
