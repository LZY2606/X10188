mod common;

use common::*;
use pack_chain_microscope::git::GitType;

/// Missing external ref-delta base: object stays blocked with a chain; other
/// objects still resolve.
#[test]
fn missing_base_is_blocked_but_neighbours_resolve() {
    let (_dir, store) = temp_store();

    let standalone = b"independent object".to_vec();
    let standalone_oid = oid_of(GitType::Blob, &standalone);

    let ghost = [0x11u8; 20];
    let delta = full_replace_delta(5, b"result body");
    let (pack, offs) = build_pack(&[
        PackItem::Base(GitType::Blob, standalone.clone()),
        PackItem::RefDelta { base_oid: ghost, delta },
    ]);
    // Index names the delta target so it appears as a candidate oid.
    let target_oid = "aa".repeat(20);
    let idx = build_idx(
        &pack,
        &[
            (standalone_oid.clone(), offs[0]),
            (target_oid.clone(), offs[1]),
        ],
    );
    import(&store, "p.pack", &pack);
    import(&store, "p.idx", &idx);

    let summary = analyze(&store, default_budget());
    assert_eq!(summary.status, "failed");
    assert_eq!(summary.resolved, 1);
    assert_eq!(summary.blocked, 1);

    // No partial object rows for the blocked target.
    let count: i64 = {
        let conn = store.db.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM resolved WHERE run_id=?1 AND oid=?2",
            rusqlite::params![summary.run_id, target_oid],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(count, 0);

    let evidence = run_evidence(&store, summary.run_id);
    assert!(evidence.iter().any(|m| m.contains("missing external ref-delta base")));

    // After importing the missing base, a later run resolves everything.
    import(
        &store,
        "base",
        &loose_bytes(GitType::Blob, b"12345"),
    );
    let summary2 = analyze(&store, default_budget());
    assert_eq!(summary2.status, "complete");
}

/// Two ref-deltas pointing at each other form a cycle: both fail with
/// cycle evidence, unrelated objects survive.
#[test]
fn ref_delta_cycle_is_detected_and_isolated() {
    let (_dir, store) = temp_store();
    let oid_a = "aa".repeat(20);
    let oid_b = "bb".repeat(20);

    let delta = full_replace_delta(4, b"wxyz");
    let (pack, offs) = build_pack(&[
        PackItem::RefDelta { base_oid: oid_bytes(&oid_b), delta: delta.clone() },
        PackItem::RefDelta { base_oid: oid_bytes(&oid_a), delta },
    ]);
    let idx = build_idx(
        &pack,
        &[(oid_a.clone(), offs[0]), (oid_b.clone(), offs[1])],
    );
    import(&store, "c.pack", &pack);
    import(&store, "c.idx", &idx);

    let summary = analyze(&store, default_budget());
    assert_eq!(summary.status, "failed");
    assert_eq!(summary.blocked, 2);
    let evidence = run_evidence(&store, summary.run_id);
    assert!(
        evidence.iter().any(|m| m.contains("delta cycle")),
        "expected cycle evidence, got {evidence:?}"
    );
}

/// A bad CRC isolates only the offending object when an index is present.
#[test]
fn bad_crc_isolated_other_objects_remain_usable() {
    let (_dir, store) = temp_store();
    let good = b"good object content".to_vec();
    let good_oid = oid_of(GitType::Blob, &good);
    let bad = b"corrupt object content".to_vec();
    let bad_oid = oid_of(GitType::Blob, &bad);

    let (mut pack, offs) = build_pack(&[
        PackItem::Base(GitType::Blob, good),
        PackItem::Base(GitType::Blob, bad),
    ]);
    let idx = build_idx(
        &pack,
        &[(good_oid.clone(), offs[0]), (bad_oid.clone(), offs[1])],
    );
    // Flip one byte inside the second object's zlib stream.
    let victim = (offs[1] as usize) + 5;
    pack[victim] ^= 0xff;
    import(&store, "x.pack", &pack);
    import(&store, "x.idx", &idx);

    let summary = analyze(&store, default_budget());
    assert_eq!(summary.blocked, 1);
    assert!(oid_resolved_any(&store, &good_oid));
    assert!(!oid_resolved_any(&store, &bad_oid));
    let evidence = run_evidence(&store, summary.run_id);
    assert!(evidence.iter().any(|m| m.contains("CRC32 mismatch") || m.contains("zlib error")));
}

/// Header size disagrees with the inflated payload: spoof detected.
#[test]
fn spoofed_inflated_size_is_flagged() {
    let (_dir, store) = temp_store();
    let content = b"honest content".to_vec();
    let oid_real = oid_of(GitType::Blob, &content);

    // Build pack by hand but lie in the size varint (claims one extra byte).
    let mut body = Vec::new();
    body.extend(pack_chain_microscope::git::encode_pack_header(
        GitType::Blob,
        content.len() as u64 + 1,
    ));
    body.extend(zlib(&content));
    let mut pack = Vec::new();
    pack.extend(b"PACK");
    pack.extend(2u32.to_be_bytes());
    pack.extend(1u32.to_be_bytes());
    pack.extend(body);
    pack.extend(sha1(&pack.clone()));

    import(&store, "s.pack", &pack);
    let summary = analyze(&store, default_budget());
    assert_eq!(summary.blocked, 1);
    let evidence = run_evidence(&store, summary.run_id);
    assert!(evidence.iter().any(|m| m.contains("size spoof")));
    let _ = oid_real;
}

/// An ofs-delta whose distance points before the pack header is rejected.
#[test]
fn ofs_distance_out_of_range_is_blocked() {
    let (_dir, store) = temp_store();
    let mut pack = Vec::new();
    pack.extend(b"PACK");
    pack.extend(2u32.to_be_bytes());
    pack.extend(1u32.to_be_bytes());
    // type=ofs-delta (6), size small
    pack.push((6 << 4) | 1);
    // distance varint = 5 (points at absolute offset ~8: before data start 12)
    pack.push(5);
    let bogus_delta = zlib(&full_replace_delta(1, b"x"));
    pack.extend(bogus_delta);
    pack.extend(sha1(&pack.clone()));

    import(&store, "o.pack", &pack);
    let parsed = parse_summary_contains(&store, "out-of-range");
    assert!(parsed, "pack scan should flag out-of-range ofs delta");
    let summary = analyze(&store, default_budget());
    assert!(summary.status == "failed" || summary.blocked >= 1);
}

fn run_evidence(store: &pack_chain_microscope::Store, run_id: i64) -> Vec<String> {
    let conn = store.db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT message FROM evidence WHERE run_id=?1")
        .unwrap();
    stmt.query_map(rusqlite::params![run_id], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn oid_resolved_any(store: &pack_chain_microscope::Store, oid: &str) -> bool {
    let conn = store.db.lock().unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM resolved WHERE oid=?1 AND run_id=(SELECT MAX(id) FROM runs)",
        rusqlite::params![oid],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

fn parse_summary_contains(store: &pack_chain_microscope::Store, needle: &str) -> bool {
    let conn = store.db.lock().unwrap();
    let errors: String = conn
        .query_row(
            "SELECT parse_errors FROM sources WHERE kind='pack' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    errors.contains(needle)
}
