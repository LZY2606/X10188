mod common;

use common::*;
use pack_chain_microscope::git::GitType;
use pack_chain_microscope::Budget;

/// Chained ofs-delta then ref-delta reconstructing a blob across two packs.
#[test]
fn chained_ofs_then_ref_delta_is_reconstructed_with_oid_check() {
    let (_dir, store) = temp_store();

    let v0 = b"hello world, this is the original blob payload".to_vec();
    let v1 = b"hello world, this is the MODIFIED blob payload!!".to_vec();
    let v2 = b"hello world, this is the MODIFIED blob payload!! and more".to_vec();

    let oid0 = oid_of(GitType::Blob, &v0);
    let oid1 = oid_of(GitType::Blob, &v1);
    let oid2 = oid_of(GitType::Blob, &v2);

    // Pack A: base v0, ofs-delta -> v1.
    let d1 = {
    // copy common prefix "hello world, this is the " (25 bytes), replace tail
    let mut d = pack_chain_microscope::git::delta::encode_delta_sizes(v0.len() as u64, v1.len() as u64);
    d.extend(pack_chain_microscope::git::delta::copy_command(0, 25));
    d.extend(pack_chain_microscope::git::delta::insert_command(b"MODIFIED blob payload!!"));
    d
};
    let (pack_a, offs_a) = build_pack(&[
        PackItem::Base(GitType::Blob, v0.clone()),
        PackItem::OfsDelta { base_index: 0, delta: d1 },
    ]);
    let idx_a = build_idx(&pack_a, &[(oid0.clone(), offs_a[0]), (oid1.clone(), offs_a[1])]);
    import(&store, "a.pack", &pack_a);
    import(&store, "a.idx", &idx_a);

    // Pack B: ref-delta against v1 -> v2.
    let d2 = copy_then_insert(v1.len(), v1.len() as u32, b" and more");
    let (pack_b, offs_b) = build_pack(&[PackItem::RefDelta {
        base_oid: oid_bytes(&oid1),
        delta: d2,
    }]);
    let idx_b = build_idx(&pack_b, &[(oid2.clone(), offs_b[0])]);
    import(&store, "b.pack", &pack_b);
    import(&store, "b.idx", &idx_b);

    let summary = analyze(&store, default_budget());
    assert_eq!(summary.status, "complete", "{}", summary.messages.join(";"));
    assert_eq!(summary.resolved, 3);
    assert!(oid_resolved_ok(&store, &oid2, 2), "v2 depth should be 2");
    assert!(oid_resolved_ok(&store, &oid1, 1));
    assert!(oid_resolved_ok(&store, &oid0, 0));

    // Two delta steps must record base, instruction range and in/out sizes.
    let steps = delta_steps(&store, &oid2);
    assert_eq!(steps.len(), 1);
    assert!(steps[0]["input_len"].as_i64().unwrap() == v1.len() as i64);
    assert!(steps[0]["output_len"].as_i64().unwrap() == v2.len() as i64);
    assert!(steps[0]["cmd_count"].as_i64().unwrap() >= 2);
    assert!(steps[0]["verify"] == "ok");
}

#[test]
fn loose_objects_resolve_and_verify_content_hash() {
    let (_dir, store) = temp_store();
    let content = b"loose blob body".to_vec();
    let oid = oid_of(GitType::Blob, &content);
    import(&store, &format!("{oid}"), &loose_bytes(GitType::Blob, &content));
    let summary = analyze(&store, default_budget());
    assert_eq!(summary.status, "complete");
    assert!(oid_resolved_ok(&store, &oid, 0));
}

fn oid_resolved_ok(
    store: &pack_chain_microscope::Store,
    oid: &str,
    expect_depth: i64,
) -> bool {
    let conn = store.db.lock().unwrap();
    conn.query_row(
        "SELECT oid_ok, depth FROM resolved
         WHERE run_id=(SELECT MAX(id) FROM runs WHERE status='complete') AND oid=?1",
        rusqlite::params![oid],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, i64>(1)?)),
    )
    .map(|(ok, depth)| ok && depth == expect_depth)
    .unwrap_or(false)
}

fn delta_steps(store: &pack_chain_microscope::Store, oid: &str) -> Vec<serde_json::Value> {
    let conn = store.db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT cmd_count, input_len, output_len, verify FROM delta_steps
             WHERE oid=?1 AND run_id=(SELECT MAX(id) FROM runs)",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![oid], |r| {
        Ok(serde_json::json!({
            "cmd_count": r.get::<_, i64>(0)?,
            "input_len": r.get::<_, i64>(1)?,
            "output_len": r.get::<_, i64>(2)?,
            "verify": r.get::<_, String>(3)?,
        }))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}
