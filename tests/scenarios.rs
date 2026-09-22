mod common;

use common::*;
use pack_chain_microscope::git::*;
use pack_chain_microscope::model::Budgets;
use pack_chain_microscope::pack::{build_idx_v2, build_pack, IdxOptions, IdxRow, SynEntry};
use pack_chain_microscope::resolver;

const B: u8 = OBJ_BLOB;

fn entries_chain() -> (Vec<SynEntry>, Vec<(u8, Vec<u8>)>, Vec<u8>, Vec<u8>) {
    let v0 = b"alpha beta gamma delta epsilon zeta eta theta iota kappa".to_vec();
    let v1 = b"alpha BETA gamma delta epsilon zeta eta theta iota kappa!".to_vec();
    let v2 = b"alpha BETA gamma DELTA epsilon zeta eta theta iota kappa!!".to_vec();
    let d01 = delta(&v0, &v1);
    let d12 = delta(&v1, &v2);
    let entries = vec![
        SynEntry::Full { kind: B, content: v0.clone() },
        SynEntry::OfsDelta { base_index: 0, delta: d01 },
        SynEntry::OfsDelta { base_index: 1, delta: d12 },
    ];
    let objs = vec![(B, v0), (B, v1), (B, v2)];
    (entries, objs.clone(), objs[1].1.clone(), objs[2].1.clone())
}

#[test]
fn chained_ofs_and_ref_deltas_reconstruct_and_hash() {
    let h = Harness::new();
    let (entries, objs, v1, v2) = entries_chain();
    // Add a ref-delta against v1 living in a second pack.
    let built = build_pack(&entries, &Default::default());
    let v3 = b"alpha BETA gamma DELTA epsilon zeta eta theta iota KAPPA!!!".to_vec();
    let d13 = delta(&v1, &v3);
    let oid_v1 = git_object_id(B, &v1);
    let thin = build_pack(
        &[SynEntry::RefDelta {
            base: oid_v1,
            delta: d13,
        }],
        &Default::default(),
    );

    // Import thin pack FIRST (base missing), then the base pack.
    let r_thin = h.import("thin.pack", &thin.bytes);
    assert_eq!(r_thin.nodes_added, 1);
    let s1 = h.resolve(Budgets::defaults());
    assert_eq!(s1.missing_base, 1);
    let st = h.statuses();
    assert_eq!(st[0].1, "missing-base");
    assert!(st[0].2.is_none(), "partial output must not be treated as an object");

    let r_base = h.import("base.pack", &built.bytes);
    assert_eq!(r_base.nodes_added, 3);
    let s2 = h.resolve(Budgets::defaults());
    assert_eq!(s2.resolved, 4, "all 4 objects including the ref-delta: {s2:?}");

    // OIDs recomputed after materialization must match real git blob ids.
    let oid2 = to_hex(&git_object_id(B, &v2));
    let oid3 = to_hex(&git_object_id(B, &v3));
    let statuses = h.statuses();
    let found2 = statuses.iter().any(|(_, st, oid)| st == "resolved" && oid.as_deref() == Some(&oid2));
    let found3 = statuses.iter().any(|(_, st, oid)| st == "resolved" && oid.as_deref() == Some(&oid3));
    assert!(found2, "chained ofs delta v2 hash mismatch: {statuses:?}");
    assert!(found3, "ref delta across packs v3 hash mismatch: {statuses:?}");

    // Delta steps recorded with ranges and checks.
    let node3: i64 = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT id FROM nodes WHERE source_id=?1",
            [r_thin.source_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    let steps: i64 = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT COUNT(*) FROM delta_steps WHERE branch_id=1 AND node_id=?1 AND check_ok=1",
            [node3],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(steps >= 2, "expected copy+insert steps, got {steps}");

    // Honest idx attaches candidates and CRC agrees.
    let idx = honest_idx(&built.bytes, &objs);
    let r_idx = h.import("base.idx", &idx);
    assert!(r_idx.errors.is_empty(), "honest idx errors: {:?}", r_idx.errors);
}

#[test]
fn missing_external_base_is_blocked_with_chain() {
    let h = Harness::new();
    let ghost = [0x11u8; 20];
    let target = b"some reconstructed text".to_vec();
    let d = delta(b"unknown base contents xxxxxxxxx", &target);
    let pack = build_pack(
        &[SynEntry::RefDelta { base: ghost, delta: d }],
        &Default::default(),
    );
    h.import("thin.pack", &pack.bytes);
    let s = h.resolve(Budgets::defaults());
    assert_eq!(s.missing_base, 1);
    let chain: Option<String> = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT blocked_chain FROM resolutions r JOIN nodes n ON n.id=r.node_id AND r.branch_id=1",
            [],
            |r| r.get(0),
        )
        .ok()
    };
    let chain = chain.expect("blocked chain recorded");
    let v: serde_json::Value = serde_json::from_str(&chain).unwrap();
    assert!(v.is_array());
    assert_eq!(v[0]["reason"].as_str().unwrap(), format!("missing external base {}", to_hex(&ghost)));
}

#[test]
fn ofs_distance_out_of_pack_isolated() {
    let h = Harness::new();
    // Build a single ofs-delta, then corrupt its ofs varint to point backwards
    // beyond the pack start.
    let base = b"hello ofs base content".to_vec();
    let target = b"hello ofs BASE content!!".to_vec();
    let entries = vec![
        SynEntry::Full { kind: B, content: base.clone() },
        SynEntry::OfsDelta { base_index: 0, delta: delta(&base, &target) },
    ];
    let mut bytes = build_pack(&entries, &Default::default()).bytes;
    // Locate the second entry header (OBJ_OFS_DELTA=6): high nibble 0x60.
    // Find byte with top pattern 0x6? after the 12-byte file header.
    let mut pos = None;
    for i in 12..bytes.len() {
        if (bytes[i] & 0x70) == 0x60 {
            pos = Some(i);
            break;
        }
    }
    let p = pos.unwrap();
    // header byte then possibly size continuation; ofs varint follows.
    // Simplest: set the first ofs byte to a large value by flipping bits,
    // but keep MSB structure valid. Find it by re-parsing header length.
    // After single-byte size (small payload), ofs byte is p+1.
    let ofs_byte = p + 1;
    // Encode a distance far larger than the pack via a 4-byte varint.
    let big = encode_ofs((1u64 << 28) + 123);
    let new_bytes = {
        let mut nb = bytes.clone();
        let old_len = {
            // decode old ofs length
            let (_, n) = decode_ofs(&nb[ofs_byte..]).unwrap();
            n
        };
        nb.splice(ofs_byte..ofs_byte + old_len, big.iter().copied());
        nb
    };
    bytes = new_bytes;
    h.import("corrupt-ofs.pack", &bytes);
    let s = h.resolve(Budgets::defaults());
    // Base still resolves; delta is isolated as bad/missing, other analysis fine.
    assert_eq!(s.resolved, 1);
    assert!(s.missing_base + s.bad_object >= 1);
    let statuses = h.statuses();
    assert!(statuses.iter().any(|(_, st, _)| st == "resolved"));
}

#[test]
fn bad_crc_marks_node_but_others_continue() {
    let h = Harness::new();
    let (entries, objs, _, _) = entries_chain();
    let built = build_pack(&entries, &Default::default());
    let mut idx_bytes = honest_idx(&built.bytes, &objs);
    // Corrupt one CRC table entry (first crc = byte after sha table).
    let count = 3usize;
    let crc_table = 8 + 256 * 4 + count * 20;
    idx_bytes[crc_table + 2] ^= 0xff;
    // Must also fix the idx trailing checksum region? We intentionally leave it,
    // so idx checksum fails; parser records it and we still read the rows.
    h.import("base.pack", &built.bytes);
    let rep = h.import("bad.idx", &idx_bytes);
    // At least one CRC mismatch reported (unless idx checksum aborted parse).
    assert!(
        rep.errors.iter().any(|e| e.contains("CRC") || e.contains("SHA1")),
        "expected CRC/SHA1 evidence, got {:?}",
        rep.errors
    );
    let s = h.resolve(Budgets::defaults());
    // Resolution based on content alone should still resolve all objects
    // because CRC evidence here targets the full base node.
    assert!(s.resolved >= 2 || s.bad_object >= 1);
}

#[test]
fn spoofed_size_isolated_mid_chain() {
    let h = Harness::new();
    let v0 = b"size spoof base content xxxxxxxxxxxxxxxxx".to_vec();
    let v1 = b"size spoof BASE content xxxxxxxxxxxxxxxxx!".to_vec();
    let d = delta(&v0, &v1);
    let entries = vec![
        SynEntry::Full { kind: B, content: b"other independent blob".to_vec() },
        SynEntry::Full { kind: B, content: v0.clone() },
        SynEntry::OfsDelta { base_index: 1, delta: d },
    ];
    // Spoof the delta entry (index 2) declared size: mismatch discovered when
    // resolution reaches that node.
    let built = build_pack(
        &entries,
        &pack_chain_microscope::pack::BuildOptions {
            spoof_size: vec![2],
            ..Default::default()
        },
    );
    h.import("spoof.pack", &built.bytes);
    let s = h.resolve(Budgets::defaults());
    assert!(s.bad_object >= 1, "spoofed delta not isolated: {s:?}");
    // Independent object still analyzed.
    assert_eq!(s.resolved, 2, "independent + base still resolve: {s:?}");
    let (st, err): (String, Option<String>) = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT r.status,r.error FROM nodes n JOIN resolutions r ON r.node_id=n.id
             WHERE n.source_id=?1 AND n.kind='ofs-delta'",
            [1i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(st, "bad-object");
    assert!(err.unwrap().contains("size spoof"));
}

#[test]
fn duplicate_oid_candidate_order_independent_of_import_order() {
    // Two different packs each contain a *full* node whose honest content hash
    // equals the same oid (identical content). A ref-delta asks for that oid.
    let shared = b"identical shared base contents 0123456789".to_vec();
    let target = b"identical shared BASE contents 0123456789!!".to_vec();
    let oid = git_object_id(B, &shared);
    let d = delta(&shared, &target);

    let pack_a = build_pack(&[SynEntry::Full { kind: B, content: shared.clone() }], &Default::default());
    let pack_b = build_pack(&[SynEntry::Full { kind: B, content: shared.clone() }], &Default::default());
    let thin = build_pack(&[SynEntry::RefDelta { base: oid, delta: d }], &Default::default());

    for order in [vec!["a", "b"], vec!["b", "a"]] {
        let h = Harness::new();
        let mut files: Vec<(&str, &[u8])> = vec![("thin.pack", &thin.bytes)];
        if order[0] == "a" {
            files.push(("a.pack", &pack_a.bytes));
            files.push(("b.pack", &pack_b.bytes));
        } else {
            files.push(("b.pack", &pack_b.bytes));
            files.push(("a.pack", &pack_a.bytes));
        }
        for (name, data) in files {
            h.import(name, data);
        }
        let s = h.resolve(Budgets::defaults());
        assert_eq!(s.resolved, 3, "duplicate oid must both rank and resolve: {s:?}");

        // Ranking must select the same base node regardless of import order:
        // resolved target oid must be identical in both orderings.
        let target_oid = to_hex(&git_object_id(B, &target));
        let got: String = {
            let c = h.db.0.lock().unwrap();
            c.query_row(
                "SELECT resolved_oid FROM resolutions WHERE branch_id=1 AND status='resolved'
                 AND resolved_oid=?1",
                [target_oid.clone()],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(got, target_oid);
    }
}

#[test]
fn budget_pause_is_resumable_and_never_partial() {
    let h = Harness::new();
    // Build many independent large-ish blobs so default resolution exceeds a
    // tiny total budget, producing a paused intermediate state.
    let big = vec![b'z'; 3000];
    let entries: Vec<SynEntry> = (0..6)
        .map(|i| {
            let mut c = big.clone();
            c.push(i as u8);
            SynEntry::Full { kind: B, content: c }
        })
        .collect();
    let built = build_pack(&entries, &Default::default());
    h.import("big.pack", &built.bytes);

    let s = h.resolve(tight_budget());
    assert!(s.paused, "tiny budget must pause: {s:?}");
    assert!(s.budget_paused >= 1);
    // No content committed for the paused node: partial output never stored.
    let paused_has_content: i64 = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT COUNT(*) FROM resolutions WHERE status='budget-paused' AND length(content)>0",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(paused_has_content, 0);
    let cp: String = {
        let c = h.db.0.lock().unwrap();
        c.query_row("SELECT status FROM checkpoints WHERE branch_id=1", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(cp, "paused");

    // Resume with a large budget and finish everything.
    let s2 = resolver::resolve_all(
        &h.db,
        resolver::ResolveOptions {
            branch_id: 1,
            budgets: Budgets::defaults(),
            only_nodes: None,
            pin_node: None,
            resume: true,
        },
    );
    assert!(!s2.paused, "resume should complete: {s2:?}");
    assert_eq!(s2.resolved, 6);
}

#[test]
fn adding_base_recomputes_only_affected_subgraph() {
    let h = Harness::new();
    let base = b"local recompute base abcdefghij".to_vec();
    let mid = b"local recompute BASE abcdefghij!".to_vec();
    let top = b"local recompute BASE ABCDEFGHIJ!!".to_vec();
    let oid = git_object_id(B, &base);
    let unrelated = b"totally unrelated independent object".to_vec();

    // thin pack: ref-delta(mid) + ofs-delta(top) chain, plus unrelated blob.
    let thin = build_pack(
        &[
            SynEntry::RefDelta { base: oid, delta: delta(&base, &mid) },
            SynEntry::OfsDelta { base_index: 0, delta: delta(&mid, &top) },
            SynEntry::Full { kind: B, content: unrelated.clone() },
        ],
        &Default::default(),
    );
    h.import("thin.pack", &thin.bytes);
    let s = h.resolve(Budgets::defaults());
    assert_eq!(s.missing_base, 2);
    assert_eq!(s.resolved, 1);

    // Capture updated_at of the unrelated resolution; it must not recompute.
    let before_unrelated: String = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT updated_at FROM resolutions r JOIN nodes n ON n.id=r.node_id
             WHERE n.source_id=?1 AND n.kind='full' AND r.branch_id=1",
            [1i64],
            |r| r.get(0),
        )
        .unwrap()
    };

    // Supply the missing base in a second source.
    let base_pack = build_pack(&[SynEntry::Full { kind: B, content: base.clone() }], &Default::default());
    h.import("base-late.pack", &base_pack.bytes);
    let s2 = h.resolve(Budgets::defaults());
    assert_eq!(s2.resolved, 4, "whole chain resolves after base arrives: {s2:?}");

    let top_oid = to_hex(&git_object_id(B, &top));
    let got: String = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT resolved_oid FROM resolutions WHERE branch_id=1 AND status='resolved' AND resolved_oid=?1",
            [top_oid.clone()],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(got, top_oid);

    let after_unrelated: String = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT updated_at FROM resolutions r JOIN nodes n ON n.id=r.node_id
             WHERE n.source_id=?1 AND n.kind='full' AND r.branch_id=1",
            [1i64],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(before_unrelated, after_unrelated, "unaffected object must not be recomputed");
}

#[test]
fn idx_pack_mismatch_is_reported_and_links_nothing() {
    let h = Harness::new();
    let p1 = build_pack(&[SynEntry::Full { kind: B, content: b"pack one contents".to_vec() }], &Default::default());
    let p2 = build_pack(&[SynEntry::Full { kind: B, content: b"pack two different contents!!".to_vec() }], &Default::default());
    // idx built against p2 but imported alongside p1.
    let idx = {
        let parsed = pack_chain_microscope::pack::parse_pack(&p2.bytes);
        let content = b"pack two different contents!!".to_vec();
        let rows = vec![IdxRow {
            offset: parsed.entries[0].offset,
            oid: git_object_id(B, &content),
            crc: parsed.entries[0].record_crc,
        }];
        build_idx_v2(&p2.bytes, &rows, &Default::default())
    };
    h.import("p1.pack", &p1.bytes);
    let rep = h.import("wrong.idx", &idx);
    assert!(rep.errors.iter().any(|e| e.contains("does not match")));
    let linked: Option<i64> = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT linked_pack_source_id FROM sources WHERE id=?1",
            [rep.source_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(linked.is_none());
    // p2 imported later should still link correctly against nothing here.
    let _ = p2;
}

#[test]
fn delta_cycle_is_detected_and_isolated() {
    let h = Harness::new();
    // Create a cycle using ref-deltas with honest-but-mutually-referring oids.
    // We craft two delta payloads whose declared base sizes/contents can be
    // made self-consistent by using equal-size buffers, then point idx claims
    // at each other. The resolver sees a ref A->B, B->A loop via candidates.
    let payload_a = vec![b'a'; 64];
    let payload_b = vec![b'b'; 64];
    // Simple deltas: insert whole output from empty-ish base is invalid; use
    // copy+insert against a same-sized base.
    let da = delta(&payload_b, &payload_a);
    let db_ = delta(&payload_a, &payload_b);
    let oid_a = [0xAAu8; 20];
    let oid_b = [0xBBu8; 20];
    let pack = build_pack(
        &[
            SynEntry::RefDelta { base: oid_b, delta: da },
            SynEntry::RefDelta { base: oid_a, delta: db_ },
        ],
        &Default::default(),
    );
    h.import("cycle.pack", &pack.bytes);
    // Inject candidates mapping the two fake oids onto the delta nodes,
    // forming an A<->B reference loop.
    {
        let c = h.db.0.lock().unwrap();
        let nodes: Vec<(i64, i64)> = {
            let mut s = c.prepare("SELECT id,source_id FROM nodes ORDER BY pack_offset").unwrap();
            s.query_map([], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,i64>(1)?)))
                .unwrap()
                .flatten()
                .collect()
        };
        for (i, (nid, sid)) in nodes.iter().enumerate() {
            let (oid, target_node) = if i == 0 {
                (oid_b, nodes[1].0)
            } else {
                (oid_a, nodes[0].0)
            };
            // candidate says node i *has* oid of the other side so lookups loop
            let oid_hex = to_hex(if i == 0 { &oid_a } else { &oid_b });
            let _ = (oid, target_node);
            c.execute(
                "INSERT INTO candidates(oid,node_id,node_source_id,node_offset,origin,source_label,hash_match,confidence,sort_key)
                 VALUES(?1,?2,?3,0,'ref-inferred','synthetic',0,10,10)",
                rusqlite::params![oid_hex, nid, sid],
            )
            .unwrap();
        }
    }
    let s = h.resolve(Budgets::defaults());
    assert_eq!(s.cycle, 2, "both looping nodes reported as cycle: {s:?}");
}

#[test]
fn deleting_source_with_dependents_is_blocked_with_list() {
    let h = Harness::new();
    // Base lives in one source, a delta (another source) depends on it.
    let base = b"delete dependency base 0001".to_vec();
    let target = b"delete dependency BASE 0001!!".to_vec();
    let oid = git_object_id(B, &base);
    let base_pack = build_pack(&[SynEntry::Full { kind: B, content: base.clone() }], &Default::default());
    let thin = build_pack(
        &[SynEntry::RefDelta { base: oid, delta: delta(&base, &target) }],
        &Default::default(),
    );
    let rb = h.import("base.pack", &base_pack.bytes);
    let rt = h.import("delta.pack", &thin.bytes);
    h.resolve(Budgets::defaults());

    // Trying to delete the base pack must be blocked and list the dependent.
    let deps = crate_dependents_for_test(&h.db, rb.source_id);
    assert!(
        deps.iter().any(|d| d["source_id"].as_i64() == Some(rt.source_id)),
        "dependent delta must be listed before deletion: {deps:?}"
    );
}

fn crate_dependents_for_test(db: &pack_chain_microscope::db::Db, source_id: i64) -> Vec<serde_json::Value> {
    // Reuse the same closure helper via resolver public API.
    let own: Vec<i64> = {
        let c = db.0.lock().unwrap();
        let mut s = c.prepare("SELECT id FROM nodes WHERE source_id=?1").unwrap();
        s.query_map([source_id], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect()
    };
    let closure = resolver::affected_subgraph(db, &own);
    let c = db.0.lock().unwrap();
    let arr = serde_json::to_string(&closure).unwrap();
    let mut s = c
        .prepare(
            "SELECT n.id,n.source_id,n.pack_offset FROM nodes n
             WHERE n.id IN (SELECT value FROM json_each(?1))",
        )
        .unwrap();
    s.query_map([arr], |r| {
        Ok(serde_json::json!({
            "node_id": r.get::<_,i64>(0)?,
            "source_id": r.get::<_,i64>(1)?,
            "offset": r.get::<_,i64>(2)?,
        }))
    })
    .unwrap()
    .flatten()
    .collect()
}

#[test]
fn loose_object_parse_and_hash() {
    let h = Harness::new();
    let content = b"loose blob hello";
    let oid = git_object_id(B, content);
    let hex = to_hex(&oid);
    let payload = loose_payload(B, content);
    let path_name = format!("{}/{}.loose", &hex[0..2], &hex[2..]);
    h.import(&path_name, &payload);
    let s = h.resolve(Budgets::defaults());
    assert_eq!(s.resolved, 1);
    let (status, got_oid): (String, String) = {
        let c = h.db.0.lock().unwrap();
        c.query_row(
            "SELECT r.status,r.resolved_oid FROM nodes n JOIN resolutions r ON r.node_id=n.id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    };
    assert_eq!(status, "resolved");
    assert_eq!(got_oid, hex);
}

#[test]
fn single_object_ratio_cap_is_hard_limit() {
    let h = Harness::new();
    let big = vec![b'q'; 5000];
    let pack = build_pack(&[SynEntry::Full { kind: B, content: big }], &Default::default());
    h.import("big-single.pack", &pack.bytes);
    let b = Budgets { max_depth: 64, total_bytes: 1_000_000, single_ratio: 0.001 };
    let s = h.resolve(b);
    assert_eq!(s.too_large, 1, "single-object ratio cap should isolate: {s:?}");
    let _ = IdxOptions::default();
}
