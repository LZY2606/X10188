use packchain_microscope::builder::*;
use packchain_microscope::engine::*;
use packchain_microscope::git::*;
use tempfile::tempdir;

fn blob(value: &str) -> Vec<u8> { value.as_bytes().to_vec() }
fn state(report: &AnalysisReport, id: i64) -> &ResolveState { &report.states[&id].state }

#[test]
fn parses_chained_ofs_and_ref_deltas_without_git() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    let base = blob("alpha text");
    let first = blob("alpha text plus one");
    let second = blob("alpha text plus one and two");
    let d1 = delta_replace(&base, &first);
    let built = write_pack(&[
        BuilderEntry::Object { kind: GitType::Blob, data: base.clone() },
        BuilderEntry::OfsDelta { distance: 0, delta: d1 },
    ]);
    let distance = built.entry_offsets[1] - built.entry_offsets[0];
    let built = write_pack(&[
        BuilderEntry::Object { kind: GitType::Blob, data: base.clone() },
        BuilderEntry::OfsDelta { distance, delta: delta_replace(&base, &first) },
    ]);
    let pack2 = write_pack(&[BuilderEntry::RefDelta { base: built.entry_oids[1], delta: delta_replace(&first, &second) }]);
    analyzer.import("objects.pack", built.bytes).unwrap();
    let report = analyzer.analyze(Budget::default(), "default").unwrap();
    assert_eq!(state(&report, 2), &ResolveState::Resolved);
    analyzer.import("dependent.pack", pack2.bytes).unwrap();
    let raw_ids = analyzer.raw_ids_for_source(2);
    let report = analyzer.recompute_affected(&raw_ids, Budget::default(), "default").unwrap();
    let last = *report.states.keys().max().unwrap();
    assert_eq!(state(&report, last), &ResolveState::Resolved);
    assert_eq!(report.states[&last].content, second);
    assert_eq!(report.states[&last].oid, Some(git_object_id(GitType::Blob, &second)));
    assert!(report.states[&last].steps.iter().any(|step| step.check_kind == "delta-op"));
}

#[test]
fn missing_external_base_records_blocking_chain_and_recovers_locally() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    let target = blob("later supplied base");
    let child = blob("later supplied base expanded");
    let pack = write_pack(&[BuilderEntry::RefDelta { base: git_object_id(GitType::Blob, &target), delta: delta_replace(&target, &child) }]);
    analyzer.import("missing.pack", pack.bytes).unwrap();
    let report = analyzer.analyze(Budget::default(), "default").unwrap();
    assert_eq!(state(&report, 1), &ResolveState::MissingBase);
    let (_oid, loose) = loose_object(GitType::Blob, &target);
    let source = analyzer.import("loose-object", loose).unwrap();
    let report = analyzer.recompute_affected(&analyzer.raw_ids_for_source(source), Budget::default(), "default").unwrap();
    assert_eq!(state(&report, 1), &ResolveState::Resolved);
    assert_eq!(report.states[&1].content, child);
}

#[test]
fn size_spoof_is_invalid_while_other_objects_remain_analyzable() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    let good_pack = write_pack(&[BuilderEntry::Object { kind: GitType::Blob, data: blob("good") }]);
    analyzer.import("good.pack", good_pack.bytes).unwrap();
    let (_oid, loose) = loose_object(GitType::Blob, b"loose-good");
    analyzer.import("loose", loose).unwrap();
    let mut spoofed = Vec::new();
    spoofed.extend_from_slice(b"PACK");
    spoofed.extend_from_slice(&2u32.to_be_bytes());
    spoofed.extend_from_slice(&1u32.to_be_bytes());
    spoofed.push((3 << 4) | 4);
    spoofed.extend_from_slice(&zlib(b"12345"));
    spoofed.extend_from_slice(&[0u8; 20]);
    analyzer.import("spoofed.pack", spoofed).unwrap();
    let report = analyzer.analyze(Budget::default(), "default").unwrap();
    let states = report.states.values().map(|value| value.state.clone()).collect::<Vec<_>>();
    assert!(states.contains(&ResolveState::Resolved));
    assert!(states.contains(&ResolveState::Invalid));
    assert!(report.states.values().any(|value| value.error_code.as_deref() == Some("size-spoof")));
}

#[test]
fn budget_pause_is_retryable_and_never_stores_partial_content() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    let base = vec![b'a'; 2000];
    let expanded = vec![b'b'; 1500];
    let built = write_pack(&[
        BuilderEntry::Object { kind: GitType::Blob, data: base.clone() },
        BuilderEntry::OfsDelta { distance: 0, delta: delta_replace(&base, &expanded) },
    ]);
    let distance = built.entry_offsets[1] - built.entry_offsets[0];
    let built = write_pack(&[
        BuilderEntry::Object { kind: GitType::Blob, data: base.clone() },
        BuilderEntry::OfsDelta { distance, delta: delta_replace(&base, &expanded) },
    ]);
    analyzer.import("budget.pack", built.bytes).unwrap();
    let tight = Budget { max_depth: 16, total_bytes: 1000, single_ratio_percent: 100 };
    let report = analyzer.analyze(tight, "default").unwrap();
    assert!(report.paused);
    assert_eq!(state(&report, 2), &ResolveState::Paused);
    assert!(report.states[&2].content.is_empty());
    let report = analyzer.analyze(Budget::default(), "default").unwrap();
    assert!(!report.paused);
    assert_eq!(state(&report, 2), &ResolveState::Resolved);
}

#[test]
fn duplicate_oids_have_deterministic_candidate_order_independent_of_import_order() {
    let mut first = Analyzer::open(tempdir().unwrap().path()).unwrap();
    let mut second = Analyzer::open(tempdir().unwrap().path()).unwrap();
    let data = blob("same candidate");
    let pack = write_pack(&[BuilderEntry::Object { kind: GitType::Blob, data: data.clone() }]);
    let (_oid, loose) = loose_object(GitType::Blob, &data);
    first.import("a.pack", pack.bytes.clone()).unwrap();
    first.import("loose", loose.clone()).unwrap();
    second.import("loose", loose).unwrap();
    second.import("a.pack", pack.bytes).unwrap();
    assert_eq!(first.dashboard().candidates.len(), second.dashboard().candidates.len());
    assert_eq!(first.dashboard().candidates[0].source, second.dashboard().candidates[0].source);
}

#[test]
fn bad_index_crc_is_reported_as_evidence() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    let built = write_pack(&[BuilderEntry::Object { kind: GitType::Blob, data: blob("crc") }]);
    let mut idx = repair_idx_checksum(built.idx.clone());
    let crc_pos = 8 + 256 * 4 + 20;
    idx[crc_pos] ^= 0xff;
    idx = repair_idx_checksum(idx);
    analyzer.import("x.pack", built.bytes).unwrap();
    analyzer.import("x.idx", idx).unwrap();
    let count: i64 = analyzer.db.conn.query_row("SELECT COUNT(*) FROM resolution_steps WHERE check_kind='index' AND check_ok=0", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn delta_cycle_and_out_of_bounds_ofs_are_isolated() {
    let dir = tempdir().unwrap();
    let analyzer = Analyzer::open(dir.path()).unwrap();
    analyzer.import("cycle.pack", write_cyclic_pack()).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    let delta = delta_replace(b"base", b"changed");
    out.extend_from_slice(&entry_size_header(6, delta.len()));
    out.extend_from_slice(&ofs_header(10_000));
    out.extend_from_slice(&zlib(&delta));
    let checksum = pack_checksum(&out);
    out.extend_from_slice(&checksum);
    analyzer.import("oos.pack", out).unwrap();
    let report = analyzer.analyze(Budget::default(), "default").unwrap();
    let states = report.states.values().map(|value| value.state.clone()).collect::<Vec<_>>();
    assert!(states.iter().filter(|state| **state == ResolveState::Cycle).count() >= 2);
    assert!(states.contains(&ResolveState::MissingBase));
}
