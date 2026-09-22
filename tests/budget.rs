mod common;

use common::*;
use pack_microscope::pack::parse_pack;
use pack_microscope::types::{Budget, ObjKind};
use pack_microscope::Engine;
use tempfile::tempdir;

#[test]
fn total_budget_pauses_then_resume_completes() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let v0 = b"budget base object content xxxxxxxxxxxx".to_vec();
    let v1 = b"budget base object content yyyyyyyyyyyy".to_vec();
    let oid0 = oid_of(ObjKind::Blob, &v0);
    let oid1 = oid_of(ObjKind::Blob, &v1);
    let d = make_delta(&v0, &v1);
    let dlen = d.len() as u64;

    let probe = build_pack(&[
        EntrySpec::Base { kind: 3, content: v0.clone() },
        EntrySpec::OfsDelta { distance: 1, delta: d.clone(), declared: dlen },
    ]);
    let len0 = probe.offsets[1] - probe.offsets[0];
    let built = build_pack(&[
        EntrySpec::Base { kind: 3, content: v0.clone() },
        EntrySpec::OfsDelta { distance: len0, delta: d, declared: dlen },
    ]);
    let parsed = parse_pack(&built.bytes);
    let entries = vec![
        (oid0, parsed.entries[0].offset, parsed.entries[0].compressed.clone()),
        (oid1, parsed.entries[1].offset, parsed.entries[1].compressed.clone()),
    ];
    let refs: Vec<_> = entries.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    let idx = build_idx_v2(&refs, built.checksum);
    eng.import_bytes("b.pack", &built.bytes, None).unwrap();
    eng.import_bytes("b.idx", &idx, None).unwrap();

    let tiny = Budget::new(50, 45, 1_000_000);
    let stats = eng.analyze(Some(tiny), None).unwrap();
    assert!(!stats.complete, "预算极小应得到可重试的中间状态");
    let paused: i64 = count_status(&eng, "paused");
    assert!(paused >= 1, "delta 对象应暂停，不能当作完整对象");

    let stats2 = eng.resume(Some(Budget::default()), None).unwrap();
    assert!(stats2.complete, "放开预算后恢复应完整");
    assert_eq!(count_status(&eng, "resolved"), 2);
    assert_eq!(count_not_resolved(&eng), 0);
}

#[test]
fn depth_budget_pauses_and_resumes() {
    let dir = tempdir().unwrap();
    let eng = engine(dir.path());

    let v0 = b"depth chain level zero body".to_vec();
    let mut vs = vec![v0.clone()];
    for i in 1..4 {
        let mut c = vs[i - 1].clone();
        c.extend_from_slice(format!("-lvl{}", i).as_bytes());
        vs.push(c);
    }
    let deltas: Vec<Vec<u8>> = (1..4).map(|i| make_delta(&vs[i - 1], &vs[i])).collect();
    let oids: Vec<_> = vs.iter().map(|v| oid_of(ObjKind::Blob, v)).collect();

    let probe_specs: Vec<EntrySpec> = std::iter::once(EntrySpec::Base {
        kind: 3,
        content: vs[0].clone(),
    })
    .chain((0..3).map(|i| EntrySpec::OfsDelta {
        distance: 1,
        delta: deltas[i].clone(),
        declared: deltas[i].len() as u64,
    }))
    .collect();
    let probe = build_pack(&probe_specs);
    let lens: Vec<u64> = (0..3).map(|i| probe.offsets[i + 1] - probe.offsets[i]).collect();

    let specs: Vec<EntrySpec> = std::iter::once(EntrySpec::Base {
        kind: 3,
        content: vs[0].clone(),
    })
    .chain((0..3).map(|i| EntrySpec::OfsDelta {
        distance: lens[i],
        delta: deltas[i].clone(),
        declared: deltas[i].len() as u64,
    }))
    .collect();
    let built = build_pack(&specs);
    let parsed = parse_pack(&built.bytes);
    let entries: Vec<_> = (0..4)
        .map(|i| (oids[i], parsed.entries[i].offset, parsed.entries[i].compressed.clone()))
        .collect();
    let refs: Vec<_> = entries.iter().map(|(o, f, c)| (*o, *f, c.as_slice())).collect();
    let idx = build_idx_v2(&refs, built.checksum);
    eng.import_bytes("d.pack", &built.bytes, None).unwrap();
    eng.import_bytes("d.idx", &idx, None).unwrap();

    let shallow = Budget::new(1, 1024 * 1024, 1_000_000);
    let stats = eng.analyze(Some(shallow), None).unwrap();
    assert!(!stats.complete);
    assert!(stats.depth_limit >= 1);

    let stats2 = eng.resume(Some(Budget::new(50, 1024 * 1024, 1_000_000)), None).unwrap();
    assert!(stats2.complete);
    assert_eq!(count_status(&eng, "resolved"), 4);
}

fn count_status(eng: &std::sync::Arc<Engine>, want: &str) -> i64 {
    let db = eng.db.lock().unwrap();
    db.conn
        .query_row(
            "SELECT COUNT(*) FROM candidates WHERE status=?1",
            rusqlite::params![want],
            |r| r.get(0),
        )
        .unwrap()
}

fn count_not_resolved(eng: &std::sync::Arc<Engine>) -> i64 {
    let db = eng.db.lock().unwrap();
    db.conn
        .query_row(
            "SELECT COUNT(*) FROM candidates WHERE status!='resolved'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
