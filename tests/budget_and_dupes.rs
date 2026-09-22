mod common;
use common::*;
use microscope::git::{git_oid, Kind};
use microscope::Budget;

fn build_chain(n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut base = vec![b'B'; 32];
    let base_oid = git_oid(Kind::Blob, &base);
    let mut objs = Vec::new();
    objs.push(PackObj::Full(Kind::Blob, base.clone()));
    let mut prev = base.clone();
    let mut prev_oid = base_oid;
    let mut prev_offset_pos = 0usize;
    for i in 1..n {
        // append growing literal to force bytes
        let mut next = prev.clone();
        next.extend_from_slice(format!("-layer{i}").as_bytes());
        let d = encode_delta(
            prev.len(),
            &[
                DeltaOp::Copy(0, prev.len()),
                DeltaOp::Insert(format!("-layer{i}").into_bytes()),
            ],
        );
        objs.push(PackObj::Ref {
            base_oid: prev_oid.clone(),
            delta: d,
            result: (Kind::Blob, next.clone()),
        });
        prev_oid = git_oid(Kind::Blob, &next);
        prev = next;
        prev_offset_pos += 1;
    }
    let built = build_pack(&objs);
    (built.bytes.clone(), built.idx.clone())
}

#[test]
fn depth_budget_pauses_then_resumes_without_partial_output() {
    let app = temp_app("budget-depth");
    let (pack, idx) = build_chain(6);
    app.import_file("chain.pack", &pack).unwrap();
    app.import_file("chain.idx", &idx).unwrap();
    // depth limit 2: deeper entries must be paused, never partially resolved
    app.set_budget(Budget {
        max_depth: 2,
        total_bytes: 1 << 30,
        per_object_bytes: 1 << 30,
    });
    app.retry().unwrap();
    {
        let s = app.store.lock().unwrap();
        let paused: i64 = s
            .db
            .query_row(
                "SELECT COUNT(*) FROM resolutions WHERE branch='default' AND status='paused'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let partial_content: i64 = s
            .db
            .query_row(
                "SELECT COUNT(*) FROM resolutions WHERE status='paused' AND content_path IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(s);
        assert!(paused >= 1, "expect depth pause");
        assert_eq!(partial_content, 0, "paused objects must not store partial output");
    }
    // raise budget and resume
    app.set_budget(Budget {
        max_depth: 16,
        total_bytes: 1 << 30,
        per_object_bytes: 1 << 30,
    });
    let r = app.retry().unwrap();
    assert_eq!(r.paused, 0);
    let s = app.store.lock().unwrap();
    let bad: i64 = s
        .db
        .query_row(
            "SELECT COUNT(*) FROM resolutions WHERE branch='default' AND status!='ok'",
            [],
            |r| r.get(0),
            )
        .unwrap();
    drop(s);
    assert_eq!(bad, 0);
}

#[test]
fn per_object_cap_pauses() {
    let app = temp_app("budget-cap");
    let big = vec![b'X'; 5000];
    let built = build_pack(&[PackObj::Full(Kind::Blob, big)]);
    app.import_file("big.pack", &built.bytes).unwrap();
    app.set_budget(Budget {
        max_depth: 64,
        total_bytes: 1 << 30,
        per_object_bytes: 1024,
    });
    app.retry().unwrap();
    let s = app.store.lock().unwrap();
    let (status, err): (String, String) = s
        .db
        .query_row(
            "SELECT status,COALESCE(error,'') FROM resolutions WHERE branch='default' AND entry_id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    drop(s);
    assert_eq!(status, "paused");
    assert!(err.contains("per-object"));
}

#[test]
fn duplicate_oid_candidates_are_order_independent_and_pinnable() {
    // import the same blob as loose and in a pack, in BOTH orders across two apps
    let content = b"duplicate candidate body content".to_vec();
    let oid = git_oid(Kind::Blob, &content);
    let built = build_pack(&[PackObj::Full(Kind::Blob, content.clone())]);
    let loose = loose_object(Kind::Blob, &content);

    let run = |pack_first: bool| -> Vec<i64> {
        let tag = if pack_first { "dup-pf" } else { "dup-lf" };
        let app = temp_app(tag);
        if pack_first {
            app.import_file("thing.pack", &built.bytes).unwrap();
            app.import_file("thing.idx", &built.idx).unwrap();
            app.import_file(&format!("{oid}"), &loose).unwrap();
        } else {
            app.import_file(&format!("{oid}.zlib"), &loose).unwrap();
            app.import_file("thing.pack", &built.bytes).unwrap();
            app.import_file("thing.idx", &built.idx).unwrap();
        }
        // a ref-delta consumer in a third pack must pick the same provider both ways
        let d = encode_delta(
            content.len(),
            &[
                DeltaOp::Copy(0, content.len()),
                DeltaOp::Insert(b"~".to_vec()),
            ],
        );
        let mut result = content.clone();
        result.push(b'~');
        let consumer = build_pack(&[PackObj::Ref {
            base_oid: oid.clone(),
            delta: d,
            result: (Kind::Blob, result),
        }]);
        app.import_file("consumer.pack", &consumer.bytes).unwrap();
        app.import_file("consumer.idx", &consumer.idx).unwrap();
        let s = app.store.lock().unwrap();
        let base_entry: i64 = s
            .db
            .query_row(
                "SELECT base_entry_id FROM entries e
                 JOIN resolutions r ON r.entry_id=e.id AND r.branch='default'
                 WHERE e.delta='ref-delta'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let (kind,): (String,) = s
            .db
            .query_row(
                "SELECT s.kind FROM entries e JOIN sources s ON s.id=e.source_id WHERE e.id=?1",
                rusqlite::params![base_entry],
                |r| Ok((r.get(0)?,)),
            )
            .unwrap();
        drop(s);
        assert_eq!(kind, "loose", "loose must win regardless of import order");
        // pin to the pack candidate -> fork branch uses it
        let pack_entry: i64 = {
            let s = app.store.lock().unwrap();
            s.db
                .query_row(
                    "SELECT e.id FROM entries e JOIN sources s ON s.id=e.source_id
                     WHERE s.kind='pack' AND e.claimed_oid=?1 LIMIT 1",
                    rusqlite::params![oid],
                    |r| r.get(0),
                )
                .unwrap()
        };
        app.pin_branch("fork", &oid, pack_entry).unwrap();
        let s = app.store.lock().unwrap();
        let (status,): (String,) = s
            .db
            .query_row(
                "SELECT status FROM resolutions WHERE branch='fork' AND entry_id=(
                    SELECT id FROM entries WHERE delta='ref-delta' LIMIT 1)",
                [],
                |r| Ok((r.get(0)?,)),
            )
            .unwrap();
        drop(s);
        assert_eq!(status, "ok");
        vec![]
    };
    run(true);
    run(false);
}

#[test]
fn adding_base_recomputes_only_affected_subgraph() {
    let app = temp_app("addbase");
    let base = b"late arriving base object body".to_vec();
    let base_oid = git_oid(Kind::Blob, &base);
    let unrelated = b"totally unrelated content x".to_vec();
    let unrelated_oid = git_oid(Kind::Blob, &unrelated);

    let d = encode_delta(
        base.len(),
        &[
            DeltaOp::Copy(0, base.len()),
            DeltaOp::Insert(b"+late".to_vec()),
        ],
    );
    let mut derived = base.clone();
    derived.extend_from_slice(b"+late");
    let thin = build_pack(&[PackObj::Ref {
        base_oid: base_oid.clone(),
        delta: d,
        result: (Kind::Blob, derived),
    }]);
    let unrelated_pack = build_pack(&[PackObj::Full(Kind::Blob, unrelated)]);

    app.import_file("unrel.pack", &unrelated_pack.bytes).unwrap();
    app.import_file("unrel.idx", &unrelated_pack.idx).unwrap();
    app.import_file("thin.pack", &thin.bytes).unwrap();

    let thin_entry: i64 = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row("SELECT id FROM entries WHERE delta='ref-delta'", [], |r| r.get(0))
            .unwrap()
    };
    let unrelated_entry: i64 = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row(
                "SELECT id FROM entries WHERE claimed_oid=?1",
                rusqlite::params![unrelated_oid],
                |r| r.get(0),
            )
            .unwrap()
    };
    let unrel_run_before: i64 = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row(
                "SELECT run_seq FROM resolutions WHERE entry_id=?1 AND branch='default'",
                rusqlite::params![unrelated_entry],
                |r| r.get(0),
            )
            .unwrap()
    };

    // import the missing base as a loose object
    let loose = loose_object(Kind::Blob, &base);
    let rep = app
        .import_file(&format!("{base_oid}.zlib"), &loose)
        .unwrap();
    // only the derived entry (and nothing unrelated) recomputed -> reused ok
    assert!(rep.run.reused >= 1, "unrelated objects should be reused");

    let st_thin = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row(
                "SELECT status FROM resolutions WHERE entry_id=?1 AND branch='default'",
                rusqlite::params![thin_entry],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
    };
    assert_eq!(st_thin, "ok");
    let unrel_run_after: i64 = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row(
                "SELECT run_seq FROM resolutions WHERE entry_id=?1 AND branch='default'",
                rusqlite::params![unrelated_entry],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(unrel_run_before, unrel_run_after, "unrelated object not recomputed");
}

#[test]
fn mismatched_index_pair_is_reported() {
    let app = temp_app("mismatch");
    let a = build_pack(&[PackObj::Full(Kind::Blob, b"pack A body".to_vec())]);
    let b = build_pack(&[PackObj::Full(Kind::Blob, b"pack B body!!".to_vec())]);
    app.import_file("a.pack", &a.bytes).unwrap();
    // import b's idx but call it a.idx; parser links by embedded pack sha
    app.import_file("a.idx", &b.idx).unwrap();
    let s = app.store.lock().unwrap();
    let (idx_ok, note): (Option<i64>, String) = s
        .db
        .query_row(
            "SELECT idx_ok,COALESCE(note,'') FROM sources WHERE kind='idx'",
            [],
            |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap();
    drop(s);
    assert_eq!(idx_ok, Some(0));
    assert!(!note.is_empty());
}
