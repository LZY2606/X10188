mod support;

use pack_microscope::testing::*;
use support::*;
use std::collections::HashSet;

fn tmp() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pm-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn harness() -> (pack_microscope::engine::Engine, std::path::PathBuf) {
    let dir = tmp();
    (pack_microscope::engine::Engine::new(&dir).unwrap(), dir)
}

async fn import(engine: &pack_microscope::engine::Engine, name: &str, data: Vec<u8>) {
    engine.import(name, data).await.unwrap();
}

fn status(engine: &pack_microscope::engine::Engine, oid: &str) -> String {
    let dir = engine_dir(engine);
    let (conn, _) = pack_microscope::testing::open_readonly(&dir);
    conn.query_row(
        "SELECT status FROM resolved r JOIN branches b ON b.id=r.branch_id
         WHERE b.name='default' AND r.oid=?1",
        rusqlite::params![oid],
        |r| r.get(0),
    )
    .unwrap_or_else(|_| "absent".to_string())
}

fn engine_dir(engine: &pack_microscope::engine::Engine) -> std::path::PathBuf {
    engine.data_dir_path()
}

fn chained_pack() -> (Vec<u8>, Vec<u8>, Vec<String>) {
    let base_payload = b"base object content v1".to_vec();
    let mid_payload = b"base object content v2 - middle".to_vec();
    let top_payload = b"final reconstructed blob content!!".to_vec();
    let base_oid = git_oid("blob", &base_payload);
    let mid_oid = git_oid("blob", &mid_payload);
    let top_oid = git_oid("blob", &top_payload);

    // delta base->mid: copy shared prefix + insert new tail
    let shared = 20usize; // "base object content"
    let delta1 = {
        let mut body = copy_op(0, shared);
        body.extend_from_slice(&insert_op(b" v2 - middle"));
        delta_with(base_payload.len(), mid_payload.len(), body)
    };
    let delta2 = {
        let mut body = Vec::new();
        body.extend_from_slice(&insert_op(b"final reconstructed "));
        body.extend_from_slice(&copy_op(0, 4)); // "base"
        body.extend_from_slice(&insert_op(b" blob content!!"));
        delta_with(mid_payload.len(), top_payload.len(), body)
    };

    let mk = |dist: usize| {
        build_pack(&[
            Entry::Plain {
                kind: "blob".into(),
                payload: base_payload.clone(),
            },
            Entry::Ofs {
                distance: dist,
                delta: delta1.clone(),
                base_oid: base_oid.clone(),
            },
            Entry::Ref {
                base_oid: mid_oid.clone(),
                delta: delta2.clone(),
            },
        ])
    };
    let distance = {
        let probe = mk(1);
        probe.entries[1].header_offset - probe.entries[0].header_offset
    };
    let built = mk(distance);
    let sha = pack_sha(&built.data[..built.data.len() - 20]);
    let idx = build_idx(&built.entries, &sha);
    let oids = vec![base_oid, mid_oid, top_oid];
    (built.data, idx, oids)
}

#[tokio::test]
async fn chained_ofs_and_ref_deltas_resolve() {
    let (engine, _dir) = harness().await;
    let (pack, idx, oids) = chained_pack();
    import(&engine, "chain.pack", pack).await;
    import(&engine, "chain.idx", idx).await;
    for oid in &oids {
        assert_eq!(status(&engine, oid), "complete", "oid {oid}");
    }
}
