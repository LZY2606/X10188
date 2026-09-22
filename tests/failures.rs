mod common;
use common::*;
use microscope::git::{git_oid, Kind};

#[test]
fn size_spoof_is_isolated() {
    let app = temp_app("spoof");
    let content = b"genuine content here".to_vec();
    let mut built = build_pack(&[PackObj::Full(Kind::Blob, content.clone())]);
    // Corrupt the object header size nibble to a wrong size (e.g. add 3),
    // keeping compressed stream intact. Header is at offset 12.
    let before = built.bytes[12];
    let tc = (before >> 4) & 7;
    let bogus_size = (content.len() as u8).wrapping_add(5);
    built.bytes[12] = (tc << 4) | (bogus_size & 0x0f);
    // recompute pack checksum so only the size lie is at fault
    use sha1::Digest;
    let end = built.bytes.len() - 20;
    let mut h = sha1::Sha1::new();
    h.update(&built.bytes[..end]);
    let d = h.finalize();
    built.bytes[end..].copy_from_slice(&d);

    app.import_file("spoof.pack", &built.bytes).unwrap();
    let s = app.store.lock().unwrap();
    let err: String = s
        .db
        .query_row("SELECT parse_err FROM entries WHERE id=1", [], |r| r.get::<_, Option<String>>(0))
        .unwrap()
        .unwrap();
    assert!(err.contains("size_spoof"), "{err}");
}

#[test]
fn ofs_out_of_bounds_rejected() {
    let app = temp_app("ofsoob");
    let base = b"base object bytes".to_vec();
    // craft a pack by hand: base then ofs-delta with neg > offset
    let mut body = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());
    let mut p1 = Vec::new();
    pack_header(&mut p1, 3, base.len() as u64);
    p1.extend_from_slice(&deflate(&base));
    body.extend_from_slice(&p1);
    // second object claims negative offset 5000 (larger than its offset)
    let fake_delta = encode_delta(5, &[DeltaOp::Insert(b"00000".to_vec())]);
    pack_header(&mut body, 6, fake_delta.len() as u64);
    body.extend_from_slice(&ofs_header(5000));
    body.extend_from_slice(&deflate(&fake_delta));
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&body);
    body.extend_from_slice(&h.finalize());

    app.import_file("oob.pack", &body).unwrap();
    let s = app.store.lock().unwrap();
    let err: String = s
        .db
        .query_row("SELECT parse_err FROM entries WHERE id=2", [], |r| r.get::<_, Option<String>>(0))
        .unwrap()
        .unwrap();
    drop(s);
    assert!(err.contains("ofs_oob"), "{err}");
    // other object still analyzed
    let st = {
        let s = app.store.lock().unwrap();
        s.db
            .query_row(
                "SELECT status FROM resolutions WHERE branch='default' AND entry_id=1",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
    };
    assert_eq!(st, "ok");
}

#[test]
fn delta_cycle_is_detected_and_isolated() {
    let app = temp_app("cycle");
    // Two ref-deltas pointing at each other's oids. We invent oids A and B,
    // craft deltas whose application yields content hashing to those oids is
    // infeasible; instead we construct a cycle via ofs in two separate packs
    // sharing offsets: ofs bases are per-pack, so use two ref deltas with
    // declared claimed oids injected through two conflicting fake idx files.
    //
    // Simpler deterministic cycle: build a single pack containing two ref
    // deltas whose base_oid fields cross-reference oids that the *idx* claims
    // for the two entries. The idx asserts oids even though hashes won't match;
    // resolution follows the ref edges and detects the cycle before hashing.
    let oid_a = "aa".repeat(20);
    let oid_b = "bb".repeat(20);
    let d_for = |n: u8| encode_delta(4, &[DeltaOp::Insert(vec![b'x'; 4 + n as usize])]);
    let _ = d_for;
    let da = encode_delta(4, &[DeltaOp::Insert(b"aaaa".to_vec())]);
    let db = encode_delta(4, &[DeltaOp::Insert(b"bbbb".to_vec())]);

    let mut body = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());
    let off_a = body.len() as u64;
    pack_header(&mut body, 7, da.len() as u64);
    body.extend_from_slice(&hex::decode(&oid_b).unwrap());
    let za = deflate(&da);
    body.extend_from_slice(&za);
    let off_b = body.len() as u64;
    pack_header(&mut body, 7, db.len() as u64);
    body.extend_from_slice(&hex::decode(&oid_a).unwrap());
    let zb = deflate(&db);
    body.extend_from_slice(&zb);
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&body);
    let pack_sha = hex::encode(h.finalize());
    body.extend_from_slice(&hex::decode(&pack_sha).unwrap());
    app.import_file("cyc.pack", &body).unwrap();

    // manually inject claimed oids so the edges become a cycle in providers
    {
        let s = app.store.lock().unwrap();
        s.db
            .execute("UPDATE entries SET claimed_oid=?2 WHERE id=1", rusqlite::params![oid_a])
            .unwrap();
        s.db
            .execute("UPDATE entries SET claimed_oid=?2 WHERE id=2", rusqlite::params![oid_b])
            .unwrap();
    }
    app.retry().unwrap();
    for id in [1, 2] {
        let s = app.store.lock().unwrap();
        let (status, err): (String, String) = s
            .db
            .query_row(
                "SELECT status,COALESCE(error,'') FROM resolutions WHERE branch='default' AND entry_id=?1",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(s);
        assert_eq!(status, "error", "entry {id}");
        assert!(err.contains("cycle"), "{err}");
    }
    let _ = (off_a, off_b);
}

#[test]
fn bad_crc_is_flagged() {
    let app = temp_app("crc");
    let content = b"crc protected payload data".to_vec();
    let mut built = build_pack(&[PackObj::Full(Kind::Blob, content)]);
    // flip a byte in the compressed object; recompute pack trailer so the
    // *idx* per-entry CRC mismatch is the signal
    let off = built.offsets[0] as usize;
    let zlen = built.spans[0].2;
    let plen = built.spans[0].1;
    built.bytes[off + plen + zlen / 2] ^= 0x01;
    let end = built.bytes.len() - 20;
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(&built.bytes[..end]);
    built.bytes[end..].copy_from_slice(&h.finalize());

    app.import_file("crc.pack", &built.bytes).unwrap();
    app.import_file("crc.idx", &built.idx).unwrap();
    let s = app.store.lock().unwrap();
    let (ok,): (i64,) = s
        .db
        .query_row("SELECT COUNT(*) FROM idx_crc WHERE ok=0", [], |r| Ok((r.get(0)?,)))
        .unwrap();
    let note: String = s
        .db
        .query_row("SELECT COALESCE(note,'') FROM sources WHERE kind='idx'", [], |r| r.get(0))
        .unwrap();
    drop(s);
    assert!(ok >= 1);
    assert!(note.contains("CRC32"), "{note}");
}
