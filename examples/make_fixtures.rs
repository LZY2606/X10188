//! Generate demo fixtures into a directory (also useful for manual UI testing).
use pack_chain_microscope::git::*;
use pack_chain_microscope::pack::*;
use std::fs;

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "demo-fixtures".into());
    fs::create_dir_all(&out).unwrap();

    let v0 = b"forensic base line alpha beta gamma delta epsilon".to_vec();
    let v1 = b"forensic BASE line alpha beta gamma delta epsilon!".to_vec();
    let v2 = b"forensic BASE line alpha BETA gamma delta epsilon!!".to_vec();
    let d01 = pack_chain_microscope::delta::delta_from_copy_insert(&v0, &v1);
    let d12 = pack_chain_microscope::delta::delta_from_copy_insert(&v1, &v2);
    let entries = vec![
        SynEntry::Full { kind: OBJ_BLOB, content: v0.clone() },
        SynEntry::OfsDelta { base_index: 0, delta: d01 },
        SynEntry::OfsDelta { base_index: 1, delta: d12 },
    ];
    let built = build_pack(&entries, &Default::default());
    fs::write(format!("{out}/base.pack"), &built.bytes).unwrap();

    // honest idx
    let parsed = parse_pack(&built.bytes);
    let objs = [v0, v1, v2];
    let rows: Vec<IdxRow> = parsed
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| IdxRow {
            offset: e.offset,
            oid: git_object_id(OBJ_BLOB, &objs[i]),
            crc: e.record_crc,
        })
        .collect();
    let idx = build_idx_v2(&built.bytes, &rows, &Default::default());
    fs::write(format!("{out}/base.idx"), idx).unwrap();

    // thin pack referencing an external base (missing initially)
    let external = b"external base payload 00001111222233334444".to_vec();
    let derived = b"external BASE payload 00001111222233334444!!".to_vec();
    let oid = git_object_id(OBJ_BLOB, &external);
    let d = pack_chain_microscope::delta::delta_from_copy_insert(&external, &derived);
    let thin = build_pack(&[SynEntry::RefDelta { base: oid, delta: d }], &Default::default());
    fs::write(format!("{out}/thin.pack"), &thin.bytes).unwrap();
    let ext_pack = build_pack(&[SynEntry::Full { kind: OBJ_BLOB, content: external }], &Default::default());
    fs::write(format!("{out}/external.pack"), &ext_pack.bytes).unwrap();

    // loose object
    let content = b"loose object written to the object store";
    let payload = loose_payload(OBJ_BLOB, content);
    let oid = git_object_id(OBJ_BLOB, content);
    let hex = to_hex(&oid);
    fs::create_dir_all(format!("{out}/loose/{}", &hex[0..2])).unwrap();
    fs::write(format!("{out}/loose/{}/{}", &hex[0..2], &hex[2..]), payload).unwrap();

    println!("fixtures written to {out}");
}
