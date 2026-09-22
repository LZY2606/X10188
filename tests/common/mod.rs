#![allow(dead_code)]
use pack_chain_microscope::db::Db;
use pack_chain_microscope::git::*;
use pack_chain_microscope::importer;
use pack_chain_microscope::model::Budgets;
use pack_chain_microscope::pack::{build_idx_v2, IdxRow};
use pack_chain_microscope::resolver;
use std::path::PathBuf;

pub struct Harness {
    pub db: Db,
    pub dir: PathBuf,
    pub counter: std::cell::Cell<u32>,
}

impl Harness {
    pub fn new() -> Harness {
        let dir = std::env::temp_dir().join(format!(
            "pcsm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(dir.join("t.sqlite").to_str().unwrap()).unwrap();
        Harness {
            db,
            dir,
            counter: std::cell::Cell::new(0),
        }
    }

    pub fn import(&self, filename: &str, data: &[u8]) -> importer::ImportReport {
        importer::import_bytes(&self.db, &self.dir, filename, data)
    }

    pub fn resolve(&self, b: Budgets) -> resolver::ResolveSummary {
        resolver::recompute_after_import(&self.db, b)
    }

    pub fn statuses(&self) -> Vec<(i64, String, Option<String>)> {
        let c = self.db.0.lock().unwrap();
        let mut s = c
            .prepare(
                "SELECT n.id,r.status,r.resolved_oid FROM nodes n
                 LEFT JOIN resolutions r ON r.node_id=n.id AND r.branch_id=1
                 ORDER BY n.source_id,n.pack_offset",
            )
            .unwrap();
        s.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| "none".into()),
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap()
        .flatten()
        .collect()
    }
}

pub fn honest_idx(pack: &[u8], objects: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let parsed = pack_chain_microscope::pack::parse_pack(pack);
    let rows: Vec<IdxRow> = parsed
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| IdxRow {
            offset: e.offset,
            oid: git_object_id(objects[i].0, &objects[i].1),
            crc: e.record_crc,
        })
        .collect();
    build_idx_v2(pack, &rows, &Default::default())
}

pub fn delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    pack_chain_microscope::delta::delta_from_copy_insert(base, target)
}

pub const fn tight_budget() -> Budgets {
    Budgets {
        max_depth: 64,
        total_bytes: 4096,
        single_ratio: 0.8,
    }
}
