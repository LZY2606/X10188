//! Analysis engine: import -> parse -> reconcile -> resolve, with
//! budgets, branch pins, conflict detection and localized recomputation.

use crate::gitio::{
    hex_oid, hash_object, parse_hex_oid, sha1_bytes, sha256_bytes, ObjType,
};
use crate::model::*;
use crate::store::{open_or_init, Store};
use rusqlite::params;
use std::path::{Path, PathBuf};

mod import;
mod resolve;
mod state;

pub struct Engine {
    pub store: Store,
    pub data_dir: PathBuf,
}

pub struct Imported {
    pub source_id: i64,
    pub duplicate: bool,
    pub kind: String,
    pub affected: i64,
    pub recomputed: i64,
}

impl Engine {
    pub fn open(data_dir: &Path) -> rusqlite::Result<Engine> {
        std::fs::create_dir_all(data_dir.join("sources")).ok();
        let store = open_or_init(&data_dir.join("microscope.db"))?;
        Ok(Engine {
            store,
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn set_active_branch(&mut self, branch: i64) -> rusqlite::Result<()> {
        self.store.kv_set("active_branch", &branch.to_string())
    }

    pub fn active_branch(&self) -> i64 {
        self.store
            .kv_get("active_branch")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|b| *b != 0)
            .unwrap_or(1)
    }

    pub fn create_branch(&mut self, name: &str) -> rusqlite::Result<i64> {
        self.store
            .conn
            .execute("INSERT INTO branches(name) VALUES(?1)", params![name])?;
        Ok(self.store.conn.last_insert_rowid())
    }

    pub fn set_budgets(
        &mut self,
        max_depth: Option<i64>,
        max_total: Option<i64>,
        max_ratio: Option<f64>,
    ) -> rusqlite::Result<()> {
        if let Some(v) = max_depth {
            self.store.kv_set("max_depth", &v.to_string())?;
        }
        if let Some(v) = max_total {
            self.store.kv_set("max_total_expanded", &v.to_string())?;
        }
        if let Some(v) = max_ratio {
            self.store.kv_set("max_single_ratio", &v.to_string())?;
        }
        Ok(())
    }

    pub fn reset_total_expanded(&mut self) -> rusqlite::Result<()> {
        self.store.kv_set("total_expanded", "0")
    }

    pub fn pin(&mut self, branch_id: i64, oid: &str, candidate_id: i64) -> rusqlite::Result<()> {
        self.store.conn.execute(
            "INSERT INTO branch_pins(branch_id, oid, candidate_id) VALUES(?1,?2,?3)
             ON CONFLICT(branch_id, oid) DO UPDATE SET candidate_id = excluded.candidate_id",
            params![branch_id, oid, candidate_id],
        )?;
        // Only the pinned oid's dependents need recomputation on this branch.
        let mut affected = std::collections::HashSet::new();
        if let Some(c) = self.find_candidate(candidate_id) {
            affected.insert(c);
        }
        affected.extend(self.dependents_of_oid(oid));
        let n = self.recompute_branch_subset(branch_id, affected)?;
        let ev = self.store.conn.last_insert_rowid();
        let _ = ev;
        self.bump_recompute(n)?;
        Ok(())
    }

    pub fn unpin(&mut self, branch_id: i64, oid: &str) -> rusqlite::Result<()> {
        self.store.conn.execute(
            "DELETE FROM branch_pins WHERE branch_id=?1 AND oid=?2",
            params![branch_id, oid],
        )?;
        let mut affected = self.dependents_of_oid(oid);
        affected.extend(
            self.providers_for_oid(oid)
                .into_iter()
                .map(|(id, _)| id),
        );
        let n = self.recompute_branch_subset(branch_id, affected)?;
        self.bump_recompute(n)?;
        Ok(())
    }

    fn bump_recompute(&mut self, n: i64) -> rusqlite::Result<()> {
        if n > 0 {
            let cur: i64 = self.store.kv_get("recompute_events")?.parse().unwrap_or(0);
            self.store
                .kv_set("recompute_events", &(cur + 1).to_string())?;
        }
        Ok(())
    }

    /// Recursive set of candidate ids that (transitively) use the given oid
    /// as a ref-delta base.
    fn dependents_of_oid(&self, oid: &str) -> std::collections::HashSet<i64> {
        let mut out = std::collections::HashSet::new();
        let mut frontier = vec![oid.to_string()];
        while let Some(base) = frontier.pop() {
            let mut stmt = self
                .store
                .conn
                .prepare("SELECT id, oid FROM candidates WHERE ref_base = ?1")
                .unwrap();
            let rows = stmt
                .query_map(params![base], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
                })
                .unwrap();
            for row in rows {
                let (id, oid_opt) = row.unwrap();
                if out.insert(id) {
                    if let Some(o) = oid_opt {
                        frontier.push(o);
                    }
                }
            }
        }
        out
    }

    fn find_candidate(&self, id: i64) -> Option<i64> {
        self.store
            .conn
            .query_row("SELECT 1 FROM candidates WHERE id=?1", params![id], |_| Ok(()))
            .ok()
            .map(|_| id)
    }

    /// Return all candidate ids providing a concrete object id, ordered by
    /// the deterministic sort key (content hash, offset) — import order is
    /// never used.
    fn providers_for_oid(&self, oid: &str) -> Vec<(i64, String)> {
        let mut stmt = self
            .store
            .conn
            .prepare(
                "SELECT id, sort_key FROM candidates
                 WHERE oid = ?1 AND kind IN ('pack','loose')
                 ORDER BY sort_key, id",
            )
            .unwrap();
        stmt.query_map(params![oid], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Objects that still depend on a source, shown before deletion.
    pub fn dependents_of_source(&self, source_id: i64) -> Vec<(i64, Option<String>, String, String)> {
        let mut stmt = self
            .store
            .conn
            .prepare(
                "SELECT c.id, c.oid, c.kind, COALESCE(r.status,'unresolved')
                 FROM candidates c
                 LEFT JOIN resolutions r
                   ON r.candidate_id = c.id AND r.branch_id = ?2
                 WHERE c.source_id = ?1
                 ORDER BY c.id",
            )
            .unwrap();
        let branch = self.active_branch();
        stmt.query_map(params![source_id, branch], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn delete_source(&mut self, source_id: i64) -> rusqlite::Result<i64> {
        let path: String = self
            .store
            .conn
            .query_row(
                "SELECT stored_path FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        std::fs::remove_file(&path).ok();
        // Capture candidates belonging to this source before cascade delete.
        let mut ids: Vec<i64> = {
            let mut stmt = self
                .store
                .conn
                .prepare("SELECT id FROM candidates WHERE source_id=?1")
                .unwrap();
            stmt.query_map(params![source_id], |r| r.get::<_, i64>(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };
        // Ref-delta candidates in OTHER sources may have based themselves on
        // oids provided here.
        for id in &ids {
            let oid: Option<String> = self
                .store
                .conn
                .query_row(
                    "SELECT oid FROM candidates WHERE id=?1",
                    params![id],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            if let Some(o) = oid {
                ids.extend(self.dependents_of_oid(&o));
            }
        }
        let affected: std::collections::HashSet<i64> = ids.into_iter().collect();
        let mut total = 0i64;
        {
            let branches = self.branch_ids();
            for b in branches {
                total += self.recompute_branch_subset(b, affected.clone())?;
            }
        }
        self.store
            .conn
            .execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
        // Reconcile orphan indexes / packs after removal.
        self.reconcile_all();
        // Orphans may have lost anchors but no candidates change; rerun full
        // resolve so missing-base evidence is refreshed.
        total += self.resolve_all()?;
        self.bump_recompute(total)?;
        Ok(total)
    }

    fn branch_ids(&self) -> Vec<i64> {
        let mut stmt = self.store.conn.prepare("SELECT id FROM branches ORDER BY id").unwrap();
        stmt.query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// Import raw bytes. `filename` is the user-visible name used for kind
    /// sniffing and display only; ordering across imports cannot affect the
    /// deterministic candidate ordering.
    pub fn import_bytes(&mut self, filename: &str, bytes: &[u8]) -> rusqlite::Result<Imported> {
        let digest = hex_oid(&sha256_bytes(bytes));
        if let Some((id, _)) = self.store.source_by_sha(&digest)? {
            let kind: String = self
                .store
                .conn
                .query_row("SELECT kind FROM sources WHERE id=?1", params![id], |r| {
                    r.get(0)
                })?;
            return Ok(Imported {
                source_id: id,
                duplicate: true,
                kind,
                affected: 0,
                recomputed: 0,
            });
        }
        let (kind, import_result) = import::sniff_and_store(self, filename, bytes, &digest)?;
        let source_id = import_result.source_id;
        // Match indexes <-> packs and cross-check CRCs / anchors.
        self.reconcile_all();
        // Assign object ids to newly resolved deltas, then localized recompute.
        let recomputed = self.resolve_all()?;
        if recomputed > 0 {
            let cur: i64 = self.store.kv_get("recompute_events")?.parse().unwrap_or(0);
            self.store
                .kv_set("recompute_events", &(cur + 1).to_string())?;
        }
        Ok(Imported {
            source_id,
            duplicate: false,
            kind,
            affected: import_result.affected,
            recomputed: recomputed.max(import_result.affected),
        })
    }

    pub fn import_file(&mut self, path: &Path) -> rusqlite::Result<Imported> {
        let filename = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "input".into());
        let bytes = std::fs::read(path).map_err(rusqlite::Error::from)?;
        self.import_bytes(&filename, &bytes)
    }

    /// Retry paused resolutions after budgets were raised (or the expanded
    /// counter was reset). Only previously paused subgraphs are recomputed.
    pub fn retry_paused(&mut self) -> rusqlite::Result<i64> {
        let paused: Vec<(i64, i64)> = {
            let mut stmt = self
                .store
                .conn
                .prepare("SELECT candidate_id, branch_id FROM resolutions WHERE status='paused'")
                .unwrap();
            stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };
        let by_branch: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
            std::collections::HashMap::new();
        let mut by_branch = by_branch;
        for (c, b) in paused {
            by_branch.entry(b).or_default().insert(c);
        }
        let mut total = 0i64;
        for (branch, set) in by_branch {
            total += self.recompute_branch_subset(branch, set)?;
        }
        self.bump_recompute(total)?;
        Ok(total)
    }
}

/// Re-exported helpers used by sibling engine modules.
pub(crate) use helpers::*;
mod helpers {
    pub use crate::gitio::{hex_oid, parse_hex_oid, sha1_bytes, ObjType};
    pub use rusqlite::params;
}
