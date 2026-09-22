//! Application facade: import pipeline, incremental recomputation, branches.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::params;

use crate::engine::Engine;
use crate::git::git_oid;
use crate::import::{parse_idx, parse_loose, parse_pack, persist_loose, persist_pack};
use crate::model::{Budget, DependencyInfo, SourceInfo};
use crate::store::{sha256_hex, Store, DEFAULT_BRANCH};

pub struct AppState {
    pub store: Mutex<Store>,
    pub data_dir: PathBuf,
    pub budget: Mutex<Budget>,
}

#[derive(Debug, Clone)]
pub enum FileKind {
    Loose,
    Pack,
    Idx,
    Unknown,
}

pub fn classify(name: &str, bytes: &[u8]) -> FileKind {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pack") || bytes.starts_with(b"PACK") {
        return FileKind::Pack;
    }
    if lower.ends_with(".idx") || bytes.starts_with(b"\xfftOc") {
        return FileKind::Idx;
    }
    // loose: zlib stream starts with 0x78
    if bytes.first() == Some(&0x78) {
        return FileKind::Loose;
    }
    FileKind::Unknown
}

impl AppState {
    pub fn open(root: &Path) -> std::io::Result<Self> {
        let store = Store::open(root)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(AppState {
            store: Mutex::new(store),
            data_dir: root.to_path_buf(),
            budget: Mutex::new(Budget::default()),
        })
    }

    pub fn budget(&self) -> Budget {
        *self.budget.lock().unwrap()
    }

    pub fn set_budget(&self, b: Budget) {
        *self.budget.lock().unwrap() = b;
    }

    /// Store a raw uploaded/imported file under the data directory.
    pub fn save_raw(&self, original: &str, bytes: &[u8]) -> std::io::Result<(String, String)> {
        let sha = sha256_hex(bytes);
        let ext = match classify(original, bytes) {
            FileKind::Pack => ".pack",
            FileKind::Idx => ".idx",
            _ => "",
        };
        let safe: String = original
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
            .collect();
        let rel = format!("raw/{safe}.{sha}{ext}");
        let path = self.data_dir.join(&rel);
        std::fs::create_dir_all(path.parent().unwrap())?;
        if !path.exists() {
            std::fs::write(&path, bytes)?;
        }
        Ok((rel, sha))
    }

    /// Import one file. Triggers default-branch incremental recomputation for
    /// exactly the dependency subgraph the new data can affect.
    pub fn import_file(&self, name: &str, bytes: &[u8]) -> Result<ImportReport, String> {
        let (rel, sha) = self.save_raw(name, bytes).map_err(|e| e.to_string())?;
        let mut store = self.store.lock().unwrap();
        let tx = store
            .db
            .transaction()
            .map_err(|e| e.to_string())?;
        // rusqlite Transaction derefs to Connection; re-wrap store for helpers
        // by operating on store directly (no explicit tx needed for our scale):
        drop(tx);

        let kind = classify(name, bytes);
        let before = entry_ids(&store).map_err(|e| e.to_string())?;
        let source_id;
        match kind {
            FileKind::Pack => {
                let parsed = parse_pack(bytes)?;
                let sid = store
                    .insert_source(
                        crate::model::SourceKind::Pack,
                        name,
                        &rel,
                        bytes.len() as i64,
                        &sha,
                        Some(&parsed.trailer_sha),
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                persist_pack(&store, sid, &parsed).map_err(|e| e.to_string())?;
                store
                    .set_source_meta(sid, None, Some(parsed.checksum_ok), None, None)
                    .map_err(|e| e.to_string())?;
                source_id = sid;
            }
            FileKind::Idx => {
                let parsed = parse_idx(bytes);
                let (pack_sha, note) = match &parsed {
                    Ok(p) => (Some(p.pack_sha.clone()), None),
                    Err(e) => (None, Some(e.clone())),
                };
                let sid = store
                    .insert_source(
                        crate::model::SourceKind::Idx,
                        name,
                        &rel,
                        bytes.len() as i64,
                        &sha,
                        pack_sha.as_deref(),
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                if let Some(msg) = note {
                    store
                        .set_source_meta(sid, Some(false), None, Some(&msg), None)
                        .map_err(|e| e.to_string())?;
                }
                source_id = sid;
            }
            FileKind::Loose => {
                let claimed = infer_loose_oid(name);
                let parsed = parse_loose(bytes);
                let sid = store
                    .insert_source(
                        crate::model::SourceKind::Loose,
                        name,
                        &rel,
                        bytes.len() as i64,
                        &sha,
                        None,
                        None,
                    )
                    .map_err(|e| e.to_string())?;
                persist_loose(&store, sid, claimed.as_deref(), parsed, bytes.len() as u64)
                    .map_err(|e| e.to_string())?;
                source_id = sid;
            }
            FileKind::Unknown => {
                return Err(format!("{name}: unrecognized file (not pack/idx/loose zlib)"))
            }
        }

        // Re-link idx<->pack after every import (idempotent).
        relink_sync(&store).map_err(|e| e.to_string())?;

        // Dependency subgraph affected by new entries (and any ref edges whose
        // provider choice may now change).
        let after = entry_ids(&store).map_err(|e| e.to_string())?;
        let mut affected: BTreeSet<i64> = after.difference(&before).copied().collect();
        // Any ref-delta whose base is now newly satisfiable / re-ranked.
        let new_oids = oids_claimed_by(&store, source_id).map_err(|e| e.to_string())?;
        if !new_oids.is_empty() {
            let mut stmt = store
                .db
                .prepare("SELECT id FROM entries WHERE delta='ref-delta' AND base_oid IN rarray")
                .ok();
            drop(stmt); // rarray unavailable; do it in Rust
            let mut es = store
                .db
                .prepare("SELECT id,base_oid FROM entries WHERE delta='ref-delta'")
                .map_err(|e| e.to_string())?;
            let rows = es
                .query_map([], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
                })
                .map_err(|e| e.to_string())?;
            for r in rows {
                let (id, oid) = r.map_err(|e| e.to_string())?;
                if let Some(o) = oid {
                    if new_oids.contains(&o) {
                        affected.insert(id);
                    }
                }
            }
        }

        let budget = *self.budget.lock().unwrap();
        let mut eng = Engine::new(&store, DEFAULT_BRANCH, budget, 0);
        let report = eng
            .resolve(&format!("import:{name}"), Some(&affected), budget)
            .map_err(|e| e.to_string())?;
        Ok(ImportReport {
            source_id,
            kind: match kind {
                FileKind::Pack => "pack",
                FileKind::Idx => "idx",
                FileKind::Loose => "loose",
                FileKind::Unknown => "unknown",
            }
            .to_string(),
            run: report,
        })
    }

    /// Retry paused entries using current budget (bounded resume).
    pub fn retry(&self) -> Result<crate::engine::RunReport, String> {
        let store = self.store.lock().unwrap();
        let budget = *self.budget.lock().unwrap();
        let mut ids: BTreeSet<i64> = BTreeSet::new();
        let mut stmt = store
            .db
            .prepare("SELECT entry_id FROM resolutions WHERE branch='default' AND status='paused'")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())?;
        for r in rows {
            ids.insert(r.map_err(|e| e.to_string())?);
        }
        let mut eng = Engine::new(&store, DEFAULT_BRANCH, budget, 0);
        eng.resolve("retry", Some(&ids), budget)
            .map_err(|e| e.to_string())
    }
}

fn relink_sync(store: &Store) -> rusqlite::Result<()> {
    crate::import::relink(store)
}

pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub run: crate::engine::RunReport,
}

fn entry_ids(store: &Store) -> rusqlite::Result<BTreeSet<i64>> {
    let mut s = store.db.prepare("SELECT id FROM entries")?;
    let rows = s.query_map([], |r| r.get::<_, i64>(0))?;
    let mut out = BTreeSet::new();
    for r in rows {
        out.insert(r?);
    }
    Ok(out)
}

fn oids_claimed_by(store: &Store, source_id: i64) -> rusqlite::Result<BTreeSet<String>> {
    let mut s = store
        .db
        .prepare("SELECT DISTINCT claimed_oid FROM entries WHERE source_id=?1 AND claimed_oid IS NOT NULL")?;
    let rows = s.query_map(params![source_id], |r| r.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for r in rows {
        out.insert(r?);
    }
    Ok(out)
}

fn infer_loose_oid(name: &str) -> Option<String> {
    // Accept either "<oid>", "<oid>.zlib" or a path ending in
    // "<2-hex>/<38-hex>".
    let stem = name.rsplit('/').next().unwrap_or(name);
    let stem = stem.strip_suffix(".zlib").unwrap_or(stem);
    let stem = stem.strip_suffix(".loose").unwrap_or(stem);
    let compact: String = stem.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() == 40 {
        return Some(compact);
    }
    if let Some((p, f)) = name.rsplit_once('/') {
        let pp: String = p.rsplit('/').next().unwrap_or(p).chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let ff: String = f.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let joined = format!("{pp}{ff}");
        if joined.len() == 40 {
            return Some(joined);
        }
    }
    None
}

impl AppState {
    pub fn list_sources(&self) -> Result<Vec<SourceInfo>, String> {
        let store = self.store.lock().unwrap();
        let mut s = store
            .db
            .prepare(
                "SELECT s.id,s.name,s.kind,s.size,s.sha256,COALESCE(s.pack_sha,''),
                        (SELECT COUNT(*) FROM entries e WHERE e.source_id=s.id)
                 FROM sources s ORDER BY s.imported_seq",
            )
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([], |r| {
                Ok(SourceInfo {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    kind: r.get(2)?,
                    size: r.get(3)?,
                    sha256: r.get(4)?,
                    pack_sha: Some(r.get::<_, String>(5)?).filter(|x| !x.is_empty()),
                    entries: r.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// Objects that currently depend (directly or transitively, in any branch)
    /// on entries contributed by this source. Shown before a delete.
    pub fn dependents_of_source(&self, source_id: i64) -> Result<Vec<DependencyInfo>, String> {
        let store = self.store.lock().unwrap();
        let seed: Vec<i64> = {
            let mut s = store
                .db
                .prepare("SELECT id FROM entries WHERE source_id=?1")
                .map_err(|e| e.to_string())?;
            let rows = s
                .query_map(params![source_id], |r| r.get::<_, i64>(0))
                .map_err(|e| e.to_string())?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| e.to_string())?);
            }
            v
        };
        let mut edges: BTreeSet<(i64, i64)> = BTreeSet::new();
        {
            let mut s = store
                .db
                .prepare("SELECT id,base_entry_id FROM entries WHERE base_entry_id IS NOT NULL")
                .map_err(|e| e.to_string())?;
            let rows = s
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| e.to_string())?;
            for r in rows {
                let (c, b) = r.map_err(|e| e.to_string())?;
                edges.insert((c, b));
            }
        }
        // reverse reachability from seeds
        let mut dep: BTreeSet<i64> = seed.iter().copied().collect();
        let mut stack = seed.clone();
        while let Some(x) = stack.pop() {
            for (c, b) in &edges {
                if *b == x && dep.insert(*c) {
                    stack.push(*c);
                }
            }
        }

        let mut out = Vec::new();
        for id in dep {
            if let Ok(row) = store.db.query_row(
                "SELECT e.source_id,s.name,e.offset,e.type_name,
                        COALESCE((SELECT r.status FROM resolutions r
                                  WHERE r.branch='default' AND r.entry_id=e.id),'unresolved')
                 FROM entries e JOIN sources s ON s.id=e.source_id
                 WHERE e.id=?1",
                params![id],
                |r| {
                    Ok(DependencyInfo {
                        entry_id: id,
                        source_id: r.get(0)?,
                        source_name: r.get(1)?,
                        offset: r.get(2)?,
                        kind: r.get(3)?,
                        status: r.get(4)?,
                    })
                },
            ) {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Delete source after the caller has acknowledged dependencies. Cascades
    /// to entries; then recomputes everything that depended on it.
    pub fn delete_source(&self, source_id: i64) -> Result<usize, String> {
        let deps = self.dependents_of_source(source_id)?;
        let affected: BTreeSet<i64> = deps.iter().map(|d| d.entry_id).collect();
        {
            let store = self.store.lock().unwrap();
            // remove raw + inflated payload files
            let rel: String = store
                .db
                .query_row("SELECT path FROM sources WHERE id=?1", params![source_id], |r| {
                    r.get(0)
                })
                .map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(store.data_dir.join(&rel));
            let mut es = store
                .db
                .prepare("SELECT id FROM entries WHERE source_id=?1")
                .map_err(|e| e.to_string())?;
            let ids = es
                .query_map(params![source_id], |r| r.get::<_, i64>(0))
                .map_err(|e| e.to_string())?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?;
            for id in ids {
                let _ = std::fs::remove_file(store.data_dir.join(format!("inflated/s{source_id}_e{id}")));
            }
            store
                .db
                .execute("DELETE FROM sources WHERE id=?1", params![source_id])
                .map_err(|e| e.to_string())?;
            crate::import::relink(&store).map_err(|e| e.to_string())?;
        }
        let store = self.store.lock().unwrap();
        // drop resolutions whose entry vanished
        store
            .db
            .execute("DELETE FROM resolutions WHERE entry_id NOT IN (SELECT id FROM entries)", [])
            .map_err(|e| e.to_string())?;
        let budget = *self.budget.lock().unwrap();
        let mut eng = Engine::new(&store, DEFAULT_BRANCH, budget, 0);
        eng.resolve(&format!("delete-source:{source_id}"), Some(&affected), budget)
            .map_err(|e| e.to_string())?;
        Ok(affected.len())
    }

    /// Fix the provider of `oid` to a specific entry, forming an analysis
    /// branch. Recomputes only the subtree affected by this pin.
    pub fn pin_branch(&self, branch: &str, oid: &str, entry_id: i64) -> Result<(), String> {
        let store = self.store.lock().unwrap();
        store
            .db
            .execute("INSERT OR IGNORE INTO branches(name) VALUES(?1)", params![branch])
            .map_err(|e| e.to_string())?;
        let bid: i64 = store
            .db
            .query_row("SELECT id FROM branches WHERE name=?1", params![branch], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        // clone current default resolutions for the branch baseline if new
        let count: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM resolutions WHERE branch=?1", params![branch], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        if count == 0 {
            store
                .db
                .execute(
                    "INSERT INTO resolutions(branch,entry_id,status,kind,content_path,content_len,
                        actual_oid,oid_ok,depth,bytes,error,blockers,steps,budget_json,run_seq)
                     SELECT ?1,entry_id,status,kind,content_path,content_len,actual_oid,oid_ok,
                            depth,bytes,error,blockers,steps,budget_json,run_seq FROM resolutions
                     WHERE branch='default'",
                    params![branch],
                )
                .map_err(|e| e.to_string())?;
        }
        store
            .db
            .execute(
                "INSERT INTO branch_pins(branch_id,oid,entry_id) VALUES(?1,?2,?3)
                 ON CONFLICT(branch_id,oid) DO UPDATE SET entry_id=excluded.entry_id",
                params![bid, oid, entry_id],
            )
            .map_err(|e| e.to_string())?;
        // affected subtree: entry_id and all dependents (within this branch)
        let mut affected: BTreeSet<i64> = BTreeSet::new();
        affected.insert(entry_id);
        let budget = *self.budget.lock().unwrap();
        let mut eng = Engine::new(&store, branch, budget, 0);
        // force the pinned oid consumers too
        eng.load().map_err(|e| e.to_string())?;
        for (id, n) in &eng.nodes {
            if n.row.base_oid.as_deref() == Some(oid) {
                affected.insert(*id);
            }
        }
        eng.resolve(&format!("pin:{oid}"), Some(&affected), budget)
            .map_err(|e| e.to_string())?;
        let _ = git_oid;
        Ok(())
    }

    pub fn branches(&self) -> Result<Vec<(i64, String)>, String> {
        let store = self.store.lock().unwrap();
        let mut s = store
            .db
            .prepare("SELECT id,name FROM branches ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        let mut v = Vec::new();
        for r in rows {
            v.push(r.map_err(|e| e.to_string())?);
        }
        Ok(v)
    }
}
