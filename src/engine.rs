//! Application orchestration: import, resolve, branches, pins, deletion.

use crate::error::{AppError, AppResult};
use crate::importer::import_file;
use crate::resolver::{
    affected_subgraph, run_branch, RunOptions, RunReport,
};
use crate::store::{ensure_default_branch, Store};
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Engine {
    pub store: Store,
    pub inner: Arc<Mutex<Connection>>,
}

impl Engine {
    pub fn data_dir_path(&self) -> std::path::PathBuf {
        self.store.data_dir.clone()
    }

    pub fn new(data_dir: &std::path::Path) -> AppResult<Engine> {
        let (conn, store) = Store::open(data_dir)?;
        ensure_default_branch(&conn)?;
        Ok(Engine {
            store,
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn import(&self, file_name: &str, data: Vec<u8>) -> AppResult<serde_json::Value> {
        let mut conn = self.inner.lock().await;
        let imp = import_file(&mut conn, &self.store, file_name, data)?;
        let seeds = crate::resolver::seed_oids_for_sources(&conn, &[imp.source_id])?;
        drop(conn);
        self.rerun_affected(seeds).await
    }

    async fn rerun_affected(&self, seeds: HashSet<String>) -> AppResult<serde_json::Value> {
        let mut conn = self.inner.lock().await;
        let branches = list_branch_ids(&conn)?;
        let mut reports = Vec::new();
        for bid in branches {
            let affected = affected_subgraph(&conn, &seeds)?;
            let report = run_branch(
                &mut conn,
                self.store.clone(),
                bid,
                &RunOptions::default(),
                Some(&affected),
                false,
            )?;
            reports.push(serde_json::json!({
                "branch_id": bid,
                "run_seq": report.run_seq,
                "complete": report.complete,
                "blocked": report.blocked,
                "paused": report.paused,
                "bad": report.bad,
                "pause_reason": report.pause_reason,
                "recomputed": affected.len(),
            }));
        }
        Ok(serde_json::json!({ "reports": reports }))
    }

    pub async fn resume(
        &self,
        branch: &str,
        add_bytes: i64,
        add_depth: i64,
        add_ratio: i64,
    ) -> AppResult<RunReport> {
        let mut conn = self.inner.lock().await;
        let bid = branch_id(&conn, branch)?;
        run_branch(
            &mut conn,
            self.store.clone(),
            bid,
            &RunOptions {
                add_bytes,
                add_depth,
                add_ratio,
            },
            None,
            false,
        )
    }

    pub async fn rerun_all(&self, branch: &str) -> AppResult<RunReport> {
        let mut conn = self.inner.lock().await;
        let bid = branch_id(&conn, branch)?;
        run_branch(
            &mut conn,
            self.store.clone(),
            bid,
            &RunOptions::default(),
            None,
            true,
        )
    }

    pub async fn create_branch(&self, name: &str) -> AppResult<i64> {
        let mut conn = self.inner.lock().await;
        let seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(created_seq),0)+1 FROM branches",
            [],
            |r| r.get(0),
        )?;
        conn.execute(
            "INSERT INTO branches(name, created_seq, depth_limit, byte_budget, ratio_limit)
             VALUES(?1,?2,16,16*1024*1024,32)",
            params![name, seq],
        )?;
        let bid = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO budget(branch_id, depth_limit, byte_budget, ratio_limit)
             VALUES(?1,16,16*1024*1024,32)",
            params![bid],
        )?;
        drop(conn);
        let _report = self.rerun_branch_full(bid).await?;
        Ok(bid)
    }

    async fn rerun_branch_full(&self, bid: i64) -> AppResult<RunReport> {
        let mut conn = self.inner.lock().await;
        run_branch(
            &mut conn,
            self.store.clone(),
            bid,
            &RunOptions::default(),
            None,
            true,
        )
    }

    pub async fn pin(&self, branch: &str, oid: &str, candidate_id: i64) -> AppResult<()> {
        let mut conn = self.inner.lock().await;
        let bid = branch_id(&conn, branch)?;
        let owns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM candidates WHERE id=?1 AND oid=?2",
            params![candidate_id, oid],
            |r| r.get(0),
        )?;
        if owns == 0 {
            return Err(AppError::Conflict(
                "candidate does not provide that oid".into(),
            ));
        }
        conn.execute(
            "INSERT INTO pins(branch_id, oid, candidate_id) VALUES(?1,?2,?3)
             ON CONFLICT(branch_id, oid) DO UPDATE SET candidate_id=excluded.candidate_id",
            params![bid, oid, candidate_id],
        )?;
        drop(conn);
        let mut seeds = HashSet::new();
        seeds.insert(oid.to_string());
        self.rerun_affected(seeds).await?;
        Ok(())
    }

    pub async fn unpin(&self, branch: &str, oid: &str) -> AppResult<()> {
        let mut conn = self.inner.lock().await;
        let bid = branch_id(&conn, branch)?;
        conn.execute(
            "DELETE FROM pins WHERE branch_id=?1 AND oid=?2",
            params![bid, oid],
        )?;
        drop(conn);
        let mut seeds = HashSet::new();
        seeds.insert(oid.to_string());
        self.rerun_affected(seeds).await?;
        Ok(())
    }

    /// Objects (resolved statuses) that currently trace back to a source.
    pub async fn deletion_dependents(&self, source_id: i64) -> AppResult<serde_json::Value> {
        let list = {
            let conn = self.inner.lock().await;
            let seeds: HashSet<String> = {
                let mut sel = conn.prepare(
                    "SELECT DISTINCT oid FROM candidates
                     WHERE source_id=?1 AND oid IS NOT NULL",
                )?;
                let rows = sel
                    .query_map(params![source_id], |r| r.get::<_, String>(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                rows
            };
            let affected = affected_subgraph(&conn, &seeds)?;
            let mut list = Vec::new();
            for oid in &affected {
                let mut stmt = conn.prepare(
                    "SELECT b.name, COALESCE(r.status,'absent')
                     FROM branches b LEFT JOIN resolved r
                       ON r.branch_id=b.id AND r.oid=?1",
                )?;
                let states: Vec<(String, String)> = stmt
                    .query_map(params![oid], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                list.push(serde_json::json!({ "oid": oid, "branches": states }));
            }
            list
        };
        Ok(serde_json::json!({
            "source_id": source_id,
            "affected": list,
            "count": list.len(),
        }))
    }

    pub async fn delete_source(&self, source_id: i64, force: bool) -> AppResult<serde_json::Value> {
        if !force {
            return Err(AppError::Conflict(
                "refuse without force; inspect dependents first".into(),
            ));
        }
        let seeds = {
            let mut conn = self.inner.lock().await;
            let existed: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )?;
            if existed == 0 {
                return Err(AppError::NotFound(format!("source {source_id}")));
            }
            let seeds: HashSet<String> = {
                let mut sel = conn.prepare(
                    "SELECT DISTINCT oid FROM candidates
                     WHERE source_id=?1 AND oid IS NOT NULL",
                )?;
                let rows = sel
                    .query_map(params![source_id], |r| r.get::<_, String>(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                rows
            };
            let stored: Option<String> = conn
                .query_row(
                    "SELECT stored_path FROM sources WHERE id=?1",
                    params![source_id],
                    |r| r.get(0),
                )
                .ok();
            conn.execute("DELETE FROM sources WHERE id=?1", params![source_id])?;
            let orphans: Vec<String> = {
                let mut os = conn.prepare(
                    "SELECT r.oid FROM resolved r
                     WHERE NOT EXISTS (SELECT 1 FROM candidates c WHERE c.oid=r.oid)
                     GROUP BY r.oid",
                )?;
                let rows = os
                    .query_map([], |r| r.get::<_, String>(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                rows
            };
            for oid in &orphans {
                conn.execute("DELETE FROM resolved WHERE oid=?1", params![oid])?;
                conn.execute("DELETE FROM blockers WHERE oid=?1", params![oid])?;
                conn.execute("DELETE FROM delta_steps WHERE oid=?1", params![oid])?;
            }
            if let Some(rel) = stored {
                let _ = std::fs::remove_file(self.store.data_dir.join(&rel));
            }
            seeds
        };
        self.rerun_affected(seeds).await
    }
}

pub fn list_branch_ids(conn: &Connection) -> AppResult<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT id FROM branches ORDER BY id")?;
    let v = stmt
        .query_map([], |r| r.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(v)
}

pub fn branch_id(conn: &Connection, name: &str) -> AppResult<i64> {
    conn.query_row("SELECT id FROM branches WHERE name=?1", params![name], |r| {
        r.get(0)
    })
    .map_err(|_| AppError::NotFound(format!("branch {name}")))
}
