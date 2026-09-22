//! SQLite persistence and data-directory file storage.

use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

use crate::model::SourceKind;

pub const DEFAULT_BRANCH: &str = "default";

#[derive(Clone, Debug)]
pub struct EntryRow {
    pub id: i64,
    pub source_id: i64,
    pub offset: Option<i64>,
    pub type_code: Option<i64>,
    pub type_name: Option<String>,
    pub delta: Option<String>, // "ofs-delta" | "ref-delta"
    pub base_oid: Option<String>,
    pub base_offset: Option<i64>,
    pub base_entry_id: Option<i64>,
    pub declared_size: Option<i64>,
    pub inflated_size: Option<i64>,
    pub z_off: Option<i64>,
    pub z_len: Option<i64>,
    pub claimed_oid: Option<String>,
    pub parse_err: Option<String>, // JSON ResolveError
    pub sha256: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    // sha2 of raw payload for content summary naming
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub struct Store {
    pub db: Connection,
    pub data_dir: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(root.join("files")).ok();
        std::fs::create_dir_all(root.join("tmp")).ok();
        let db = Connection::open(root.join("microscope.db"))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        let mut s = Store {
            db,
            data_dir: root.to_path_buf(),
        };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&mut self) -> rusqlite::Result<()> {
        self.db.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,                 -- loose|pack|idx
                name TEXT NOT NULL,
                path TEXT NOT NULL,                 -- relative to data dir
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                imported_seq INTEGER NOT NULL,      -- import order; ordering must not affect ranks
                pack_sha TEXT,                      -- 40 hex pack checksum/name token
                idx_sha TEXT,
                idx_ok INTEGER,                     -- idx paired & structurally valid
                pack_checksum_ok INTEGER,
                note TEXT
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                offset INTEGER,                     -- byte offset inside pack
                type_code INTEGER,
                type_name TEXT,
                delta TEXT,
                base_oid TEXT,
                base_offset INTEGER,
                base_entry_id INTEGER,
                declared_size INTEGER,
                inflated_size INTEGER,
                z_off INTEGER,
                z_len INTEGER,
                claimed_oid TEXT,
                parse_err TEXT,
                sha256 TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
            CREATE INDEX IF NOT EXISTS idx_entries_claimed ON entries(claimed_oid);
            CREATE INDEX IF NOT EXISTS idx_entries_base ON entries(base_entry_id);

            CREATE TABLE IF NOT EXISTS branches (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                note TEXT
            );

            CREATE TABLE IF NOT EXISTS branch_pins (
                branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
                oid TEXT NOT NULL,
                entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                PRIMARY KEY (branch_id, oid)
            );

            CREATE TABLE IF NOT EXISTS resolutions (
                branch TEXT NOT NULL,
                entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                status TEXT NOT NULL,               -- ok|paused|error|missing|cycle
                kind TEXT,
                content_path TEXT,
                content_len INTEGER,
                actual_oid TEXT,
                oid_ok INTEGER,
                depth INTEGER,
                bytes INTEGER,
                error TEXT,                         -- JSON ResolveError
                blockers TEXT,                      -- JSON Vec<Blocker>
                steps TEXT,                         -- JSON Vec<StepRec>
                budget_json TEXT,
                run_seq INTEGER NOT NULL,
                reused INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (branch, entry_id)
            );

            CREATE INDEX IF NOT EXISTS idx_res_oid ON resolutions(actual_oid);
            CREATE INDEX IF NOT EXISTS idx_res_status ON resolutions(status);

            CREATE TABLE IF NOT EXISTS fanout (
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
                bucket INTEGER NOT NULL,
                cumulative INTEGER NOT NULL,
                PRIMARY KEY (source_id, bucket)
            );

            CREATE TABLE IF NOT EXISTS idx_crc (
                source_id INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                expected INTEGER NOT NULL,
                actual INTEGER NOT NULL,
                ok INTEGER NOT NULL,
                PRIMARY KEY (source_id, offset)
            );

            CREATE TABLE IF NOT EXISTS runs (
                seq INTEGER PRIMARY KEY,
                reason TEXT,
                budget_json TEXT,
                total_bytes INTEGER,
                paused INTEGER,
                created_at TEXT DEFAULT (datetime('now'))
            );
            "#,
        )?;
        self.db.execute(
            "INSERT OR IGNORE INTO branches(id,name,note) VALUES (1,?1,'默认分析分支')",
            params![DEFAULT_BRANCH],
        )?;
        Ok(())
    }

    pub fn next_run_seq(&self) -> rusqlite::Result<i64> {
        self.db.query_row(
            "SELECT COALESCE(MAX(seq),0)+1 FROM runs",
            [],
            |r| r.get::<_, i64>(0),
        )
    }

    pub fn insert_run(&self, reason: &str, budget: &str, total: i64, paused: bool) -> rusqlite::Result<i64> {
        self.db.execute(
            "INSERT INTO runs(reason,budget_json,total_bytes,paused) VALUES(?1,?2,?3,?4)",
            params![reason, budget, total, paused as i64],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn insert_source(
        &self,
        kind: SourceKind,
        name: &str,
        rel_path: &str,
        size: i64,
        sha: &str,
        pack_sha: Option<&str>,
        idx_sha: Option<&str>,
    ) -> rusqlite::Result<i64> {
        let seq: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(imported_seq),0)+1 FROM sources", [], |r| {
                r.get(0)
            })?;
        self.db.execute(
            "INSERT INTO sources(kind,name,path,size,sha256,imported_seq,pack_sha,idx_sha)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![kind.as_str(), name, rel_path, size, sha, seq, pack_sha, idx_sha],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn set_source_meta(
        &self,
        id: i64,
        idx_ok: Option<bool>,
        pack_ok: Option<bool>,
        note: Option<&str>,
        pack_sha: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE sources SET
                idx_ok = COALESCE(?2, idx_ok),
                pack_checksum_ok = COALESCE(?3, pack_checksum_ok),
                note = COALESCE(?4, note),
                pack_sha = COALESCE(?5, pack_sha)
             WHERE id=?1",
            params![id, idx_ok, pack_ok, note, pack_sha],
        )?;
        Ok(())
    }

    pub fn insert_entry(&self, e: &NewEntry) -> rusqlite::Result<i64> {
        self.db.execute(
            "INSERT INTO entries(source_id,offset,type_code,type_name,delta,base_oid,base_offset,
                declared_size,inflated_size,z_off,z_len,claimed_oid,parse_err,sha256)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                e.source_id,
                e.offset,
                e.type_code,
                e.type_name,
                e.delta,
                e.base_oid,
                e.base_offset,
                e.declared_size,
                e.inflated_size,
                e.z_off,
                e.z_len,
                e.claimed_oid,
                e.parse_err,
                e.sha256,
            ],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn set_base_entry(&self, entry_id: i64, base_entry_id: Option<i64>) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE entries SET base_entry_id=?2 WHERE id=?1",
            params![entry_id, base_entry_id],
        )?;
        Ok(())
    }

    pub fn replace_fanout(&self, source_id: i64, f: &[(i64, i64)]) -> rusqlite::Result<()> {
        self.db.execute(
            "DELETE FROM fanout WHERE source_id=?1",
            params![source_id],
        )?;
        {
            let mut st = self
                .db
                .prepare("INSERT INTO fanout(source_id,bucket,cumulative) VALUES(?1,?2,?3)")?;
            for (b, c) in f {
                st.execute(params![source_id, b, c])?;
            }
        }
        Ok(())
    }

    pub fn replace_crc(&self, source_id: i64, rows: &[(i64, u32, u32, bool)]) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM idx_crc WHERE source_id=?1", params![source_id])?;
        let mut st = self.db.prepare(
            "INSERT INTO idx_crc(source_id,offset,expected,actual,ok) VALUES(?1,?2,?3,?4,?5)",
        )?;
        for (off, exp, act, ok) in rows {
            st.execute(params![source_id, off, *exp as i64, *act as i64, ok])?;
        }
        Ok(())
    }

    pub fn files_dir(&self) -> PathBuf {
        self.data_dir.join("files")
    }

    /// Persist reconstructed content; returns relative path.
    pub fn write_content(&self, entry_id: i64, run_seq: i64, data: &[u8]) -> std::io::Result<String> {
        let dir = self.files_dir().join("resolved");
        std::fs::create_dir_all(&dir)?;
        let rel = format!("resolved/e{entry_id}_r{run_seq}");
        std::fs::write(self.data_dir.join(&rel), data)?;
        Ok(rel)
    }

    pub fn read_content(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.data_dir.join(rel))
    }
}

#[derive(Default, Debug)]
pub struct NewEntry {
    pub source_id: i64,
    pub offset: Option<i64>,
    pub type_code: Option<i64>,
    pub type_name: Option<String>,
    pub delta: Option<String>,
    pub base_oid: Option<String>,
    pub base_offset: Option<i64>,
    pub base_entry_id: Option<i64>,
    pub declared_size: Option<i64>,
    pub inflated_size: Option<i64>,
    pub z_off: Option<i64>,
    pub z_len: Option<i64>,
    pub claimed_oid: Option<String>,
    pub parse_err: Option<String>,
    pub sha256: String,
}
