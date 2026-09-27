//! SQLite 持久层。所有导入内容（原始字节、解析结果、分支状态、delta 步骤）都在
//! `--data-dir`（默认 `./data`）内，不向项目其他位置写输入。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{Budget, BudgetUse};
use crate::git::idx::IdxFile;
use crate::git::loose::LooseObject;
use crate::git::parse_pack::PackFile;
use crate::Oid;

pub const KIND_PACK: &str = "pack";
pub const KIND_IDX: &str = "idx";
pub const KIND_LOOSE: &str = "loose";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub parse_error: Option<String>,
    /// loose 对象文件名中声明的 oid。
    pub claimed_oid: Option<String>,
}

pub struct Store {
    pub db: Connection,
}

pub fn schema() -> &'static str {
    r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    claimed_oid TEXT,
    raw BLOB NOT NULL,
    parse_error TEXT,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packs (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
    pack_sha TEXT NOT NULL,
    version INTEGER NOT NULL,
    object_count INTEGER NOT NULL,
    trailer_oid TEXT NOT NULL,
    trailer_offset INTEGER NOT NULL,
    trailer_ok INTEGER NOT NULL,
    trailing_garbage INTEGER NOT NULL,
    pack_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pack_objects (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    next_offset INTEGER NOT NULL,
    data_offset INTEGER NOT NULL,
    kind TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    ofs_negative INTEGER,
    ref_base TEXT,
    crc32 INTEGER NOT NULL,
    entry_len INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    payload BLOB NOT NULL,
    idx_oid TEXT,
    idx_crc_ok INTEGER,
    UNIQUE(source_id, offset)
);
CREATE TABLE IF NOT EXISTS loose_objects (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
    object_type TEXT NOT NULL,
    declared_size INTEGER NOT NULL,
    computed_oid TEXT NOT NULL,
    oid_ok INTEGER NOT NULL,
    body BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS indexes (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
    pack_source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
    pack_checksum TEXT NOT NULL,
    pack_checksum_ok INTEGER NOT NULL,
    idx_checksum_ok INTEGER NOT NULL,
    object_count INTEGER NOT NULL,
    fanout_json TEXT NOT NULL,
    idx_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    parent_branch TEXT,
    budget_json TEXT NOT NULL,
    used_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS branch_pins (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    offset INTEGER,
    PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS branch_nodes (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    depth INTEGER,
    resolved_oid TEXT,
    object_type TEXT,
    size INTEGER,
    content BLOB,
    input_weight INTEGER,
    paused_json TEXT,
    blocking_json TEXT,
    oid_ok INTEGER,
    idx_claim_ok INTEGER,
    recompute_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (branch_id, node_id)
);
CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    step INTEGER NOT NULL,
    base_node_id TEXT,
    base_oid TEXT,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    oid_ok INTEGER,
    UNIQUE(branch_id, node_id, step)
);
CREATE TABLE IF NOT EXISTS edges (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    from_node TEXT NOT NULL,
    to_node TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (branch_id, from_node, to_node)
);
CREATE INDEX IF NOT EXISTS idx_po_src ON pack_objects(source_id);
CREATE INDEX IF NOT EXISTS idx_bn_branch ON branch_nodes(branch_id);
CREATE INDEX IF NOT EXISTS idx_ds_branch ON delta_steps(branch_id, node_id);
CREATE INDEX IF NOT EXISTS idx_edges_branch ON edges(branch_id);
"#
}

impl Store {
    pub fn open(path: &std::path::Path) -> rusqlite::Result<Store> {
        let mut db = Connection::open(path)?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.execute_batch(schema())?;
        Ok(Store { db })
    }

    pub fn open_in_memory() -> rusqlite::Result<Store> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.execute_batch(schema())?;
        Ok(Store { db })
    }

    pub fn sha256(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        let d = h.finalize();
        let mut s = String::with_capacity(64);
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// 幂等导入：同 sha256 返回既有 id。
    pub fn insert_source_if_new(
        &mut self,
        kind: &str,
        filename: &str,
        raw: &[u8],
        claimed: Option<&Oid>,
    ) -> rusqlite::Result<(i64, bool)> {
        let sha = Store::sha256(raw);
        if let Some(id) = self
            .db
            .query_row("SELECT id FROM sources WHERE sha256=?1", params![sha], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
        {
            return Ok((id, false));
        }
        self.db.execute(
            "INSERT INTO sources(kind, filename, sha256, size, claimed_oid, raw)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                kind,
                filename,
                sha,
                raw.len() as i64,
                claimed.map(crate::git::oid::oid_to_hex),
                raw
            ],
        )?;
        let id = self.db.last_insert_rowid();
        Ok((id, true))
    }

    pub fn set_parse_error(&mut self, id: i64, err: &str) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE sources SET parse_error=?1 WHERE id=?2", params![err, id])?;
        Ok(())
    }

    pub fn insert_pack(&mut self, source_id: i64, pf: &PackFile) -> rusqlite::Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO packs(source_id, pack_sha, version, object_count, trailer_oid,
                 trailer_offset, trailer_ok, trailing_garbage, pack_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                source_id,
                crate::git::oid::oid_to_hex(&pf.trailer),
                pf.version,
                pf.count,
                crate::git::oid::oid_to_hex(&pf.trailer),
                pf.trailer_offset as i64,
                pf.trailer_ok as i64,
                pf.trailing_garbage as i64,
                serde_json::to_string(pf).unwrap()
            ],
        )?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO pack_objects(source_id, offset, next_offset, data_offset, kind,
                     declared_size, ofs_negative, ref_base, crc32, entry_len, outcome, payload)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            )?;
            for e in &pf.entries {
                stmt.execute(params![
                    source_id,
                    e.offset as i64,
                    e.next_offset as i64,
                    e.data_offset as i64,
                    e.kind.type_name(),
                    e.declared_size as i64,
                    e.ofs_negative.map(|v| v as i64),
                    e.ref_base.map(|o| crate::git::oid::oid_to_hex(&o)),
                    e.crc32 as i64,
                    e.entry_len as i64,
                    serde_json::to_string(&e.outcome).unwrap(),
                    e.payload,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_loose(&mut self, source_id: i64, lo: &LooseObject) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO loose_objects(source_id, object_type, declared_size, computed_oid,
                 oid_ok, body) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                source_id,
                lo.object_type,
                lo.declared_size as i64,
                crate::git::oid::oid_to_hex(&lo.computed_oid),
                lo.oid_ok as i64,
                lo.body
            ],
        )?;
        Ok(())
    }

    pub fn insert_index(
        &mut self,
        source_id: i64,
        pack_source_id: Option<i64>,
        ix: &IdxFile,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO indexes(source_id, pack_source_id, pack_checksum, pack_checksum_ok,
                 idx_checksum_ok, object_count, fanout_json, idx_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                source_id,
                pack_source_id,
                crate::git::oid::oid_to_hex(&ix.pack_checksum),
                ix.pack_checksum_ok as i64,
                ix.idx_checksum_ok as i64,
                ix.count,
                serde_json::to_string(&ix.fanout).unwrap(),
                serde_json::to_string(ix).unwrap()
            ],
        )?;
        Ok(())
    }

    pub fn list_sources(&mut self) -> rusqlite::Result<Vec<Source>> {
        let mut s = self.db.prepare(
            "SELECT id, kind, filename, sha256, size, parse_error, claimed_oid
             FROM sources ORDER BY id",
        )?;
        let rows = s
            .query_map([], |r| {
                Ok(Source {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    filename: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get(4)?,
                    parse_error: r.get(5)?,
                    claimed_oid: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn source_raw(&mut self, id: i64) -> rusqlite::Result<Option<Vec<u8>>> {
        self.db
            .query_row("SELECT raw FROM sources WHERE id=?1", params![id], |r| r.get::<_, Vec<u8>>(0))
            .optional()
    }

    pub fn delete_source(&mut self, id: i64) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM sources WHERE id=?1", params![id])?;
        Ok(())
    }

    // ---------- branches ----------

    pub fn ensure_branch(&mut self, name: &str, budget: &Budget) -> rusqlite::Result<i64> {
        if let Some(id) = self
            .db
            .query_row("SELECT id FROM branches WHERE name=?1", params![name], |r| r.get::<_, i64>(0))
            .optional()?
        {
            return Ok(id);
        }
        self.db.execute(
            "INSERT INTO branches(name, budget_json, used_json) VALUES(?1,?2,?3)",
            params![
                name,
                serde_json::to_string(budget).unwrap(),
                serde_json::to_string(&BudgetUse::default()).unwrap()
            ],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn list_branches(&mut self) -> rusqlite::Result<Vec<(i64, String, String, String)>> {
        let mut s = self.db.prepare(
            "SELECT id, name, budget_json, used_json FROM branches ORDER BY id",
        )?;
        let v = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(v)
    }

    pub fn set_budget(&mut self, branch_id: i64, budget: &Budget) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE branches SET budget_json=?1 WHERE id=?2",
            params![serde_json::to_string(budget).unwrap(), branch_id],
        )?;
        Ok(())
    }

    pub fn get_budget(&mut self, branch_id: i64) -> rusqlite::Result<(Budget, BudgetUse)> {
        let (bj, uj): (String, String) = self.db.query_row(
            "SELECT budget_json, used_json FROM branches WHERE id=?1",
            params![branch_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((serde_json::from_str(&bj).unwrap(), serde_json::from_str(&uj).unwrap()))
    }

    pub fn set_used(&mut self, branch_id: i64, used: &BudgetUse) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE branches SET used_json=?1 WHERE id=?2",
            params![serde_json::to_string(used).unwrap(), branch_id],
        )?;
    }

    pub fn clear_branch_results(&mut self, branch_id: i64) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM branch_nodes WHERE branch_id=?1", params![branch_id])?;
        self.db.execute("DELETE FROM delta_steps WHERE branch_id=?1", params![branch_id])?;
        self.db.execute("DELETE FROM edges WHERE branch_id=?1", params![branch_id])?;
        Ok(())
    }
}
