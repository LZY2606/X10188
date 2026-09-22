//! SQLite 持久层。所有导入文件保存在项目数据目录，数据库记录内容摘要与原始偏移。

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use std::sync::Mutex;

use crate::types::{Evidence, ObjType, IdxReport, PackReport};

pub const DEFAULT_BRANCH: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Pack => "pack",
            SourceKind::Idx => "idx",
            SourceKind::Loose => "loose",
            SourceKind::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> SourceKind {
        match s {
            "pack" => SourceKind::Pack,
            "idx" => SourceKind::Idx,
            "loose" => SourceKind::Loose,
            _ => SourceKind::Unknown,
        }
    }
}

pub const CB_COMPLETE: &str = "complete";
pub const CB_BLOCKED: &str = "blocked";
pub const CB_PAUSED: &str = "paused";
pub const CB_ERROR: &str = "error";
pub const CB_FRESH: &str = "fresh";

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub stored_path: String,
    pub size_bytes: i64,
    pub sha1: String,
    pub pack_checksum: Option<String>,
    pub idx_pack_checksum: Option<String>,
    pub parse_state: String,
    pub evidence_json: String,
}

/// 不含大字段（body / delta payload）的候选行。
#[derive(Debug, Clone)]
pub struct CandidateMeta {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    pub pack_offset: Option<i64>,
    pub stype: String,
    pub final_type: Option<String>,
    pub oid: Option<String>,
    pub declared_size: i64,
    pub inflated_size: Option<i64>,
    pub body_len: Option<i64>,
    pub delta: bool,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub parse_state: String,
    pub evidence_json: String,
    pub rank_score: i64,
    pub content_sig: String,
}

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: String,
}

impl Store {
    pub fn open(data_dir: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        std::fs::create_dir_all(format!("{data_dir}/files"))?;
        let conn = Connection::open(format!("{data_dir}/microscope.db")).map_err(std::io::Error::other)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        migrate(&conn).map_err(std::io::Error::other)?;
        let store = Store { conn: Mutex::new(conn), data_dir: data_dir.to_string() };
        store.ensure_default_branch();
        Ok(store)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    fn ensure_default_branch(&self) {
        self.lock()
            .execute(
                "INSERT OR IGNORE INTO branches(name,note,pinned_json) VALUES(?1,'默认分析分支','{}')",
                params![DEFAULT_BRANCH],
            )
            .unwrap();
    }

    pub fn branch_id(&self, name: &str) -> Option<i64> {
        self.lock()
            .query_row("SELECT id FROM branches WHERE name=?1", params![name], |r| r.get(0))
            .optional()
            .unwrap()
    }

    pub fn create_branch(&self, name: &str, note: &str, pinned_json: &str) -> rusqlite::Result<i64> {
        let c = self.lock();
        c.execute(
            "INSERT INTO branches(name,note,pinned_json) VALUES(?1,?2,?3)",
            params![name, note, pinned_json],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn insert_source(
        &self,
        kind: SourceKind,
        filename: &str,
        stored_path: &str,
        size_bytes: i64,
        sha1: &str,
        pack_checksum: Option<&str>,
        idx_pack_checksum: Option<&str>,
        parse_state: &str,
        evidence: &[Evidence],
    ) -> i64 {
        let c = self.lock();
        c.execute(
            "INSERT INTO sources(kind,filename,stored_path,size_bytes,sha1,pack_checksum,idx_pack_checksum,parse_state,evidence_json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                kind.as_str(),
                filename,
                stored_path,
                size_bytes,
                sha1,
                pack_checksum,
                idx_pack_checksum,
                parse_state,
                ev_json(evidence)
            ],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    pub fn sources(&self) -> Vec<SourceRow> {
        let c = self.lock();
        let mut stmt = c.prepare(SOURCE_COLS).unwrap();
        stmt.query_map([], row_source).unwrap().map(|r| r.unwrap()).collect()
    }

    pub fn source_by_id(&self, id: i64) -> Option<SourceRow> {
        let c = self.lock();
        c.query_row(&format!("{SOURCE_COLS} WHERE id=?1"), params![id], row_source)
            .optional()
            .unwrap()
    }

    pub fn candidate_metas(&self) -> Vec<CandidateMeta> {
        let c = self.lock();
        let mut stmt = c.prepare(CAND_COLS).unwrap();
        stmt.query_map([], row_cand).unwrap().map(|r| r.unwrap()).collect()
    }

    pub fn candidate_meta(&self, id: i64) -> Option<CandidateMeta> {
        let c = self.lock();
        c.query_row(&format!("{CAND_COLS} WHERE id=?1"), params![id], row_cand)
            .optional()
            .unwrap()
    }
}

const SOURCE_COLS: &str =
    "SELECT id,kind,filename,stored_path,size_bytes,sha1,pack_checksum,idx_pack_checksum,parse_state,evidence_json FROM sources";

const CAND_COLS: &str = "SELECT id,source_id,kind,pack_offset,stype,final_type,oid,declared_size,inflated_size,body_len,\
     delta,base_offset,base_oid,parse_state,evidence_json,rank_score,content_sig FROM candidates";

fn row_source(r: &rusqlite::Row<'_>) -> rusqlite::Result<SourceRow> {
    Ok(SourceRow {
        id: r.get(0)?,
        kind: r.get(1)?,
        filename: r.get(2)?,
        stored_path: r.get(3)?,
        size_bytes: r.get(4)?,
        sha1: r.get(5)?,
        pack_checksum: r.get(6)?,
        idx_pack_checksum: r.get(7)?,
        parse_state: r.get(8)?,
        evidence_json: r.get(9)?,
    })
}

fn row_cand(r: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateMeta> {
    Ok(CandidateMeta {
        id: r.get(0)?,
        source_id: r.get(1)?,
        kind: r.get(2)?,
        pack_offset: r.get(3)?,
        stype: r.get(4)?,
        final_type: r.get(5)?,
        oid: r.get(6)?,
        declared_size: r.get(7)?,
        inflated_size: r.get(8)?,
        body_len: r.get(9)?,
        delta: r.get::<_, i64>(10)? != 0,
        base_offset: r.get(11)?,
        base_oid: r.get(12)?,
        parse_state: r.get(13)?,
        evidence_json: r.get(14)?,
        rank_score: r.get(15)?,
        content_sig: r.get(16)?,
    })
}

pub fn ev_json(ev: &[Evidence]) -> String {
    serde_json::to_string(
        &ev.iter()
            .map(|e| json!({"code": e.code, "message": e.message, "offset": e.offset, "len": e.len}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into())
}

pub fn obj_code(t: ObjType) -> String {
    t.code().to_string()
}

pub fn pack_trailer(report: &PackReport) -> Option<String> {
    report.trailer_oid.clone()
}
pub fn idx_pack_checksum(report: &IdxReport) -> Option<String> {
    report.pack_checksum.clone()
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha1 TEXT NOT NULL,
    pack_checksum TEXT,
    idx_pack_checksum TEXT,
    parse_state TEXT NOT NULL DEFAULT 'imported',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    pack_offset INTEGER,
    header_len INTEGER,
    meta_len INTEGER,
    comp_offset INTEGER,
    comp_len INTEGER,
    stype TEXT NOT NULL,
    final_type TEXT,
    oid TEXT,
    declared_size INTEGER NOT NULL DEFAULT 0,
    inflated_size INTEGER,
    body_len INTEGER,
    delta INTEGER NOT NULL DEFAULT 0,
    base_offset INTEGER,
    base_oid TEXT,
    delta_payload BLOB NOT NULL DEFAULT x'',
    body BLOB NOT NULL DEFAULT x'',
    parse_state TEXT NOT NULL DEFAULT 'parsed',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    rank_score INTEGER NOT NULL DEFAULT 0,
    content_sig TEXT NOT NULL DEFAULT '',
    UNIQUE(source_id, pack_offset)
);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_candidates_base_oid ON candidates(base_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    pinned_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS candidate_branch (
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    final_type TEXT,
    oid TEXT,
    body_len INTEGER,
    generation INTEGER NOT NULL DEFAULT 0,
    blocked_chain_json TEXT NOT NULL DEFAULT '[]',
    pause_json TEXT NOT NULL DEFAULT '{}',
    resolved_at TEXT,
    PRIMARY KEY (branch_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    depth INTEGER NOT NULL,
    base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
    base_oid TEXT,
    kind TEXT NOT NULL,
    op_start INTEGER NOT NULL,
    op_len INTEGER NOT NULL,
    src_offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    out_before INTEGER NOT NULL,
    out_after INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    note TEXT,
    check_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(branch_id, candidate_id, seq)
);
CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    from_candidate INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    to_candidate INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    ref_kind TEXT NOT NULL,
    UNIQUE(branch_id, from_candidate, to_candidate)
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolve_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    status TEXT NOT NULL,
    used_total_bytes INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
"#;

/* ---------------- 候选对象写入 / 读取（大字段） ---------------- */

#[derive(Debug, Clone)]
pub struct NewCandidate<'a> {
    pub source_id: i64,
    pub kind: &'a str, // packed / loose
    pub pack_offset: Option<i64>,
    pub header_len: Option<i64>,
    pub meta_len: Option<i64>,
    pub comp_offset: Option<i64>,
    pub comp_len: Option<i64>,
    pub stype: String,
    pub declared_size: i64,
    pub inflated_size: Option<i64>,
    pub delta: bool,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub delta_payload: &'a [u8],
    pub body: &'a [u8],
    pub evidence: &'a [Evidence],
    /// index 给出的期望 oid（packed 才有）。
    pub expected_oid: Option<String>,
}

impl Store {
    pub fn insert_candidate(&self, n: &NewCandidate<'_>) -> i64 {
        let c = self.lock();
        // 同 (source, offset) 重导入时幂等替换：先删后插。
        if let Some(off) = n.pack_offset {
            c.execute("DELETE FROM candidates WHERE source_id=?1 AND pack_offset=?2", params![n.source_id, off])
                .unwrap();
        }
        let content_sig = if n.delta {
            crate::hash::sha1_hex(n.delta_payload)
        } else {
            crate::hash::sha1_hex(n.body)
        };
        let expected = n.expected_oid.clone();
        c.execute(
            "INSERT INTO candidates(source_id,kind,pack_offset,header_len,meta_len,comp_offset,comp_len,stype,
                declared_size,inflated_size,delta,base_offset,base_oid,delta_payload,body,oid,
                parse_state,evidence_json,rank_score,content_sig)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'parsed',?17,0,?18)",
            params![
                n.source_id,
                n.kind,
                n.pack_offset,
                n.header_len,
                n.meta_len,
                n.comp_offset,
                n.comp_len,
                n.stype,
                n.declared_size,
                n.inflated_size,
                n.delta as i64,
                n.base_offset,
                n.base_oid,
                n.delta_payload,
                n.body,
                expected,
                ev_json(n.evidence),
                content_sig,
            ],
        )
        .unwrap();
        let id = c.last_insert_rowid();
        // 让所有现存分支为新候选建一个 fresh 行。
        c.execute(
            "INSERT OR IGNORE INTO candidate_branch(branch_id,candidate_id,status)
             SELECT id, ?1, 'fresh' FROM branches",
            params![id],
        )
        .unwrap();
        id
    }

    pub fn set_candidate_oid_from_index(&self, source_id: i64, offset: i64, oid: &str) {
        self.lock()
            .execute(
                "UPDATE candidates SET oid=?1 WHERE source_id=?2 AND pack_offset=?3 AND oid IS NULL",
                params![oid, source_id, offset],
            )
            .unwrap();
    }

    /// 读取大字段：body / delta_payload。
    pub fn candidate_payload(&self, id: i64) -> Option<(Vec<u8>, Vec<u8>)> {
        self.lock()
            .query_row(
                "SELECT body, delta_payload FROM candidates WHERE id=?1",
                params![id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .unwrap()
    }

    pub fn candidates_for_oid<'a>(&self, oid: &str) -> Vec<CandidateMeta> {
        let c = self.lock();
        let mut stmt = c
            .prepare(&format!(
                "{CAND_COLS} WHERE oid=?1 AND delta=0 ORDER BY rank_score DESC, id ASC"
            ))
            .unwrap();
        stmt.query_map(params![oid], row_cand).unwrap().map(|r| r.unwrap()).collect()
    }

    /// delta by offset base：同一 pack 内、偏移等于 base_offset 的候选。
    pub fn candidate_by_source_offset(&self, source_id: i64, offset: i64) -> Option<CandidateMeta> {
        let c = self.lock();
        c.query_row(
            &format!("{CAND_COLS} WHERE source_id=?1 AND pack_offset=?2"),
            params![source_id, offset],
            row_cand,
        )
        .optional()
        .unwrap()
    }

    pub fn all_dependents_via_base_oid(&self, base_oid: &str) -> Vec<CandidateMeta> {
        let c = self.lock();
        let mut stmt = c
            .prepare(&format!("{CAND_COLS} WHERE base_oid=?1 AND delta=1"))
            .unwrap();
        stmt.query_map(params![base_oid], row_cand).unwrap().map(|r| r.unwrap()).collect()
    }

    pub fn all_candidates(&self) -> Vec<CandidateMeta> {
        self.candidate_metas()
    }

    pub fn recompute_rank_scores(&self) {
        // 确定性排序（与导入顺序无关）：
        //   优先 index/路径给出 oid 的来源；oid 非空 > 空；
        //   解析干净（无证据）> 有证据；
        //   同分时按 content_sig、source id、offset 排序（在查询处加 tie-break）。
        let c = self.lock();
        c.execute(
            "UPDATE candidates SET rank_score =
                CASE WHEN oid IS NOT NULL THEN 4 ELSE 0 END
              + CASE WHEN evidence_json='[]' THEN 2 ELSE 0 END
              + CASE WHEN kind='loose' THEN 1 ELSE 0 END",
            [],
        )
        .unwrap();
    }
}

/* ---------------- 分支 / 解析状态 / 边 / 步骤 ---------------- */

#[derive(Debug, Clone)]
pub struct BranchRow {
    pub id: i64,
    pub name: String,
    pub note: String,
    pub pinned_json: String,
}

#[derive(Debug, Clone)]
pub struct CandidateBranchRow {
    pub branch_id: i64,
    pub candidate_id: i64,
    pub status: String,
    pub final_type: Option<String>,
    pub oid: Option<String>,
    pub body_len: Option<i64>,
    pub generation: i64,
    pub blocked_chain_json: String,
    pub pause_json: String,
}

impl Store {
    pub fn branches(&self) -> Vec<BranchRow> {
        let c = self.lock();
        let mut stmt = c.prepare("SELECT id,name,note,pinned_json FROM branches ORDER BY id").unwrap();
        stmt.query_map([], |r| {
            Ok(BranchRow { id: r.get(0)?, name: r.get(1)?, note: r.get(2)?, pinned_json: r.get(3)? })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn branch_by_name(&self, name: &str) -> Option<BranchRow> {
        let c = self.lock();
        c.query_row("SELECT id,name,note,pinned_json FROM branches WHERE name=?1", params![name], |r| {
            Ok(BranchRow { id: r.get(0)?, name: r.get(1)?, note: r.get(2)?, pinned_json: r.get(3)? })
        })
        .optional()
        .unwrap()
    }

    /// 复制一个分支：pinned 候选选择 + 当前解析结果快照。
    pub fn clone_branch(&self, src_name: &str, new_name: &str, note: &str, pinned_json: &str) -> rusqlite::Result<()> {
        let mut c = self.lock();
        let tx = c.transaction()?;
        tx.execute("INSERT INTO branches(name,note,pinned_json) VALUES(?1,?2,?3)", params![new_name, note, pinned_json])?;
        let new_id = tx.last_insert_rowid();
        let src_id: i64 = tx.query_row("SELECT id FROM branches WHERE name=?1", params![src_name], |r| r.get(0))?;
        tx.execute(
            "INSERT INTO candidate_branch(branch_id,candidate_id,status,final_type,oid,body_len,generation,blocked_chain_json,pause_json)
             SELECT ?1,candidate_id,status,final_type,oid,body_len,generation,blocked_chain_json,pause_json
             FROM candidate_branch WHERE branch_id=?2",
            params![new_id, src_id],
        )?;
        tx.execute(
            "INSERT INTO edges(branch_id,from_candidate,to_candidate,ref_kind)
             SELECT ?1,from_candidate,to_candidate,ref_kind FROM edges WHERE branch_id=?2",
            params![new_id, src_id],
        )?;
        tx.execute(
            "INSERT INTO delta_steps(branch_id,candidate_id,seq,depth,base_candidate_id,base_oid,kind,op_start,op_len,
                src_offset,length,out_before,out_after,input_len,output_len,ok,note,check_json)
             SELECT ?1,candidate_id,seq,depth,base_candidate_id,base_oid,kind,op_start,op_len,src_offset,length,
                out_before,out_after,input_len,output_len,ok,note,check_json
             FROM delta_steps WHERE branch_id=?2",
            params![new_id, src_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn cb_row(&self, branch_id: i64, candidate_id: i64) -> Option<CandidateBranchRow> {
        let c = self.lock();
        c.query_row(
            "SELECT branch_id,candidate_id,status,final_type,oid,body_len,generation,blocked_chain_json,pause_json
             FROM candidate_branch WHERE branch_id=?1 AND candidate_id=?2",
            params![branch_id, candidate_id],
            |r| {
                Ok(CandidateBranchRow {
                    branch_id: r.get(0)?,
                    candidate_id: r.get(1)?,
                    status: r.get(2)?,
                    final_type: r.get(3)?,
                    oid: r.get(4)?,
                    body_len: r.get(5)?,
                    generation: r.get(6)?,
                    blocked_chain_json: r.get(7)?,
                    pause_json: r.get(8)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    pub fn cb_rows_for_branch(&self, branch_id: i64) -> Vec<CandidateBranchRow> {
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT branch_id,candidate_id,status,final_type,oid,body_len,generation,blocked_chain_json,pause_json
                 FROM candidate_branch WHERE branch_id=?1",
            )
            .unwrap();
        stmt.query_map(params![branch_id], |r| {
            Ok(CandidateBranchRow {
                branch_id: r.get(0)?,
                candidate_id: r.get(1)?,
                status: r.get(2)?,
                final_type: r.get(3)?,
                oid: r.get(4)?,
                body_len: r.get(5)?,
                generation: r.get(6)?,
                blocked_chain_json: r.get(7)?,
                pause_json: r.get(8)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn upsert_cb(&self, row: &CandidateBranchRow) {
        self.lock()
            .execute(
                "INSERT INTO candidate_branch(branch_id,candidate_id,status,final_type,oid,body_len,generation,blocked_chain_json,pause_json,resolved_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,datetime('now'))
                 ON CONFLICT(branch_id,candidate_id) DO UPDATE SET
                    status=excluded.status, final_type=excluded.final_type, oid=excluded.oid,
                    body_len=excluded.body_len, generation=excluded.generation,
                    blocked_chain_json=excluded.blocked_chain_json, pause_json=excluded.pause_json,
                    resolved_at=datetime('now')",
                params![
                    row.branch_id,
                    row.candidate_id,
                    row.status,
                    row.final_type,
                    row.oid,
                    row.body_len,
                    row.generation,
                    row.blocked_chain_json,
                    row.pause_json
                ],
            )
            .unwrap();
    }

    pub fn clear_steps(&self, branch_id: i64, candidate_id: i64) {
        self.lock()
            .execute("DELETE FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2", params![branch_id, candidate_id])
            .unwrap();
    }

    pub fn upsert_edge(&self, branch_id: i64, from_id: i64, to_id: i64, ref_kind: &str) {
        self.lock()
            .execute(
                "INSERT OR IGNORE INTO edges(branch_id,from_candidate,to_candidate,ref_kind) VALUES(?1,?2,?3,?4)",
                params![branch_id, from_id, to_id, ref_kind],
            )
            .unwrap();
    }

    pub fn delete_candidate_edges(&self, branch_id: i64, candidate_id: i64) {
        self.lock()
            .execute(
                "DELETE FROM edges WHERE branch_id=?1 AND (from_candidate=?2 OR to_candidate=?2)",
                params![branch_id, candidate_id],
            )
            .unwrap();
    }

    pub fn total_used_bytes(&self, branch_id: i64) -> u64 {
        self.lock()
            .query_row(
                "SELECT COALESCE(SUM(body_len),0) FROM candidate_branch WHERE branch_id=?1 AND status='complete'",
                params![branch_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u64
    }

    /// 写回成品内容 + 最终类型/oid（解析成功时）。
    pub fn commit_candidate_content(&self, id: i64, final_type: &str, oid: &str, body: &[u8]) {
        self.lock()
            .execute(
                "UPDATE candidates SET final_type=?1, oid=?2, body=?3, body_len=?4, parse_state='resolved' WHERE id=?5",
                params![final_type, oid, body, body.len() as i64, id],
            )
            .unwrap();
    }

    pub fn mark_candidate_parse_error(&self, id: i64) {
        self.lock()
            .execute("UPDATE candidates SET parse_state='error' WHERE id=?1", params![id])
            .unwrap();
    }
}

impl Store {
    pub fn set_pack_oid(&self, source_id: i64, offset: i64, oid: &str) {
        self.lock()
            .execute(
                "UPDATE candidates SET oid=?1 WHERE source_id=?2 AND pack_offset=?3",
                params![oid, source_id, offset],
            )
            .unwrap();
    }

    pub fn candidate_ids_of_source(&self, source_id: i64) -> Vec<i64> {
        self.lock()
            .prepare("SELECT id FROM candidates WHERE source_id=?1 ORDER BY id")
            .unwrap()
            .query_map(params![source_id], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// 候选 `cand_id` 的出边是否指向 `targets` 中的任一候选（用于删除源文件前确认）。
    pub fn edges_pointing_into(&self, cand_id: &i64, targets: &std::collections::HashSet<i64>) -> bool {
        let c = self.lock();
        let mut stmt = c
            .prepare("SELECT to_candidate FROM edges WHERE from_candidate=?1")
            .unwrap();
        let ids: Vec<i64> = stmt
            .query_map(params![cand_id], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        ids.iter().any(|i| targets.contains(i))
    }

    pub fn delete_source_cascade(&self, source_id: i64) {
        // 依赖该源候选的其他候选 cb 状态先退回 fresh（它们将重新阻塞）。
        let own: std::collections::HashSet<i64> = self.candidate_ids_of_source(source_id).into_iter().collect();
        {
            let c = self.lock();
            c.execute("DELETE FROM sources WHERE id=?1", params![source_id]).unwrap();
        }
        // candidates 外键 ON DELETE CASCADE 会删掉候选；此处把外部依赖者复位。
        for c in self.all_candidates() {
            if own.contains(&c.id) {
                continue;
            }
            if self.edges_pointing_into(&c.id, &own) {
                if let Some(mut row) = self.cb_row(self.branch_id_or_default(), c.id) {
                    row.status = CB_FRESH.into();
                    row.blocked_chain_json = "[]".into();
                    row.pause_json = "{}".into();
                    self.upsert_cb(&row);
                }
            }
        }
    }

    fn branch_id_or_default(&self) -> i64 {
        self.branch_id(DEFAULT_BRANCH).expect("default branch")
    }

    pub fn delta_steps(&self, branch_id: i64, candidate_id: i64) -> Vec<StepRow> {
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT seq,depth,base_candidate_id,base_oid,kind,op_start,op_len,src_offset,length,
                        out_before,out_after,input_len,output_len,ok,note,check_json
                 FROM delta_steps WHERE branch_id=?1 AND candidate_id=?2 ORDER BY seq",
            )
            .unwrap();
        stmt.query_map(params![branch_id, candidate_id], |r| {
            Ok(StepRow {
                seq: r.get(0)?,
                depth: r.get(1)?,
                base_candidate_id: r.get(2)?,
                base_oid: r.get(3)?,
                kind: r.get(4)?,
                op_start: r.get(5)?,
                op_len: r.get(6)?,
                src_offset: r.get(7)?,
                length: r.get(8)?,
                out_before: r.get(9)?,
                out_after: r.get(10)?,
                input_len: r.get(11)?,
                output_len: r.get(12)?,
                ok: r.get::<_, i64>(13)? != 0,
                note: r.get(14)?,
                check_json: r.get(15)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    pub fn edges(&self, branch_id: i64) -> Vec<EdgeRow> {
        let c = self.lock();
        let mut stmt = c
            .prepare("SELECT from_candidate,to_candidate,ref_kind FROM edges WHERE branch_id=?1")
            .unwrap();
        stmt.query_map(params![branch_id], |r| {
            Ok(EdgeRow { from_candidate: r.get(0)?, to_candidate: r.get(1)?, ref_kind: r.get(2)? })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StepRow {
    pub seq: i64,
    pub depth: i64,
    pub base_candidate_id: Option<i64>,
    pub base_oid: Option<String>,
    pub kind: String,
    pub op_start: i64,
    pub op_len: i64,
    pub src_offset: i64,
    pub length: i64,
    pub out_before: i64,
    pub out_after: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub ok: bool,
    pub note: Option<String>,
    pub check_json: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeRow {
    pub from_candidate: i64,
    pub to_candidate: i64,
    pub ref_kind: String,
}
