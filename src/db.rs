use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// 分析引擎持久化连接与数据目录。
pub struct Db {
    pub conn: Connection,
    pub data_dir: PathBuf,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- 'pack' | 'index' | 'loose'
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    byte_len INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
    pack_checksum TEXT,                 -- pack/index 关联键（pack 的包体 sha1）
    idx_pack_checksum TEXT,             -- index 尾部声明的 pack checksum
    attached_pack_id INTEGER,
    status TEXT NOT NULL DEFAULT 'ok', -- 'ok' | 'fatal' | 'mismatch'
    note TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    origin TEXT NOT NULL,               -- 'pack' | 'loose'
    pack_offset INTEGER,
    data_start INTEGER,
    header_len INTEGER,
    zlib_consumed INTEGER,
    compressed BLOB,
    etype TEXT NOT NULL,               -- 'commit'|'tree'|'blob'|'tag'|'ofs-delta'|'ref-delta'
    kind TEXT,
    declared_size INTEGER NOT NULL,
    inflated_size INTEGER NOT NULL,
    payload BLOB,
    claim_oid TEXT,                    -- 主要声称 oid（idx 或 loose 路径/自证）
    oid_verified INTEGER NOT NULL DEFAULT 0,
    idx_crc INTEGER,
    crc_ok INTEGER,
    base_ofs INTEGER,
    base_ofs_cand INTEGER,
    base_ref_oid TEXT,
    parse_error_code TEXT,
    parse_error TEXT,
    runtime_error_code TEXT,
    runtime_error TEXT,
    -- 还原状态
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_kind TEXT,
    resolved_size INTEGER,
    resolved_oid TEXT,
    resolved_content BLOB,
    chain_depth INTEGER,
    blocking_chain TEXT,               -- JSON: [{cand, oid, reason}]
    run_id INTEGER NOT NULL DEFAULT 0,
    ord INTEGER NOT NULL               -- 稳定排序键（与导入顺序无关）
);

CREATE INDEX IF NOT EXISTS idx_cand_claim ON candidates(claim_oid);
CREATE INDEX IF NOT EXISTS idx_cand_source ON candidates(source_id);
CREATE INDEX IF NOT EXISTS idx_cand_ofs ON candidates(source_id, pack_offset);
CREATE INDEX IF NOT EXISTS idx_cand_status ON candidates(status);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cand_id INTEGER NOT NULL REFERENCES candidates(id),
    step INTEGER NOT NULL,             -- 0 表示最靠近 base 的一步
    base_cand INTEGER,
    base_oid TEXT,
    declared_base_len INTEGER,
    declared_result_len INTEGER,
    input_len INTEGER,
    output_len INTEGER,
    op_count INTEGER,
    summary TEXT,
    input_ok INTEGER,
    output_ok INTEGER,
    ops_json TEXT,
    UNIQUE(cand_id, step)
);

CREATE TABLE IF NOT EXISTS edges (
    from_cand INTEGER NOT NULL REFERENCES candidates(id),
    to_cand INTEGER,                   -- 解析出的 base 候选；缺失时为 NULL
    kind TEXT NOT NULL,                -- 'ofs' | 'ref'
    ref_oid TEXT
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_cand);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_cand);

CREATE TABLE IF NOT EXISTS fanout (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    kind TEXT NOT NULL,                -- 'idx256' | 'pack_layout'
    cumulative_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS branches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    pinned_source_id INTEGER REFERENCES sources(id),
    pinned_cand_id INTEGER REFERENCES candidates(id),
    ref_oid TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    scope TEXT NOT NULL,               -- 'full' | 'subgraph'
    budget_json TEXT NOT NULL,
    finished INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0
);
"#;

impl Db {
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let stored = data_dir.join("files");
        std::fs::create_dir_all(&stored)?;
        let db_path = data_dir.join("microscope.db");
        let conn = Connection::open(db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(Db {
            conn,
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn files_dir(&self) -> PathBuf {
        self.data_dir.join("files")
    }
}

/// 源文件内容指纹（SHA-1，仅用于去重与确定性排序，与 git 对象 id 分开使用）。
pub fn fingerprint_hex(b: &[u8]) -> String {
    use sha1::Digest as _;
    let mut h = sha1::Sha1::new();
    h.update(b);
    hex::encode(h.finalize())
}
