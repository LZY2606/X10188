//! SQLite 持久层：源文件、解析条目、oid 候选、delta DAG、
//! 分析分支、还原结果、delta 步骤、预算任务与阻塞证据。

use rusqlite::Connection;

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                -- pack | idx | loose
  filename TEXT NOT NULL,
  path TEXT NOT NULL,               -- 数据目录内的相对/绝对路径
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  imported_at TEXT NOT NULL DEFAULT (datetime('now')),
  pack_checksum TEXT,               -- idx 声明的 pack 校验和(hex)
  parse_status TEXT NOT NULL,       -- ok | error
  parse_errors TEXT NOT NULL DEFAULT '[]',
  version INTEGER,
  object_count INTEGER,
  trailer_ok INTEGER
);

-- 通用对象条目（pack 条目或 loose 对象）
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                -- commit|tree|blob|tag|ofs_delta|ref_delta
  ordinal INTEGER NOT NULL,
  header_offset INTEGER,
  data_offset INTEGER,
  end_offset INTEGER,
  declared_size INTEGER NOT NULL,
  inflated_size INTEGER,
  ofs_negative INTEGER,
  ref_base_oid TEXT,
  problem TEXT,
  overshoot INTEGER NOT NULL DEFAULT 0,
  undershoot INTEGER NOT NULL DEFAULT 0,
  resynced INTEGER NOT NULL DEFAULT 0,
  crc_index INTEGER,                 -- index 给出的 CRC（可空）
  crc_calc INTEGER,
  crc_ok INTEGER,
  loose_path_oid TEXT
);

-- 每个条目的候选 oid：loose/还原成功后才有；同一 oid 可有多行（冲突）
CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  oid TEXT NOT NULL,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  rank INTEGER NOT NULL,             -- 确定性排序（小者优先）
  is_dominant INTEGER NOT NULL DEFAULT 0,
  UNIQUE(oid, entry_id)
);

-- delta DAG 边：child entry 依赖 parent entry
CREATE TABLE IF NOT EXISTS deps (
  child_entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  parent_entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  dep_kind TEXT NOT NULL,            -- ofs | ref
  PRIMARY KEY (child_entry_id, parent_entry_id)
);

CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  pinned_source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  note TEXT NOT NULL DEFAULT ''
);

-- 每个分支下每个 entry 的还原结果（部分/完整分状态，绝不把部分当完整）
CREATE TABLE IF NOT EXISTS results (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  status TEXT NOT NULL,             -- complete | blocked | suspended | invalid
  object_type TEXT,
  oid TEXT,
  oid_calc TEXT,
  oid_ok INTEGER,
  output_size INTEGER,
  content_path TEXT,
  preview TEXT,
  depth INTEGER,
  bytes_charged INTEGER NOT NULL DEFAULT 0,
  blocker_entry_id INTEGER REFERENCES entries(id) ON DELETE SET NULL,
  blocker_reason TEXT,
  chain_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (branch_id, entry_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
  step_no INTEGER NOT NULL,
  base_entry_id INTEGER REFERENCES entries(id) ON DELETE SET NULL,
  instr_start INTEGER NOT NULL,
  instr_end INTEGER NOT NULL,
  op TEXT NOT NULL,
  copy_offset INTEGER,
  length INTEGER NOT NULL,
  in_size INTEGER NOT NULL,
  out_size INTEGER NOT NULL,
  verify TEXT NOT NULL              -- ok | error:<原因>
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  status TEXT NOT NULL,             -- done | suspended
  max_depth INTEGER NOT NULL,
  total_budget INTEGER NOT NULL,
  per_object_ratio INTEGER NOT NULL,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  resume_after_entry_id INTEGER,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source_id);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE INDEX IF NOT EXISTS idx_deps_child ON deps(child_entry_id);
CREATE INDEX IF NOT EXISTS idx_deps_parent ON deps(parent_entry_id);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(branch_id, status);
"#,
    )?;

    conn.execute(
        "INSERT OR IGNORE INTO branches(id,name,note) VALUES(1,'default','默认分支（候选自动排序）')",
        [],
    )?;
    Ok(())
}
