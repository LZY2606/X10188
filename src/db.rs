//! SQLite 持久化：源文件、候选节点、解析结果、delta 步骤、分析分支与预算。

use rusqlite::Connection;

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- pack | idx | loose
    file_name TEXT NOT NULL,
    rel_path TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    paired_pack_rel TEXT,               -- idx 配套 pack 的 rel_path
    pack_sha_match INTEGER,
    trailer_ok INTEGER,
    parse_error TEXT,
    imported_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                 -- pack_entry | loose
    entry_index INTEGER,
    pack_offset INTEGER,
    entry_range_start INTEGER,
    entry_range_end INTEGER,
    zlib_range_start INTEGER,
    zlib_range_end INTEGER,
    claimed_oid TEXT,                   -- pack: index 声称 / loose: 路径
    actual_oid TEXT,                    -- 重新计算（未坏时）
    obj_type TEXT NOT NULL,             -- commit/tree/blob/tag/ofs-delta/ref-delta
    declared_size INTEGER,
    inflated_len INTEGER,
    ofs_base_offset INTEGER,
    ref_base_oid TEXT,
    entry_crc32 INTEGER,
    crc_ok INTEGER,                     -- NULL 未知 / 0 坏 / 1 好
    payload_b64 TEXT,                   -- 解析出的负载（loose content 或 delta 指令）
    parse_error TEXT,
    parse_ok INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_actual ON candidates(actual_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_claimed ON candidates(claimed_oid);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);

-- 解析结果（针对分支 pin 选择）。branch_id = 'default' 或创建的分析分支。
CREATE TABLE IF NOT EXISTS resolutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    branch_id TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    status TEXT NOT NULL,               -- resolved | blocked | error | paused | cycle
    actual_oid TEXT,
    out_type TEXT,
    out_len INTEGER,
    chain_len INTEGER,
    error TEXT,
    blocked_chain TEXT,                 -- JSON 阻塞链
    budget_total INTEGER,
    updated_at INTEGER NOT NULL,
    UNIQUE(branch_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS delta_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resolution_id INTEGER NOT NULL REFERENCES resolutions(id) ON DELETE CASCADE,
    step INTEGER NOT NULL,
    base_candidate_id INTEGER,
    base_oid TEXT,
    instr_start INTEGER NOT NULL,
    instr_end INTEGER NOT NULL,
    input_len INTEGER NOT NULL,
    output_len INTEGER NOT NULL,
    check_ok INTEGER NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS branches (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS pins (
    branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    oid TEXT NOT NULL,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    PRIMARY KEY(branch_id, oid)
);

CREATE TABLE IF NOT EXISTS budgets (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    max_depth INTEGER NOT NULL,
    total_budget INTEGER NOT NULL,
    per_object_cap INTEGER NOT NULL,
    per_object_ratio INTEGER NOT NULL,
    total_spent INTEGER NOT NULL
);
"#,
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO branches(id, created_at, note) VALUES ('default', 0, '默认分析视图')",
        [],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO budgets(id, max_depth, total_budget, per_object_cap, per_object_ratio, total_spent) \
         VALUES (1, 50, 268435456, 67108864, 4096, 0)",
        [],
    )?;
    Ok(())
}
