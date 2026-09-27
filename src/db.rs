//! SQLite 持久层：所有输入与分析状态都存放在项目数据目录。

use rusqlite::Connection;
use std::path::Path;

pub fn open(data_dir: &Path) -> rusqlite::Result<Connection> {
    std::fs::create_dir_all(data_dir).ok();
    let db_path = data_dir.join("microscope.db");
    let conn = Connection::open(db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,                 -- pack | idx | loose
            filename TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            bytes BLOB NOT NULL,
            sha256 TEXT NOT NULL,
            imported_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            -- pack 内偏移；loose 为 0
            offset INTEGER NOT NULL,
            -- 非 delta 为声明类型；delta 为 ofs-delta/ref-delta
            kind_code INTEGER NOT NULL,
            declared_size INTEGER NOT NULL,
            -- idx 声称的 oid（仅 pack+idx 有）；loose 由路径推断
            claimed_oid TEXT,
            -- 原始解压字节（delta 为指令字节；loose 为 content 之前的原始包）
            raw_inflated BLOB,
            -- zlib 在源文件中的范围
            zlib_start INTEGER,
            zlib_end INTEGER,
            parse_errors TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS delta_edges (
            id INTEGER PRIMARY KEY,
            object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
            ref_type TEXT NOT NULL,            -- ofs | ref
            base_offset INTEGER,
            base_oid TEXT
        );

        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pins (
            id INTEGER PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            oid TEXT NOT NULL,                  -- 被固定的候选 oid（通常是 base）
            object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
            UNIQUE(branch_id, oid)
        );

        -- 每个 (分支, 候选对象) 的最新还原结果
        CREATE TABLE IF NOT EXISTS resolved (
            id INTEGER PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
            status TEXT NOT NULL,              -- ok | error | pending | paused | blocked
            final_kind INTEGER,
            final_oid TEXT,                     -- 重新计算的 git object id
            content BLOB,
            depth INTEGER,
            error TEXT,
            blockers TEXT,                      -- JSON: [{oid, object_id, reason, via:[...]}]
            updated_run INTEGER,
            UNIQUE(branch_id, object_id)
        );

        CREATE TABLE IF NOT EXISTS steps (
            id INTEGER PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
            step_no INTEGER NOT NULL,           -- 0 = base，之后每应用一次 delta
            base_object_id INTEGER,
            base_oid TEXT,
            instr_start INTEGER,
            instr_end INTEGER,
            input_len INTEGER,
            output_len INTEGER,
            check TEXT,                         -- match | mismatch | error: ...
            UNIQUE(branch_id, object_id, step_no)
        );

        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY,
            branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
            started_at INTEGER NOT NULL,
            finished_at INTEGER,
            outcome TEXT,                       -- complete | paused
            max_depth INTEGER NOT NULL,
            max_total_bytes INTEGER NOT NULL,
            max_object_bytes INTEGER NOT NULL,
            bytes_used INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )?;
    // 确保存在默认分支
    conn.execute(
        "INSERT OR IGNORE INTO branches(name, created_at) VALUES ('main', 0)",
        [],
    )?;
    Ok(())
}
