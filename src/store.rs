use rusqlite::Connection;

pub fn open(path: &std::path::Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("打开数据库失败: {}", e))?;
    init(&conn)?;
    Ok(conn)
}

pub fn init(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            size INTEGER NOT NULL,
            pack_checksum TEXT,
            linked_file_id INTEGER,
            imported_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entries(
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            obj_type INTEGER NOT NULL,
            size INTEGER NOT NULL,
            data_offset INTEGER NOT NULL,
            data_len INTEGER NOT NULL,
            base_offset INTEGER,
            base_oid TEXT,
            crc_actual INTEGER NOT NULL,
            crc_index INTEGER,
            inflated BLOB NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            oid TEXT,
            UNIQUE(file_id, offset)
        );
        CREATE TABLE IF NOT EXISTS index_entries(
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            oid TEXT NOT NULL,
            crc32 INTEGER NOT NULL,
            offset INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_index_entries_oid ON index_entries(oid);
        CREATE TABLE IF NOT EXISTS loose(
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            oid TEXT NOT NULL,
            obj_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            status TEXT NOT NULL,
            reason TEXT
        );
        CREATE TABLE IF NOT EXISTS objects(
            oid TEXT PRIMARY KEY,
            obj_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            content BLOB NOT NULL,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS object_sources(
            oid TEXT NOT NULL,
            entry_kind TEXT NOT NULL,
            entry_id INTEGER NOT NULL,
            file_id INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            PRIMARY KEY(oid, entry_kind, entry_id)
        );
        CREATE INDEX IF NOT EXISTS idx_object_sources_file ON object_sources(file_id);
        CREATE TABLE IF NOT EXISTS delta_steps(
            id INTEGER PRIMARY KEY,
            entry_id INTEGER NOT NULL,
            step INTEGER NOT NULL,
            base_desc TEXT NOT NULL,
            base_oid TEXT,
            instr_start INTEGER NOT NULL,
            instr_end INTEGER NOT NULL,
            in_len INTEGER NOT NULL,
            out_len INTEGER NOT NULL,
            verified INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_delta_steps_base ON delta_steps(base_oid);
        CREATE TABLE IF NOT EXISTS paused_deltas(
            entry_id INTEGER PRIMARY KEY,
            pos INTEGER NOT NULL,
            partial BLOB NOT NULL,
            reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pins(
            oid TEXT NOT NULL,
            file_id INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            note TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(oid, file_id, offset)
        );
        CREATE TABLE IF NOT EXISTS errors(
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            entry_id INTEGER,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS budgets(
            id INTEGER PRIMARY KEY CHECK(id = 1),
            max_depth INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL,
            max_ratio REAL NOT NULL
        );
        ",
    )
    .map_err(|e| format!("初始化数据库失败: {}", e))
}
