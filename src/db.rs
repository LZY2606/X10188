use rusqlite::Connection;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    init(&conn)?;
    Ok(conn)
}

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            kind TEXT NOT NULL,              -- pack | idx | loose
            stored_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            imported_at TEXT NOT NULL DEFAULT (datetime('now')),
            pack_id INTEGER,                 -- set for idx after pairing
            linked_oid TEXT,                 -- set for loose
            UNIQUE(sha256, filename)
        );
        CREATE TABLE IF NOT EXISTS packs (
            id INTEGER PRIMARY KEY,
            source_id INTEGER NOT NULL,
            version INTEGER NOT NULL,
            object_count INTEGER NOT NULL,
            trailer_oid TEXT NOT NULL,
            computed_checksum TEXT NOT NULL,
            idx_source_id INTEGER,
            idx_pack_checksum TEXT,
            idx_checksum_ok INTEGER NOT NULL DEFAULT 0,
            matched INTEGER NOT NULL DEFAULT 0,
            mismatch_note TEXT
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY,
            oid TEXT NOT NULL,               -- declared (idx/loose) or computed
            kind TEXT NOT NULL,              -- commit|tree|blob|tag|ofs-delta|ref-delta|unknown
            final_kind TEXT,                 -- resolved git type
            source_id INTEGER NOT NULL,
            pack_id INTEGER,
            loose_path TEXT,
            pack_offset INTEGER,
            zlib_start INTEGER,
            entry_end INTEGER,
            declared_size INTEGER,
            base_offset INTEGER,
            base_oid TEXT,
            idx_crc INTEGER,
            computed_crc INTEGER,
            crc_ok INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            error_code TEXT,
            error_note TEXT,
            resolved_kind TEXT,
            resolve_depth INTEGER,
            pinned INTEGER NOT NULL DEFAULT 0,
            UNIQUE(source_id, pack_offset, loose_path)
        );
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY,
            from_node INTEGER NOT NULL,
            to_oid TEXT NOT NULL,            -- missing if target unknown
            to_node INTEGER,
            kind TEXT NOT NULL,              -- ofs | ref
            UNIQUE(from_node, to_oid)
        );
        CREATE TABLE IF NOT EXISTS steps (
            id INTEGER PRIMARY KEY,
            node_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            base_node INTEGER,
            base_oid TEXT,
            instr_start INTEGER,
            instr_end INTEGER,
            in_len INTEGER,
            out_len INTEGER,
            check_ok INTEGER,
            note TEXT,
            UNIQUE(node_id, seq)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY,
            node_id INTEGER,
            pack_id INTEGER,
            level TEXT NOT NULL,             -- error | warning | info
            code TEXT NOT NULL,
            message TEXT NOT NULL,
            at_offset INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS objects (
            oid TEXT NOT NULL,
            node_id INTEGER NOT NULL,
            kind TEXT,
            data BLOB,
            stage TEXT NOT NULL,             -- raw | resolved
            PRIMARY KEY (oid, node_id, stage)
        );
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        "#,
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO kv(k,v) VALUES
         ('budget_max_depth','64'),
         ('budget_total_bytes','67108864'),
         ('budget_single_ratio','100'),
         ('budget_used_depth','0'),
         ('budget_used_total_bytes','0')",
        [],
    )?;
    Ok(())
}
