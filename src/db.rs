use rusqlite::{params, Connection};
use std::path::Path;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "on")?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            kind TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            content BLOB NOT NULL,
            imported_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(sha256, filename)
        );
        CREATE TABLE IF NOT EXISTS packs (
            id INTEGER PRIMARY KEY,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            object_count INTEGER NOT NULL,
            raw_len INTEGER NOT NULL,
            pack_sha1 TEXT NOT NULL,
            trailer_sha1 TEXT NOT NULL,
            checksum_valid INTEGER NOT NULL,
            parse_error TEXT
        );
        CREATE TABLE IF NOT EXISTS pack_objects (
            id INTEGER PRIMARY KEY,
            pack_id INTEGER NOT NULL REFERENCES packs(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            header_end INTEGER NOT NULL,
            data_start INTEGER NOT NULL,
            data_end INTEGER NOT NULL,
            object_type TEXT NOT NULL,
            declared_size INTEGER NOT NULL,
            payload BLOB NOT NULL,
            crc32 INTEGER NOT NULL,
            ofs_base_offset INTEGER,
            ref_base_oid TEXT,
            parse_error TEXT,
            UNIQUE(pack_id, offset)
        );
        CREATE TABLE IF NOT EXISTS indexes (
            id INTEGER PRIMARY KEY,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            object_count INTEGER NOT NULL,
            pack_checksum TEXT NOT NULL,
            index_checksum TEXT NOT NULL,
            fanout_json TEXT NOT NULL,
            parse_error TEXT
        );
        CREATE TABLE IF NOT EXISTS index_entries (
            id INTEGER PRIMARY KEY,
            index_id INTEGER NOT NULL REFERENCES indexes(id) ON DELETE CASCADE,
            oid TEXT NOT NULL,
            offset INTEGER NOT NULL,
            crc32 INTEGER
        );
        CREATE TABLE IF NOT EXISTS index_matches (
            id INTEGER PRIMARY KEY,
            index_id INTEGER NOT NULL REFERENCES indexes(id) ON DELETE CASCADE,
            pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE,
            matches INTEGER NOT NULL,
            reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS loose_objects (
            id INTEGER PRIMARY KEY,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            object_type TEXT,
            declared_oid TEXT,
            computed_oid TEXT,
            payload BLOB,
            zlib_consumed INTEGER,
            parse_error TEXT
        );
        CREATE TABLE IF NOT EXISTS pins (
            oid TEXT PRIMARY KEY,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY,
            origin_kind TEXT NOT NULL,
            source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            origin_table_id INTEGER NOT NULL,
            pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE,
            offset INTEGER,
            declared_oid TEXT,
            input_type TEXT NOT NULL,
            payload BLOB NOT NULL,
            direct_base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
            ref_base_oid TEXT,
            parse_error TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            resolved_oid TEXT,
            resolved_type TEXT,
            depth INTEGER,
            expansion_ratio INTEGER,
            chosen_base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
            error TEXT,
            blocking_chain_json TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS resolved_objects (
            oid TEXT PRIMARY KEY,
            candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
            object_type TEXT NOT NULL,
            payload BLOB NOT NULL,
            depth INTEGER NOT NULL,
            expansion_ratio INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS delta_steps (
            id INTEGER PRIMARY KEY,
            candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            base_candidate_id INTEGER REFERENCES candidates(id) ON DELETE SET NULL,
            base_oid TEXT,
            base_type TEXT,
            delta_start INTEGER NOT NULL,
            delta_end INTEGER NOT NULL,
            input_len INTEGER NOT NULL,
            output_len INTEGER,
            check_valid INTEGER NOT NULL,
            ops_json TEXT NOT NULL,
            error TEXT,
            UNIQUE(candidate_id, seq)
        );
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_candidates_ref ON candidates(ref_base_oid);
        CREATE INDEX IF NOT EXISTS idx_candidates_resolved ON candidates(resolved_oid, status);
        CREATE INDEX IF NOT EXISTS idx_candidates_pack_offset ON candidates(pack_id, offset);
        CREATE INDEX IF NOT EXISTS idx_index_entries_oid ON index_entries(oid);
        "#,
    )?;
    Ok(())
}

pub fn set_state(conn: &mut Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO state(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_state(conn: &Connection, key: &str, default: &str) -> rusqlite::Result<String> {
    conn.query_row("SELECT value FROM state WHERE key=?1", params![key], |row| {
        row.get::<_, String>(0)
    })
    .or_else(|err| {
        if matches!(err, rusqlite::Error::QueryReturnedNoRows) {
            Ok(default.to_string())
        } else {
            Err(err)
        }
    })
}
