use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct SourceRow {
    pub id: i64,
    pub kind: String,
    pub original_name: String,
    pub stored_path: String,
    pub sha256: String,
    pub paired_source_id: Option<i64>,
}

pub struct Database {
    pub conn: Connection,
}

impl Database {
    pub fn open(root: &Path) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(root.join("uploads")).ok();
        let conn = Connection::open(root.join("microscope.db"))?;
        let db = Database { conn };
        db.init()?;
        Ok(db)
    }

    pub fn init(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS sources (
              id INTEGER PRIMARY KEY,
              kind TEXT NOT NULL CHECK(kind IN ('pack','idx','loose')),
              original_name TEXT NOT NULL,
              stored_path TEXT NOT NULL UNIQUE,
              sha256 TEXT NOT NULL,
              parse_status TEXT NOT NULL,
              parse_error TEXT,
              paired_source_id INTEGER REFERENCES sources(id),
              imported_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS raw_objects (
              id INTEGER PRIMARY KEY,
              source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
              source_kind TEXT NOT NULL,
              pack_offset INTEGER,
              type_name TEXT NOT NULL,
              declared_size INTEGER NOT NULL,
              inflated_size INTEGER NOT NULL,
              compressed_size INTEGER NOT NULL,
              content BLOB NOT NULL,
              content_sha256 TEXT NOT NULL,
              header_offset INTEGER,
              zlib_end INTEGER,
              base_ref_oid TEXT,
              base_offset INTEGER,
              parse_error TEXT,
              crc32 INTEGER
            );
            CREATE TABLE IF NOT EXISTS candidates (
              oid TEXT NOT NULL,
              raw_id INTEGER NOT NULL REFERENCES raw_objects(id) ON DELETE CASCADE,
              source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
              origin_rank INTEGER NOT NULL,
              valid INTEGER NOT NULL,
              mismatch_reason TEXT,
              PRIMARY KEY(oid, raw_id)
            );
            CREATE TABLE IF NOT EXISTS edges (
              child_raw_id INTEGER PRIMARY KEY REFERENCES raw_objects(id) ON DELETE CASCADE,
              ref_kind TEXT NOT NULL,
              base_oid TEXT,
              base_offset INTEGER,
              base_raw_id INTEGER REFERENCES raw_objects(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS resolved (
              raw_id INTEGER PRIMARY KEY REFERENCES raw_objects(id) ON DELETE CASCADE,
              state TEXT NOT NULL,
              oid TEXT,
              type_name TEXT,
              content BLOB,
              depth INTEGER,
              expanded_bytes INTEGER,
              error_code TEXT,
              error_message TEXT,
              blocked_chain TEXT,
              version INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS resolution_steps (
              id INTEGER PRIMARY KEY,
              raw_id INTEGER NOT NULL REFERENCES raw_objects(id) ON DELETE CASCADE,
              seq INTEGER NOT NULL,
              base_raw_id INTEGER,
              base_oid TEXT,
              op_start INTEGER,
              op_end INTEGER,
              op_kind TEXT,
              input_len INTEGER,
              output_len INTEGER,
              check_kind TEXT,
              check_ok INTEGER,
              detail TEXT
            );
            CREATE TABLE IF NOT EXISTS branch_pins (
              oid TEXT NOT NULL,
              branch TEXT NOT NULL,
              source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
              PRIMARY KEY(oid, branch)
            );
            CREATE TABLE IF NOT EXISTS analysis_runs (
              id INTEGER PRIMARY KEY,
              state TEXT NOT NULL,
              max_depth INTEGER NOT NULL,
              total_budget INTEGER NOT NULL,
              single_ratio INTEGER NOT NULL,
              used_bytes INTEGER NOT NULL,
              started_at INTEGER NOT NULL,
              finished_at INTEGER
            );
            "#,
        )
    }

    pub fn insert_source(
        &self,
        kind: &str,
        original_name: &str,
        stored_path: &Path,
        sha256: &str,
        parse_status: &str,
        parse_error: Option<&str>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sources(kind, original_name, stored_path, sha256, parse_status, parse_error, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,strftime('%s','now'))",
            params![kind, original_name, stored_path.to_string_lossy(), sha256, parse_status, parse_error],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn source_by_path(&self, path: &Path) -> rusqlite::Result<Option<SourceRow>> {
        self.conn
            .query_row(
                "SELECT id, kind, original_name, stored_path, sha256, paired_source_id FROM sources WHERE stored_path=?1",
                params![path.to_string_lossy()],
                |row| {
                    Ok(SourceRow {
                        id: row.get(0)?,
                        kind: row.get(1)?,
                        original_name: row.get(2)?,
                        stored_path: row.get(3)?,
                        sha256: row.get(4)?,
                        paired_source_id: row.get(5)?,
                    })
                },
            )
            .optional()
    }
}

pub fn optional<T>(result: rusqlite::Result<T>) -> rusqlite::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err),
    }
}

pub trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        optional(self)
    }
}

pub fn data_file(root: &Path, filename: &str) -> PathBuf {
    let safe = filename
        .split(['/', '\\'])
        .last()
        .filter(|name| !name.is_empty())
        .unwrap_or("import.bin");
    root.join("uploads").join(safe)
}
