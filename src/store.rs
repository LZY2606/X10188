//! SQLite-backed persistence + on-disk payload store.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

pub struct Store {
    pub conn: Connection,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_expanded: u64,
    pub max_single_ratio: f64,
    pub total_expanded_used: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            max_total_expanded: 64 * 1024 * 1024,
            max_single_ratio: 0.9,
            total_expanded_used: 0,
        }
    }
}

impl Store {
    pub fn open(dir: &Path) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(dir.join("payloads")).ok();
        std::fs::create_dir_all(dir.join("intermediate")).ok();
        std::fs::create_dir_all(dir.join("uploads")).ok();
        let db_path = dir.join("microscope.db");
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000i64)?;
        conn.execute_batch(include_str!("schema.sql"))?;
        conn.execute(
            "INSERT OR IGNORE INTO branches(id, name, created_at) VALUES (1, 'default', strftime('%s','now'))",
            [],
        )?;
        let mut s = Store {
            conn,
            data_dir: dir.to_path_buf(),
        };
        s.ensure_default_budget();
        Ok(s)
    }

    fn ensure_default_budget(&mut self) {
        let b = Budget::default();
        for (k, v) in [
            ("max_depth", b.max_depth.to_string()),
            ("max_total_expanded", b.max_total_expanded.to_string()),
            ("max_single_ratio", b.max_single_ratio.to_string()),
            ("total_expanded_used", "0".to_string()),
        ] {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES (?1, ?2)",
                    params![k, v],
                )
                .ok();
        }
    }

    pub fn budget(&self) -> Budget {
        let get = |k: &str| -> String {
            self.conn
                .query_row("SELECT value FROM settings WHERE key=?1", params![k], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap_or_default()
        };
        Budget {
            max_depth: get("max_depth").parse().unwrap_or(50),
            max_total_expanded: get("max_total_expanded").parse().unwrap_or(64 << 20),
            max_single_ratio: get("max_single_ratio").parse().unwrap_or(0.9),
            total_expanded_used: get("total_expanded_used").parse().unwrap_or(0),
        }
    }

    pub fn set_budget(&mut self, b: &Budget) {
        for (k, v) in [
            ("max_depth", b.max_depth.to_string()),
            ("max_total_expanded", b.max_total_expanded.to_string()),
            ("max_single_ratio", b.max_single_ratio.to_string()),
        ] {
            self.conn
                .execute(
                    "INSERT INTO settings(key,value) VALUES(?1,?2)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    params![k, v],
                )
                .ok();
        }
    }

    pub fn add_used(&mut self, bytes: u64) {
        self.conn
            .execute(
                "UPDATE settings SET value = CAST(CAST(value AS INTEGER) + ?1 AS TEXT)
                 WHERE key='total_expanded_used'",
                params![bytes],
            )
            .ok();
    }

    pub fn reset_used(&mut self) {
        self.conn
            .execute(
                "INSERT INTO settings(key,value) VALUES('total_expanded_used','0')
                 ON CONFLICT(key) DO UPDATE SET value='0'",
                [],
            )
            .ok();
    }

    pub fn payload_path(&self, name: &str) -> PathBuf {
        self.data_dir.join("payloads").join(name)
    }
    pub fn intermediate_path(&self, name: &str) -> PathBuf {
        self.data_dir.join("intermediate").join(name)
    }

    pub fn write_payload(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.payload_path(name), data)
    }
    pub fn write_intermediate(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.intermediate_path(name), data)
    }

    pub fn branch_id(&self, name: &str) -> rusqlite::Result<i64> {
        if let Ok(id) = self.conn.query_row(
            "SELECT id FROM branches WHERE name=?1",
            params![name],
            |r| r.get::<_, i64>(0),
        ) {
            return Ok(id);
        }
        self.conn.execute(
            "INSERT INTO branches(name, created_at) VALUES (?1, strftime('%s','now'))",
            params![name],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn add_evidence(
        &mut self,
        subject: &str,
        code: &str,
        severity: &str,
        message: &str,
        detail: Option<&str>,
    ) {
        self.conn
            .execute(
                "INSERT INTO evidence(subject, code, severity, message, detail, created_at)
                 VALUES (?1,?2,?3,?4,?5, strftime('%s','now'))",
                params![subject, code, severity, message, detail],
            )
            .ok();
    }

    pub fn candidate_exists_for_entry(&self, entry_id: i64) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM candidates WHERE entry_id=?1 AND valid=1 LIMIT 1",
                params![entry_id],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
    }
}
